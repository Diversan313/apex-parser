"""Оркестрация пайплайна apex-parser (бывший main из parser.py)."""
from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from .config import (
    WHITE_IP_FILE,
    INCOMING_FILE,
    MAX_WORKERS,
    MAX_QUEUE_LIMIT,
    MAX_CONFIGS_PER_IP_WL,
    MAX_CONFIGS_PER_IP_BL,
    MAX_CONFIGS_PER_SUBNET_BL,
    WL_MIN_SUCCESS_COUNT,
    BL_MIN_SUCCESS_COUNT,
    RU_SNI_RATIO,
)
from . import config as cfg
from .geoip import init_geoip
from .sni_whitelist import init_sni_whitelist
from .utils import safe_b64encode, safe_b64decode
import ipaddress

from .parse import (
    parse_host_port,
    parse_host_port_and_name,
    extract_sni_from_link,
    parse_ip_or_resolve,
    find_matched_ip_for_link,
)
from .geoip import is_valid_public_host
from .classify import classify_config, is_wl_by_keywords, is_bl_by_keywords
from .xray import (
    check_proxy_alive_detailed,
    link_to_xray_outbound,
    print_xray_version,
)
from .fetch import (
    fetch_links_parallel_with_source,
    extract_configs_from_json_text,
    content_looks_expired,
)
from .incoming import process_incoming_queue, load_previous_alives
from .dedup import (
    get_config_dedup_key,
    get_final_dedup_key,
    clean_and_dedup,
    dedup_advanced,
    limit_bl_configs_per_ip,
)
from .diversify import (
    get_wl_item_info,
    select_wl_diverse,
    filter_protocols_bl,
    rename_config,
)

def main():

    print(
        "🚀 Старт продвинутого Xray-парсера..."
    )

    print(
        "⚙️ WL white_ip: TCP → Xray, потом дедуп"
    )

    print(
        "⚙️ WL остальные: тест 1/3"
    )

    print(
        "⚙️ BL: тест 2/3"
    )

    print(
        f"⚙️ WL: max {MAX_CONFIGS_PER_IP_WL}/IP"
    )

    print(
        "⚙️ SNI из arch/lists/whitelist.txt → WL"
    )

    print(
        f"⚙️ прочие .ru SNI → WL с шансом "
        f"{int(RU_SNI_RATIO * 100)}%"
    )

    print(
        "⚙️ Старые alive-конфиги используются"
    )

    print_xray_version()

    wl_file = (
        "sources_wl.txt"
        if os.path.exists(
            "sources_wl.txt"
        )
        else "source_wl.txt"
    )

    bl_file = (
        "sources_bl.txt"
        if os.path.exists(
            "sources_bl.txt"
        )
        else "source_bl.txt"
    )

    # ========================================================
    # 1. SOURCES
    # ========================================================

    wl_fetched = (
        fetch_links_parallel_with_source(
            wl_file
        )
    )

    bl_fetched = (
        fetch_links_parallel_with_source(
            bl_file
        )
    )

    incoming_proxies, incoming_raw_ips = (
        process_incoming_queue()
    )

    # ========================================================
    # 2. WHITE IP
    # ========================================================

    white_ips = set()

    if os.path.exists(
        WHITE_IP_FILE
    ):

        try:

            with open(
                WHITE_IP_FILE,
                "r",
                encoding="utf-8",
            ) as f:

                for line in f:

                    white_ips.update(
                        parse_ip_or_resolve(
                            line
                        )
                    )

        except Exception as e:

            print(
                f"⚠️ Ошибка чтения "
                f"{WHITE_IP_FILE}: {e}"
            )

    for item in incoming_raw_ips:

        white_ips.update(
            parse_ip_or_resolve(
                item
            )
        )

    def ip_sort_key(ip):

        try:
            return (
                0,
                ipaddress.ip_address(
                    ip
                )
            )

        except ValueError:

            return (
                1,
                ip,
            )

    with open(
        WHITE_IP_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        for ip in sorted(
            list(
                white_ips
            ),
            key=ip_sort_key,
        ):

            f.write(
                ip
                + "\n"
            )

    print(
        f"💾 White IP база: "
        f"{len(white_ips)} IP"
    )

    # ========================================================
    # 3. OLD ALIVE
    # ========================================================

    prev_wl_links, prev_bl_links = (
        load_previous_alives()
    )

    # ========================================================
    # 4. ALL CANDIDATES
    # ========================================================

    tagged_items = []

    # NEW WL source
    for link, src in wl_fetched:

        tagged_items.append(
            (
                link,
                src,
            )
        )

    # NEW BL source
    for link, src in bl_fetched:

        tagged_items.append(
            (
                link,
                src,
            )
        )

    # Telegram
    for link in incoming_proxies:

        tagged_items.append(
            (
                link,
                "INCOMING_TELEGRAM",
            )
        )

    # PREVIOUS WL
    for link in prev_wl_links:

        tagged_items.append(
            (
                link,
                "PREV_WL",
            )
        )

    # PREVIOUS BL
    for link in prev_bl_links:

        tagged_items.append(
            (
                link,
                "PREV_BL",
            )
        )

    print(
        f"\n📦 Всего кандидатов "
        f"до дедупликации: "
        f"{len(tagged_items)}"
    )

    # ========================================================
    # 5. EXACT/LOGICAL DEDUP
    # ========================================================

    clean_items = (
        clean_and_dedup(
            tagged_items
        )
    )

    # ========================================================
    # 6. CLASSIFY FIRST
    #
    # КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ:
    #
    # Раньше BL limit применялся к ВСЕМ конфигам
    # ДО classify_config().
    #
    # Поэтому WL по keyword/RU-IP/RU-SNI мог
    # быть ошибочно ограничен как BL.
    #
    # Теперь сначала классифицируем.
    # ========================================================

    pre_ping_wl = []
    pre_ping_bl = []

    for link, src in clean_items:

        host, port, orig_name = (
            parse_host_port_and_name(
                link
            )
        )

        if (
            not host
            or not port
            or not is_valid_public_host(
                host
            )
        ):
            continue

        category = classify_config(
            link,
            white_ips,
            RU_SNI_RATIO,
        )

        if category == "WL":

            pre_ping_wl.append(
                (
                    link,
                    src,
                )
            )

        else:

            pre_ping_bl.append(
                (
                    link,
                    src,
                )
            )

    print(
        f"\n🧠 Классификация ДО пинга:"
        f"\n   WL: {len(pre_ping_wl)}"
        f"\n   BL: {len(pre_ping_bl)}"
    )

    # ========================================================
    # 7. ONLY BL LIMIT
    #
    # WL не режем здесь вообще.
    # ========================================================

    pre_ping_bl = (
        limit_bl_configs_per_ip(
            pre_ping_bl
        )
    )

    print(
        f"\n📡 После BL-предлимита:"
        f"\n   WL: {len(pre_ping_wl)}"
        f"\n   BL: {len(pre_ping_bl)}"
    )

    # ========================================================
    # 8. PING WL
    #
    # white_ip → тоже в Xray-очередь (метка WHITE_IP:...),
    # но НЕ режем их BL-лимитами.
    # Тест → только живые → дедуп/diversity.
    # ========================================================

    alive_wl_data = []
    ping_wl = []
    seen_wl = set()
    white_ip_queued = 0

    for link, src in pre_ping_wl:

        if link in seen_wl:
            continue

        seen_wl.add(link)

        matched_ip = find_matched_ip_for_link(
            link,
            white_ips,
        )

        if matched_ip:
            # Метка WHITE_IP сохраняется после теста
            # для приоритета в diversity.
            ping_wl.append(
                (
                    link,
                    "WHITE_IP:" + str(src),
                )
            )
            white_ip_queued += 1
            continue

        ping_wl.append((link, src))

    # ========================================================
    # 9. PING BL
    # ========================================================

    ping_bl = []
    seen_bl = set()

    for link, src in pre_ping_bl:

        if link in seen_bl:
            continue

        seen_bl.add(link)
        ping_bl.append((link, src))

    print(
        f"\n📡 Xray очередь:"
        f"\n   WL white_ip (с тестом):  {white_ip_queued}"
        f"\n   WL heuristic на тест:    {len(ping_wl) - white_ip_queued}"
        f"\n   WL всего на Xray:        {len(ping_wl)}"
        f"\n   BL на Xray-тест:         {len(ping_bl)}"
    )

    # ========================================================
    # 10. TEST WL + BL
    # ========================================================

    alive_bl_data = []

    wl_ok = 0
    wl_fail = 0
    white_ip_ok = 0
    white_ip_fail = 0

    bl_ok = 0
    bl_fail = 0
    bl_ru_to_wl = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        # ----------------------------------------------------
        # WL 1/3 (включая white_ip)
        # ----------------------------------------------------

        wl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                WL_MIN_SUCCESS_COUNT,
            ): (
                link,
                src,
            )
            for link, src in ping_wl
        }

        for future in as_completed(
            wl_futures
        ):

            link, src = wl_futures[
                future
            ]

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception:
                continue

            is_white = str(src).startswith("WHITE_IP")

            if is_ok:

                # res = (link, flag)
                # source сохраняем (WHITE_IP:... или обычный)
                alive_wl_data.append(
                    (
                        res[0],
                        res[1],
                        src,
                    )
                )

                wl_ok += 1
                if is_white:
                    white_ip_ok += 1

            else:

                wl_fail += 1
                if is_white:
                    white_ip_fail += 1

        print(
            f"\n🟢 WL тест завершён: "
            f"OK={wl_ok}, "
            f"FAIL={wl_fail}"
        )
        print(
            f"   └ white_ip: "
            f"OK={white_ip_ok}, "
            f"FAIL={white_ip_fail}"
        )

        # ----------------------------------------------------
        # BL 2/3
        # ----------------------------------------------------

        bl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                BL_MIN_SUCCESS_COUNT,
            ): (
                link,
                src,
            )
            for link, src in ping_bl
        }

        for future in as_completed(
            bl_futures
        ):

            link, src = bl_futures[
                future
            ]

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception:
                continue

            if not is_ok:

                bl_fail += 1
                continue

            bl_ok += 1

            # Всё русское → WL: живой BL с RU exit.
            if cc and cc.upper() == "RU":
                alive_wl_data.append(
                    (
                        res[0],
                        res[1],
                        "RU_EXIT:" + str(src),
                    )
                )
                bl_ru_to_wl += 1
            else:
                alive_bl_data.append(
                    (
                        res[0],
                        res[1],
                        src,
                    )
                )

    print(
        f"\n🔴 BL тест завершён: "
        f"OK={bl_ok}, "
        f"FAIL={bl_fail}, "
        f"RU→WL={bl_ru_to_wl}"
    )

    # ========================================================
    # 11. WL DEDUP AFTER TEST
    # ========================================================

    alive_wl_data = (
        dedup_advanced(
            alive_wl_data,
            "WL после Xray",
        )
    )

    # ========================================================
    # 12. WL DIVERSITY
    # ========================================================

    alive_wl_clean = select_wl_diverse(
        alive_wl_data
    )

    alive_wl_clean = dedup_advanced(
        alive_wl_clean,
        "WL после diversity",
    )

    # ========================================================
    # 13. BL DEDUP
    # ========================================================

    alive_bl_data = (
        dedup_advanced(
            alive_bl_data,
            "BL после Xray",
        )
    )

    # ========================================================
    # 14. BL LIMIT AFTER TEST
    #
    # Сохраняем:
    # IP = 2
    # /24 = 5
    # ========================================================

    alive_bl_limited = (
        limit_bl_configs_per_ip(
            alive_bl_data
        )
    )

    # ========================================================
    # 15. BL PROTOCOL FILTER
    #
    # НЕ МЕНЯЕМ.
    # ========================================================

    alive_bl_clean = (
        filter_protocols_bl(
            alive_bl_limited,
            minority_ratio=0.10,
        )
    )

    # ========================================================
    # 16. FULL
    # ========================================================

    alive_full_raw = (
        alive_wl_clean
        + alive_bl_clean
    )

    alive_full_clean = (
        dedup_advanced(
            alive_full_raw,
            "FULL",
        )
    )

    # --------------------------------------------------------
    # Для FULL не применяем BL-ограничение к WL.
    # --------------------------------------------------------

    wl_keys = set()

    for item in alive_wl_clean:

        key = get_final_dedup_key(
            item[0]
        )

        if key:
            wl_keys.add(
                key
            )

    full_wl = []
    full_bl = []

    for item in alive_full_clean:

        key = get_final_dedup_key(
            item[0]
        )

        if key in wl_keys:
            full_wl.append(
                item
            )
        else:
            full_bl.append(
                item
            )

    # BL ограничиваем ещё раз для FULL.
    full_bl = limit_bl_configs_per_ip(
        full_bl
    )

    alive_full_clean = (
        full_wl
        + full_bl
    )

    # ========================================================
    # 17. RENAME
    # ========================================================

    final_wl = [
        rename_config(
            item[0],
            idx,
            "[WL]",
            item[1],
        )
        for idx, item in enumerate(
            alive_wl_clean,
            1,
        )
    ]

    final_bl = [
        rename_config(
            item[0],
            idx,
            "[BL]",
            item[1],
        )
        for idx, item in enumerate(
            alive_bl_clean,
            1,
        )
    ]

    final_full = []

    for idx, item in enumerate(
        alive_full_clean,
        1,
    ):

        key = get_final_dedup_key(
            item[0]
        )

        tag = (
            "[WL]"
            if key in wl_keys
            else "[BL]"
        )

        final_full.append(
            rename_config(
                item[0],
                idx,
                tag,
                item[1],
            )
        )

    # ========================================================
    # 18. SAVE
    # ========================================================

    with open(
        "alive_bs.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_wl
                )
            )
        )

    with open(
        "alive_bl.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_bl
                )
            )
        )

    with open(
        "alive_full.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_full
                )
            )
        )

    # ========================================================
    # CLOSE GEO
    # ========================================================

    if cfg.GEO_READER:

        try:
            cfg.GEO_READER.close()
        except Exception:
            pass

    # ========================================================
    # FINAL STATS
    # ========================================================

    print()
    print("=" * 70)
    print("📊 ФИНАЛЬНАЯ СТАТИСТИКА")
    print("=" * 70)

    print(
        f"WL white_ip в очереди:   {white_ip_queued}"
    )

    print(
        f"WL white_ip живых:       {white_ip_ok}"
    )

    print(
        f"WL на Xray всего:        {len(ping_wl)}"
    )

    print(
        f"WL живых всего:          {wl_ok}"
    )

    print(
        f"WL после diversity:      {len(final_wl)}"
    )

    print(
        f"BL кандидатов:           {len(ping_bl)}"
    )

    print(
        f"BL живых:                {bl_ok}"
    )

    print(
        f"BL финал:                {len(final_bl)}"
    )


    print(
        f"BL RU → WL:              {bl_ru_to_wl}"
    )
    print(
        f"FULL:                 {len(final_full)}"
    )

    print(
        f"White IP:             {len(white_ips)}"
    )

    print("=" * 70)

    # stats/latest.json — машинная сводка для бота / badge / CI
    try:
        os.makedirs("stats", exist_ok=True)
        stats = {
            "updated_at": datetime.now(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "wl": len(final_wl),
            "bl": len(final_bl),
            "full": len(final_full),
            "white_ip": len(white_ips),
            "wl_tested": len(ping_wl),
            "bl_tested": len(ping_bl),
            "wl_ok": wl_ok,
            "bl_ok": bl_ok,
            "bl_ru_to_wl": bl_ru_to_wl,
            "white_ip_queued": white_ip_queued,
            "white_ip_ok": white_ip_ok,
        }
        with open(
            os.path.join("stats", "latest.json"),
            "w",
            encoding="utf-8",
        ) as sf:
            json.dump(
                stats,
                sf,
                ensure_ascii=False,
                indent=2,
            )
            sf.write("\n")
        print("stats/latest.json записан")
    except Exception as e:
        print(f"⚠️ Не удалось записать stats/latest.json: {e}")

    print(
        "✨ Готово!"
    )




def run():
    """Точка входа: init + main."""
    init_geoip()
    init_sni_whitelist()
    main()


if __name__ == "__main__":
    run()
