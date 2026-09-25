"""Оркестрация пайплайна apex-parser (бывший main из parser.py)."""
from __future__ import annotations

import os
import json
import shutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from .config import (
    WHITE_IP_FILE,
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
from .classify import (
    classify_config,
    is_wl_by_keywords,
    is_bl_by_keywords,
    is_ai_by_keywords,
    is_torrent_by_keywords,
)
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
from .incoming import (
    load_previous_alives,
    resolve_source_files,
    download_white_ip,
    load_white_ips,
    save_white_ips,
)
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
    links_to_clash_yaml,
    sanitize_proxy_link,
)


def _write_subscription_files(base_dir: str, prefix: str, links: list) -> None:
    """
    Пишет base64 / plain / yaml для списка links
    с учётом WRITE_BASE64 / WRITE_PLAIN / WRITE_YAML.
    """
    os.makedirs(base_dir, exist_ok=True)

    if cfg.WRITE_BASE64:
        path = os.path.join(base_dir, f"alive_{prefix}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(safe_b64encode("\n".join(links)))

    if cfg.WRITE_PLAIN:
        path = os.path.join(base_dir, f"alive_plain_{prefix}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(links))
            if links:
                f.write("\n")

    if cfg.WRITE_YAML:
        path = os.path.join(base_dir, f"alive_{prefix}.yaml")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(links_to_clash_yaml(links))
        except Exception as e:
            print(f"⚠️ Не удалось записать YAML {path}: {e}")


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

    print(
        f"⚙️ SECURE_SOURCES_GITHUB={cfg.SECURE_SOURCES_GITHUB} "
        f"SPLIT_SOURCES={cfg.SPLIT_SOURCES} "
        f"ENABLE_TG_SOURCES={cfg.ENABLE_TG_SOURCES}"
    )

    # ========================================================
    # 1. WHITE IP (remote → local)
    # ========================================================

    download_white_ip()
    white_ips = load_white_ips()
    save_white_ips(white_ips)
    print(f"💾 White IP база: {len(white_ips)} IP")

    # ========================================================
    # 2. SOURCES
    # ========================================================

    wl_file, bl_file = resolve_source_files()
    print(f"📂 Sources: WL={wl_file}  BL={bl_file}")

    if wl_file == bl_file:
        # один sources.txt — общий пул, классификация только по keywords/IP/SNI
        all_fetched = fetch_links_parallel_with_source(wl_file)
        wl_fetched = all_fetched
        bl_fetched = []
    else:
        wl_fetched = fetch_links_parallel_with_source(wl_file)
        bl_fetched = fetch_links_parallel_with_source(bl_file)

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
    # 6. CLASSIFY FIRST + AI / TORRENT tags
    # ========================================================

    pre_ping_wl = []
    pre_ping_bl = []
    ai_links = set()
    torrent_links = set()

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

        # AI / Torrent — по оригинальному имени и ссылке
        if is_ai_by_keywords(link, orig_name):
            ai_links.add(link)
        if is_torrent_by_keywords(link, orig_name):
            torrent_links.add(link)

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
        f"\n   AI-кандидаты: {len(ai_links)}"
        f"\n   Torrent-кандидаты: {len(torrent_links)}"
    )

    # ========================================================
    # 7. ONLY BL LIMIT
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

                # (link, flag, src, cc)
                alive_wl_data.append(
                    (
                        res[0],
                        res[1],
                        src,
                        cc,
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
                        cc,
                    )
                )
                bl_ru_to_wl += 1
            else:
                alive_bl_data.append(
                    (
                        res[0],
                        res[1],
                        src,
                        cc,
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
    # ========================================================

    alive_bl_limited = (
        limit_bl_configs_per_ip(
            alive_bl_data
        )
    )

    # ========================================================
    # 15. BL PROTOCOL FILTER
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
    # 17. SANITIZE + RENAME
    # ========================================================

    def _build_renamed(items, tag_fn):
        out = []
        for item in items:
            cleaned = sanitize_proxy_link(item[0])
            if not cleaned:
                continue
            idx = len(out) + 1
            tag = tag_fn(item)
            out.append(
                rename_config(
                    cleaned,
                    idx,
                    tag,
                    item[1],
                )
            )
        return out

    final_wl = _build_renamed(
        alive_wl_clean,
        lambda _item: cfg.RENAME_PREFIX_WL,
    )

    final_bl = _build_renamed(
        alive_bl_clean,
        lambda _item: cfg.RENAME_PREFIX_BL,
    )

    final_full = _build_renamed(
        alive_full_clean,
        lambda item: (
            cfg.RENAME_PREFIX_WL
            if get_final_dedup_key(item[0]) in wl_keys
            else cfg.RENAME_PREFIX_BL
        ),
    )

    # ========================================================
    # 18. SAVE MAIN
    # ========================================================

    os.makedirs("subs/main", exist_ok=True)

    if cfg.WRITE_BASE64:
        with open(
            "subs/main/alive_bs.txt",
            "w",
            encoding="utf-8",
        ) as f:
            f.write(
                safe_b64encode(
                    "\n".join(final_wl)
                )
            )

        with open(
            "subs/main/alive_bl.txt",
            "w",
            encoding="utf-8",
        ) as f:
            f.write(
                safe_b64encode(
                    "\n".join(final_bl)
                )
            )

        if cfg.WRITE_FULL:
            with open(
                "subs/main/alive_full.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    safe_b64encode(
                        "\n".join(final_full)
                    )
                )

    if cfg.WRITE_PLAIN:
        with open(
            "subs/main/alive_plain_bs.txt",
            "w",
            encoding="utf-8",
        ) as f:
            f.write("\n".join(final_wl))
            if final_wl:
                f.write("\n")

        with open(
            "subs/main/alive_plain_bl.txt",
            "w",
            encoding="utf-8",
        ) as f:
            f.write("\n".join(final_bl))
            if final_bl:
                f.write("\n")

        if cfg.WRITE_FULL:
            with open(
                "subs/main/alive_plain_full.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write("\n".join(final_full))
                if final_full:
                    f.write("\n")

    if cfg.WRITE_YAML:
        try:
            with open(
                "subs/main/alive_bs.yaml",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(links_to_clash_yaml(final_wl))

            with open(
                "subs/main/alive_bl.yaml",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(links_to_clash_yaml(final_bl))

            if cfg.WRITE_FULL:
                with open(
                    "subs/main/alive_full.yaml",
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(links_to_clash_yaml(final_full))
            print("💾 YAML (Clash): alive_*.yaml записаны")
        except Exception as e:
            print(f"⚠️ Не удалось записать YAML: {e}")

    if cfg.WRITE_PLAIN:
        print("💾 Plain text: alive_plain_*.txt записаны")

    # ========================================================
    # 19. OTHER: AI / TORRENT / COUNTRIES
    # ========================================================

    # --- AI ---
    if cfg.WRITE_OTHER_AI:
        ai_items = [
            item for item in alive_full_clean
            if item[0] in ai_links
        ]
        if ai_items:
            final_ai = _build_renamed(
                ai_items,
                lambda _item: cfg.RENAME_PREFIX_AI,
            )
            _write_subscription_files(
                "subs/other/AI",
                "AI",
                final_ai,
            )
            print(f"💾 AI: {len(final_ai)} конфигов → subs/other/AI/")
        else:
            print("💾 AI: 0 конфигов — файлы не перезаписываем")

    # --- TORRENT ---
    if cfg.WRITE_OTHER_TORRENT:
        torrent_items = [
            item for item in alive_full_clean
            if item[0] in torrent_links
        ]
        if torrent_items:
            final_torrent = _build_renamed(
                torrent_items,
                lambda _item: cfg.RENAME_PREFIX_TORRENT,
            )
            _write_subscription_files(
                "subs/other/torrent",
                "torrent",
                final_torrent,
            )
            print(
                f"💾 Torrent: {len(final_torrent)} конфигов "
                f"→ subs/other/torrent/"
            )
        else:
            print(
                "💾 Torrent: 0 конфигов — файлы не перезаписываем"
            )

    # --- COUNTRIES ---
    if cfg.WRITE_COUNTRY:
        countries_dir = "subs/other/countries"
        os.makedirs(countries_dir, exist_ok=True)

        by_cc = defaultdict(list)
        for item in alive_full_clean:
            cc = None
            if len(item) > 3 and item[3]:
                cc = str(item[3]).upper()
            if not cc or len(cc) != 2:
                continue
            by_cc[cc].append(item)

        active_ccs = set(by_cc.keys())

        for cc, items in sorted(by_cc.items()):
            final_cc = _build_renamed(
                items,
                lambda _item: (
                    cfg.RENAME_PREFIX_WL
                    if get_final_dedup_key(_item[0]) in wl_keys
                    else cfg.RENAME_PREFIX_BL
                ),
            )
            if not final_cc:
                continue
            cc_dir = os.path.join(countries_dir, cc)
            _write_subscription_files(cc_dir, cc, final_cc)

        print(
            f"💾 Countries: {len(active_ccs)} стран "
            f"→ subs/other/countries/"
        )

        if cfg.DELETE_MISSING_COUNTRIES:
            try:
                for name in os.listdir(countries_dir):
                    path = os.path.join(countries_dir, name)
                    if (
                        os.path.isdir(path)
                        and name.isalpha()
                        and len(name) == 2
                        and name.upper() not in active_ccs
                    ):
                        shutil.rmtree(path, ignore_errors=True)
                        print(f"   🗑 удалена папка страны {name}")
            except Exception as e:
                print(f"⚠️ Ошибка очистки стран: {e}")

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
    if cfg.WRITE_LATEST_JSON:
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
