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
    MAX_CONFIGS_PER_IP_WL,
    MAX_CONFIGS_PER_IP_BL,
    MAX_CONFIGS_PER_SUBNET_BL,
    WL_MIN_SUCCESS_COUNT,
    BL_MIN_SUCCESS_COUNT,
    RU_SNI_RATIO,
)
from . import config as cfg
from .geoip import init_geoip, is_cf_ip
from .sni_whitelist import init_sni_whitelist
from .utils import safe_b64encode, safe_b64decode
import ipaddress

from .parse import (
    parse_host_port,
    parse_host_port_and_name,
    extract_sni_from_link,
    parse_ip_or_resolve,
)
from .geoip import is_valid_public_host
from .classify import (
    classify_config,
    is_unsafe_config,
    is_wl_by_keywords,
    is_bl_by_keywords,
    is_ai_by_keywords,
    is_torrent_by_keywords,
)
from .chunker import test_links_chunked
from .xray import (
    check_proxy_alive_detailed,
    ensure_xray_core,
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
    limit_bl_configs_per_exit_ip,
)
from .diversify import (
    get_wl_item_info,
    select_wl_diverse,
    filter_protocols_bl,
    rename_config,
    links_to_clash_yaml,
    sanitize_proxy_link,
)


_PROTO_NAMES = frozenset({"vless", "vmess", "trojan", "ss", "hysteria2"})


def _subscription_header(prefix: str, count: int) -> str:
    """
    Заголовок подписки для base64/plain файлов: клиенты читают строки
    #profile-* и показывают имя и свежесть. YAML заголовков не получает.
    """
    if not cfg.SUBSCRIPTION_HEADERS:
        return ""
    # суффикс титула: спец-имена для главных/континентов/протоколов/exotic
    title_suffix = {
        "bs": "WL", "bl": "BL", "full": "FULL",
        "EUROPE": "EU", "NORTH_AMERICA": "NA", "SOUTH_AMERICA": "SA",
        "AFRICA": "AF", "OCEANIA": "OC",
        "exotic": "Exotic",
    }.get(prefix, prefix.upper() if prefix in _PROTO_NAMES else prefix)
    lines = [
        f"#profile-title: {cfg.SUBSCRIPTION_TITLE} {title_suffix}".rstrip(),
    ]
    if int(cfg.SUBSCRIPTION_UPDATE_INTERVAL) > 0:
        lines.append(f"#profile-update-interval: {int(cfg.SUBSCRIPTION_UPDATE_INTERVAL)}")
    if cfg.SUBSCRIPTION_SUPPORT_URL:
        lines.append(f"#support-url: {cfg.SUBSCRIPTION_SUPPORT_URL}")
    if cfg.SUBSCRIPTION_WEB_PAGE_URL:
        lines.append(f"#profile-web-page-url: {cfg.SUBSCRIPTION_WEB_PAGE_URL}")
    if cfg.SUBSCRIPTION_ANNOUNCE:
        lines.append(f"#announce: {cfg.SUBSCRIPTION_ANNOUNCE}")
    return "\n".join(lines) + "\n"


def _write_subscription_files(base_dir: str, prefix: str, links: list) -> None:
    """
    Пишет base64 / plain / yaml для списка links
    с учётом WRITE_BASE64 / WRITE_PLAIN / WRITE_YAML.
    """
    os.makedirs(base_dir, exist_ok=True)
    # заголовок входит в base64-тело целиком: клиент декодирует и читает #profile-*
    header = _subscription_header(prefix, len(links))

    if cfg.WRITE_BASE64:
        path = os.path.join(base_dir, f"alive_{prefix}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(safe_b64encode(header + "\n".join(links)))

    if cfg.WRITE_PLAIN:
        path = os.path.join(base_dir, f"alive_plain_{prefix}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(header + "\n".join(links))
            if links:
                f.write("\n")

    if cfg.WRITE_YAML:
        path = os.path.join(base_dir, f"alive_{prefix}.yaml")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(links_to_clash_yaml(links))
        except Exception as e:
            print(f"⚠️ Не удалось записать YAML {path}: {e}")


def _sort_by_ping(items):
    """
    Сортировка по пингу: низкий — выше (SORT_BY_PING).
    Пинг берётся из замера теста (лучший успешный ответ, мс).
    Без пинга (None) — в конец, порядок не меняется (stable).
    """
    if not cfg.SORT_BY_PING:
        return items

    def key(item):
        ping = item[5] if len(item) > 5 and isinstance(item[5], (int, float)) else None
        return (1, 0) if ping is None else (0, ping)

    return sorted(items, key=key)


def _item_exit_ip(item):
    """exit IP из элемента alive-данных; None, если не определён."""
    return item[4] if len(item) > 4 and item[4] else None


def _drop_cf_exit(items):
    """REMOVE_CF_EXIT: убирает конфиги с выходом через WARP/Cloudflare.

    exit IP неизвестен - конфиг не трогаем: отсутствие данных не повод выкидывать.
    """
    kept, dropped = [], 0
    for item in items:
        exit_ip = _item_exit_ip(item)
        if exit_ip and is_cf_ip(exit_ip):
            dropped += 1
            continue
        kept.append(item)
    return kept, dropped


def _collect_cf_items(items):
    """Только конфиги с выходом через WARP/Cloudflare (для subs/other/CF)."""
    return [item for item in items if (ip := _item_exit_ip(item)) and is_cf_ip(ip)]


def _is_cf_exit(item):
    """Выход конфига через WARP/Cloudflare? (exit IP неизвестен - не CF)."""
    ip = _item_exit_ip(item)
    return bool(ip and is_cf_ip(ip))


def _cf_suffix(item):
    """'/CF' или ''. Суффикс ставится только там, где CF не гарантирован списком."""
    if cfg.RENAME_CF_SUFFIX and _is_cf_exit(item):
        return f"/{cfg.RENAME_CF_SUFFIX}"
    return ""


def _wl_bl_tag_fn(wl_keys, with_cf=True):
    """
    Тег по структурной принадлежности: [WL] / [BL], плюс '/CF'-суффикс,
    если включён и выход - WARP/CF. with_cf=False даёт чистый [WL]/[BL]
    для списков, которые сами гарантируют CF (subs/other/CF).
    """
    def tag(item):
        base = (
            cfg.RENAME_PREFIX_WL
            if get_final_dedup_key(item[0]) in wl_keys
            else cfg.RENAME_PREFIX_BL
        )
        if not with_cf:
            return base
        suffix = _cf_suffix(item)
        return f"{base[:-1]}{suffix}]" if suffix else base
    return tag


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

    if cfg.AUTO_DOWNLOAD_XRAY:
        ensure_xray_core()

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

    unsafe_dropped = 0

    for link, src in clean_items:

        # REMOVE_UNSAFE: allowInsecure / plaintext без TLS — мимо
        if cfg.REMOVE_UNSAFE and is_unsafe_config(link):
            unsafe_dropped += 1
            continue

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

        matched_ip = None
        from .parse import extract_sni_from_link
        _host, _, _ = parse_host_port_and_name(link)
        if _host:
            _clean = _host.strip('[] \t\r\n\'"').lower()
            if _clean in white_ips:
                matched_ip = _clean
        if not matched_ip:
            _sni = extract_sni_from_link(link)
            if _sni and _sni.lower() in white_ips:
                matched_ip = _sni

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

    # WL: батчевый прогон (один Xray на чанк) или одиночный путь
    wl_results = test_links_chunked(ping_wl, WL_MIN_SUCCESS_COUNT)

    for link, src in ping_wl:

        result = wl_results.get(link)
        if result is None:
            continue  # исключение в тесте - конфиг не считаем ни живым, ни мёртвым

        is_ok, res, reason, cc, exit_ip, ping_ms = result
        is_white = str(src).startswith("WHITE_IP")

        if is_ok:

            # (link, flag, src, cc, exit_ip, ping_ms)
            alive_wl_data.append(
                (
                    res[0],
                    res[1],
                    src,
                    cc,
                    exit_ip,
                    ping_ms,
                )
            )

            wl_ok += 1
            if is_white:
                white_ip_ok += 1

        else:

            wl_fail += 1
            if is_white:
                white_ip_fail += 1

    if cfg.REMOVE_CF_EXIT:
        alive_wl_data, cf_dropped_wl = _drop_cf_exit(alive_wl_data)
        if cf_dropped_wl:
            print(f"   └ REMOVE_CF_EXIT: убрано из WL {cf_dropped_wl} (выход через WARP/CF)")

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

    # BL: батчевый прогон
    bl_results = test_links_chunked(ping_bl, BL_MIN_SUCCESS_COUNT)

    for link, src in ping_bl:

        result = bl_results.get(link)
        if result is None:
            continue

        is_ok, res, reason, cc, exit_ip, ping_ms = result

        if not is_ok:

            bl_fail += 1
            continue

        bl_ok += 1

        # Всё русское -> WL (если включено в конфиге): живой BL с RU exit.
        if cc and cc.upper() == "RU" and cfg.BL_RU_TO_WL:
            alive_wl_data.append(
                (
                    res[0],
                    res[1],
                    "RU_EXIT:" + str(src),
                    cc,
                    exit_ip,
                    ping_ms,
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
                    exit_ip,
                    ping_ms,
                )
            )

    if cfg.REMOVE_CF_EXIT:
        alive_bl_data, cf_dropped_bl = _drop_cf_exit(alive_bl_data)
        if cf_dropped_bl:
            print(f"   └ REMOVE_CF_EXIT: убрано из BL {cf_dropped_bl} (выход через WARP/CF)")

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

    # Выходные лимиты (exit IP): CF-подсети — исключение
    alive_bl_data = (
        limit_bl_configs_per_exit_ip(
            alive_bl_data
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
            minority_ratio=cfg.BL_MINORITY_RATIO,
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

    alive_full_clean = _sort_by_ping(
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

    alive_wl_clean = _sort_by_ping(alive_wl_clean)
    alive_bl_clean = _sort_by_ping(alive_bl_clean)

    final_wl = _build_renamed(
        alive_wl_clean,
        _wl_bl_tag_fn(wl_keys),
    )

    final_bl = _build_renamed(
        alive_bl_clean,
        _wl_bl_tag_fn(wl_keys),
    )

    full_tag = _wl_bl_tag_fn(wl_keys)

    final_full = _build_renamed(
        alive_full_clean,
        full_tag,
    )

    # ========================================================
    # 18. SAVE MAIN
    # ========================================================

    os.makedirs("subs/main", exist_ok=True)

    # три основных списка через общий writer: заголовки и форматы единые
    _write_subscription_files("subs/main", "bs", final_wl)
    _write_subscription_files("subs/main", "bl", final_bl)
    if cfg.WRITE_FULL:
        _write_subscription_files("subs/main", "full", final_full)

    print("💾 Основные списки: alive_bs / alive_bl / alive_full (base64 + plain + yaml)")

    # ========================================================
    # 19. OTHER: AI / TORRENT / COUNTRIES
    # ========================================================

    # --- AI ---
    if cfg.WRITE_OTHER_AI:
        # CF-выход не даёт конфигу быть AI: через WARP AI-сервисы
        # часто считают трафик ботовым. Такие конфиги остаются в WL/BL.
        ai_items = [
            item for item in alive_full_clean
            if item[0] in ai_links and not _is_cf_exit(item)
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
        # CF-выход не даёт конфигу быть TR: Cloudflare режет не-вебовый
        # трафик. Такие конфиги остаются в WL/BL.
        torrent_items = [
            item for item in alive_full_clean
            if item[0] in torrent_links and not _is_cf_exit(item)
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
    # Группировка по странам нужна и для country-списков, и для exotic.
    by_cc = defaultdict(list)
    for item in alive_full_clean:
        cc = None
        if len(item) > 3 and item[3]:
            cc = str(item[3]).upper()
        if not cc or len(cc) != 2:
            continue
        by_cc[cc].append(item)

    if cfg.WRITE_OTHER_COUNTRIES:
        countries_dir = "subs/other/countries"
        os.makedirs(countries_dir, exist_ok=True)

        active_ccs = set(by_cc.keys())

        for cc, items in sorted(by_cc.items()):
            final_cc = _build_renamed(
                items,
                _wl_bl_tag_fn(wl_keys),
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

    # --- PROTOCOLS ---
    if cfg.WRITE_OTHER_PROTOCOLS:
        protocols_dir = "subs/other/protocols"
        os.makedirs(protocols_dir, exist_ok=True)

        by_proto = defaultdict(list)
        for item in alive_full_clean:
            proto = item[0].split("://", 1)[0].lower()
            if proto == "hy2":
                proto = "hysteria2"
            by_proto[proto].append(item)

        for proto, items in sorted(by_proto.items()):
            final_proto = _build_renamed(items, full_tag)
            if not final_proto:
                continue
            proto_dir = os.path.join(protocols_dir, proto)
            _write_subscription_files(proto_dir, proto, final_proto)

        print(
            f"💾 Protocols: {len(by_proto)} протоколов "
            f"({', '.join(sorted(by_proto))}) → subs/other/protocols/"
        )

    # --- CONTINENTS ---
    if cfg.WRITE_OTHER_CONTINENTS:
        from .utils.geo_data import continent_for_cc

        by_continent = defaultdict(list)
        unknown_cc = 0
        for item in alive_full_clean:
            cc = None
            if len(item) > 3 and item[3]:
                cc = str(item[3]).upper()
            if not cc or len(cc) != 2:
                continue
            continent = continent_for_cc(cc)
            if not continent:
                unknown_cc += 1
                continue
            by_continent[continent].append(item)

        for continent, items in sorted(by_continent.items()):
            final_cont = _build_renamed(items, full_tag)
            if not final_cont:
                continue
            _write_subscription_files(
                os.path.join("subs/other/continents", continent),
                continent,
                final_cont,
            )

        print(
            f"💾 Continents: {len(by_continent)} континентов "
            f"({', '.join(sorted(by_continent))})"
            + (f", {unknown_cc} нод без континента" if unknown_cc else "")
            + " → subs/other/continents/"
        )

    # --- CLOUDFLARE EXIT ---
    # Только конфиги с выходом через WARP/Cloudflare: безопаснее и быстрее
    # для пользователей за строгими NAT'ами.
    if cfg.WRITE_OTHER_CF:
        cf_items = _collect_cf_items(alive_full_clean)
        if cf_items:
            # список сам гарантирует CF - у всех конфигов единый тег [CF]
            final_cf = _build_renamed(cf_items, lambda _item: cfg.RENAME_PREFIX_CF)
            if final_cf:
                _write_subscription_files("subs/other/CF", "CF", final_cf)
                print(
                    f"💾 CF exit: {len(final_cf)} конфигов с выходом через WARP/CF "
                    f"-> subs/other/CF/"
                )
            else:
                print("💾 CF exit: конфиги есть, но ни один не прошёл переименование")
        else:
            print("💾 CF exit: 0 конфигов - файлы не перезаписываем")

    # --- EXOTIC ---
    # Редкие страны: если в стране нод <= EXOTIC_MAX_NODES —
    # её конфиги идут и в общий экзотический список.
    if cfg.WRITE_OTHER_EXOTIC:
        exotic_items = [
            item
            for items in by_cc.values()
            if len(items) <= cfg.EXOTIC_MAX_NODES
            for item in items
        ]
        if exotic_items:
            final_exotic = _build_renamed(exotic_items, full_tag)
            _write_subscription_files(
                "subs/other/exotic",
                "exotic",
                final_exotic,
            )
            exotic_ccs = {
                cc for cc, items in by_cc.items()
                if len(items) <= cfg.EXOTIC_MAX_NODES
            }
            print(
                f"💾 Exotic: {len(final_exotic)} конфигов из "
                f"{len(exotic_ccs)} редких стран "
                f"(лимит {cfg.EXOTIC_MAX_NODES} нод) → subs/other/exotic/"
            )
        else:
            print("💾 Exotic: 0 конфигов — файлы не перезаписываем")

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
                "ai": len(final_ai) if cfg.WRITE_OTHER_AI and ai_items else 0,
                "torrent": len(final_torrent) if cfg.WRITE_OTHER_TORRENT and torrent_items else 0,
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
