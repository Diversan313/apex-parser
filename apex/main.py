"""Оркестрация пайплайна apex-parser (бывший main из parser.py)."""
from __future__ import annotations

import os
import json
import time
import shutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from .config import (
    MAX_WORKERS,
    MAX_CONFIGS_PER_IP_BL,
    MAX_CONFIGS_PER_SUBNET_BL,
    WL_MIN_SUCCESS_COUNT,
    BL_MIN_SUCCESS_COUNT,
)
from . import config as cfg
from .geoip import init_geoip, is_cf_ip, resolve_hosts_bulk
from .sni_whitelist import init_sni_whitelist
from .utils import safe_b64encode, safe_b64decode, fmt_duration
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
    build_white_network_index,
    host_in_white_ips,
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
            print(f"warn: YAML {path} не записан: {e}")


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


def _wl_bl_tag_fn(wl_keys, with_cf=True, ai_links=None, torrent_links=None):
    """
    Тег по структурной принадлежности: [WL] / [BL], плюс доп-статусы
    через "/" — AI/TR (RENAME_EXTRA_TAGS) и CF-выход (RENAME_CF_SUFFIX).
    Все списки с структурными тегами собирают их одной функцией — правила
    одни и те же везде. CF-выход статус AI/TR не даёт: через WARP
    AI-сервисы и трекеры работают плохо — то же правило, что в самих
    AI/TR списках. with_cf=False даёт тег без CF-статуса для списков,
    которые сами гарантируют CF (subs/other/CF).
    """
    def tag(item):
        base = (
            cfg.RENAME_PREFIX_WL
            if get_final_dedup_key(item[0]) in wl_keys
            else cfg.RENAME_PREFIX_BL
        )
        parts = [base.strip("[]")]

        if cfg.RENAME_EXTRA_TAGS and not _is_cf_exit(item):
            if ai_links is not None and item[0] in ai_links:
                parts.append(cfg.RENAME_PREFIX_AI.strip("[]"))
            if torrent_links is not None and item[0] in torrent_links:
                parts.append(cfg.RENAME_PREFIX_TORRENT.strip("[]"))

        if with_cf:
            suffix = _cf_suffix(item)
            if suffix:
                parts.append(suffix.lstrip("/"))

        return "[" + "/".join(parts) + "]"
    return tag


def main():

    t_run = time.monotonic()

    if cfg.AUTO_DOWNLOAD_XRAY:
        ensure_xray_core()

    print_xray_version()

    download_white_ip()
    white_ips, white_networks = load_white_ips()
    save_white_ips(white_ips, white_networks)
    print(f"white_ip: {len(white_ips)} IP, {len(white_networks)} подсетей")

    wl_file, bl_file = resolve_source_files()

    if wl_file == bl_file:
        # один sources.txt — общий пул, классификация только по keywords/IP/SNI
        all_fetched = fetch_links_parallel_with_source(wl_file)
        wl_fetched = all_fetched
        bl_fetched = []
    else:
        wl_fetched = fetch_links_parallel_with_source(wl_file)
        bl_fetched = fetch_links_parallel_with_source(bl_file)

    prev_wl_links, prev_bl_links = (
        load_previous_alives()
    )

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

    clean_items = (
        clean_and_dedup(
            tagged_items
        )
    )
    # Классификация и CF-фильтр дальше берут адреса только из кэша:
    # одна параллельная волна с жёстким потолком вместо DNS-резолва
    # в последовательных циклах по всем кандидатам.
    white_net_index = build_white_network_index(white_networks)
    if white_ips or white_networks:
        warm_hosts = set()
        for link, _src in clean_items:
            h, _, _ = parse_host_port_and_name(link)
            if h:
                warm_hosts.add(h.strip('[] \t\r\n\'"').lower())
        resolve_hosts_bulk(warm_hosts)

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
            white_net_index,
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
        f"классификация: WL {len(pre_ping_wl)}, "
        f"BL {len(pre_ping_bl)}, "
        f"AI {len(ai_links)}, "
        f"TR {len(torrent_links)}"
    )

    bl_before_limit = len(pre_ping_bl)

    pre_ping_bl = (
        limit_bl_configs_per_ip(
            pre_ping_bl
        )
    )

    print(
        f"предлимит BL: {bl_before_limit} -> {len(pre_ping_bl)}"
    )

    alive_wl_data = []
    ping_wl = []
    seen_wl = set()
    white_ip_queued = 0

    for link, src in pre_ping_wl:

        if link in seen_wl:
            continue

        seen_wl.add(link)

        # общий матчер белой базы: строка хоста/SNI, резолв из кэша, CIDR
        if host_in_white_ips(link, white_ips, white_net_index):
            ping_wl.append(
                (
                    link,
                    "WHITE_IP:" + str(src),
                )
            )
            white_ip_queued += 1
            continue

        ping_wl.append((link, src))

    ping_bl = []
    seen_bl = set()

    for link, src in pre_ping_bl:

        if link in seen_bl:
            continue

        seen_bl.add(link)
        ping_bl.append((link, src))

    alive_bl_data = []

    wl_ok = 0
    wl_fail = 0
    white_ip_ok = 0
    white_ip_fail = 0

    bl_ok = 0
    bl_fail = 0
    bl_ru_to_wl = 0

    # WL: батчевый прогон (один Xray на чанк) или одиночный путь
    print(f"тест WL: {len(ping_wl)} конфигов")
    t_wl_test = time.monotonic()
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
            print(f"warn: cf-exit: убрано из WL {cf_dropped_wl}")

    print(
        f"тест WL: {wl_ok}/{len(ping_wl)} "
        f"за {fmt_duration(time.monotonic() - t_wl_test)}"
    )

    # BL: батчевый прогон
    print(f"тест BL: {len(ping_bl)} конфигов")
    t_bl_test = time.monotonic()
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
            print(f"warn: cf-exit: убрано из BL {cf_dropped_bl}")

    print(
        f"тест BL: {bl_ok}/{len(ping_bl)}, "
        f"RU->WL {bl_ru_to_wl} "
        f"за {fmt_duration(time.monotonic() - t_bl_test)}"
    )

    alive_wl_data = (
        dedup_advanced(
            alive_wl_data,
            "WL после Xray",
        )
    )

    alive_wl_clean = select_wl_diverse(
        alive_wl_data
    )

    alive_wl_clean = dedup_advanced(
        alive_wl_clean,
        "WL после diversity",
    )

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

    alive_bl_limited = (
        limit_bl_configs_per_ip(
            alive_bl_data
        )
    )
    print(f"лимиты BL после теста: {len(alive_bl_data)} -> {len(alive_bl_limited)}")

    alive_bl_clean = (
        filter_protocols_bl(
            alive_bl_limited,
            minority_ratio=cfg.BL_MINORITY_RATIO,
        )
    )

    # Для FULL не применяем BL-ограничение к WL.

    wl_keys = set()

    for item in alive_wl_clean:

        key = get_final_dedup_key(
            item[0]
        )

        if key:
            wl_keys.add(
                key
            )

    # fp-варианты одного туннеля классифицируются независимо и могут
    # пройти тест в обеих очередях; дедупи внутри WL и BL этого не видят.
    # WL приоритетнее: туннель, уже живущий в WL-подписке, из BL убираем.
    bl_kept = []
    bl_wl_dupes = 0

    for item in alive_bl_clean:

        key = (
            get_final_dedup_key(
                item[0]
            )
        )

        if key and key in wl_keys:
            bl_wl_dupes += 1
            continue

        bl_kept.append(item)

    if bl_wl_dupes:
        print(
            f"дедуп BL∩WL: {len(alive_bl_clean)} -> {len(bl_kept)}"
        )

    alive_bl_clean = bl_kept

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

    # BL ограничиваем ещё раз для FULL; без изменений этап молчит
    full_bl_pre = len(full_bl)
    full_bl = limit_bl_configs_per_ip(
        full_bl
    )
    if len(full_bl) != full_bl_pre:
        print(f"лимиты BL (FULL): {full_bl_pre} -> {len(full_bl)}")
    alive_full_clean = _sort_by_ping(
        full_wl
        + full_bl
    )

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
        _wl_bl_tag_fn(
            wl_keys,
            ai_links=ai_links,
            torrent_links=torrent_links,
        ),
    )

    final_bl = _build_renamed(
        alive_bl_clean,
        _wl_bl_tag_fn(
            wl_keys,
            ai_links=ai_links,
            torrent_links=torrent_links,
        ),
    )

    # один и тот же тег для FULL, протоколов и континентов
    full_tag = _wl_bl_tag_fn(
        wl_keys,
        ai_links=ai_links,
        torrent_links=torrent_links,
    )

    final_full = _build_renamed(
        alive_full_clean,
        full_tag,
    )

    # все записи собираются в одну итоговую строку ниже
    written = []

    os.makedirs("subs/main", exist_ok=True)

    # три основных списка через общий writer: заголовки и форматы единые
    _write_subscription_files("subs/main", "bs", final_wl)
    _write_subscription_files("subs/main", "bl", final_bl)
    if cfg.WRITE_FULL:
        _write_subscription_files("subs/main", "full", final_full)
    written.append(
        f"WL {len(final_wl)}, BL {len(final_bl)}, FULL {len(final_full)}"
    )

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
            written.append(f"AI {len(final_ai)}")

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
            written.append(f"TR {len(final_torrent)}")

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
                _wl_bl_tag_fn(
                    wl_keys,
                    ai_links=ai_links,
                    torrent_links=torrent_links,
                ),
            )
            if not final_cc:
                continue
            cc_dir = os.path.join(countries_dir, cc)
            _write_subscription_files(cc_dir, cc, final_cc)

        removed_ccs = 0
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
                        removed_ccs += 1
            except Exception as e:
                print(f"warn: очистка стран: {e}")

        written.append(
            f"стран {len(active_ccs)}"
            + (f" (удалено {removed_ccs})" if removed_ccs else "")
        )

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

        written.append(f"протоколов {len(by_proto)}")

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

        written.append(
            f"континентов {len(by_continent)}"
            + (f" ({unknown_cc} нод без континента)" if unknown_cc else "")
        )

    # Только конфиги с выходом через WARP/Cloudflare: безопаснее и быстрее
    # для пользователей за строгими NAT'ами.
    if cfg.WRITE_OTHER_CF:
        cf_items = _collect_cf_items(alive_full_clean)
        if cf_items:
            # список сам гарантирует CF - у всех конфигов единый тег [CF]
            final_cf = _build_renamed(cf_items, lambda _item: cfg.RENAME_PREFIX_CF)
            if final_cf:
                _write_subscription_files("subs/other/CF", "CF", final_cf)
                written.append(f"CF {len(final_cf)}")
            else:
                print("warn: CF-список: переименование не прошло ни для одного конфига")

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
            written.append(
                f"экзотика {len(final_exotic)} ({len(exotic_ccs)} стран)"
            )


    if cfg.GEO_READER:

        try:
            cfg.GEO_READER.close()
        except Exception:
            pass


    if written:
        print("записано: " + ", ".join(written))
    print(
        f"итог: WL {wl_ok}/{len(ping_wl)} -> {len(final_wl)} "
        f"(white_ip {white_ip_ok}/{white_ip_queued}), "
        f"BL {bl_ok}/{len(ping_bl)} -> {len(final_bl)}, "
        f"RU->WL {bl_ru_to_wl}"
    )
    print(
        f"прогон: {fmt_duration(time.monotonic() - t_run)}"
    )

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
        except Exception as e:
            print(f"warn: stats/latest.json не записан: {e}")


def run():
    """Точка входа: init + main."""
    init_geoip()
    init_sni_whitelist()
    main()


if __name__ == "__main__":
    run()
