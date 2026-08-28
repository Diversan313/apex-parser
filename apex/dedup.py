"""Дедупликация конфигов и лимиты по IP/подсетям."""
from __future__ import annotations

import re
import json
import ipaddress
import urllib.parse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import (
    MAX_CONFIGS_PER_IP_BL,
    MAX_CONFIGS_PER_SUBNET_BL,
    MAX_CONFIGS_PER_IP_WL,
    SUPPORTED_PROTOCOLS,
)
from .utils import safe_b64decode
from .parse import (
    parse_host_port,
    parse_host_port_and_name,
    extract_sni_from_link,
    extract_all_hosts_and_ips_from_link,
    parse_ip_or_resolve,
    find_matched_ip_for_link,
)
from .geoip import resolve_host_cached, is_valid_public_host
from .xray import parse_xhttp_extra

def get_config_dedup_key(
    link: str,
):
    """
    До теста:
    удаляем только логически абсолютно одинаковые
    конфиги.

    SNI, UUID, path, flow, pbk, sid, fp,
    serviceName и mode входят в ключ.
    """

    host, port, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if not host or not port:
        return None

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    clean_ip = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    protocol = (
        link.split(
            "://",
            1,
        )[0].lower()
        if "://" in link
        else ""
    )

    sni = extract_sni_from_link(
        link
    )

    net = ""
    path = ""
    pbk = ""
    uuid = ""
    security = ""
    flow = ""
    sid = ""
    mode = ""
    fp = ""
    service_name = ""
    authority = ""
    extra_signature = ""

    try:

        if link.startswith(
            "vmess://"
        ):

            b64_data = (
                link.replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = (
                safe_b64decode(
                    b64_data
                )
            )

            data = json.loads(
                decoded
            )

            uuid = str(
                data.get(
                    "id",
                    "",
                )
            )

            net = str(
                data.get(
                    "net",
                    "raw",
                )
            ).lower()

            path = str(
                data.get(
                    "path",
                    "",
                )
            )

            security = str(
                data.get(
                    "tls",
                    "",
                )
            ).lower()

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            uuid = (
                parsed.username
                or ""
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            net = (
                query_params.get(
                    "type",
                    query_params.get(
                        "net",
                        ["raw"],
                    ),
                )[0].lower()
            )

            path = query_params.get(
                "path",
                [""],
            )[0]

            pbk = query_params.get(
                "pbk",
                [""],
            )[0]

            security = (
                query_params.get(
                    "security",
                    [""],
                )[0].lower()
            )

            flow = (
                query_params.get(
                    "flow",
                    [""],
                )[0].lower()
            )

            sid = query_params.get(
                "sid",
                [""],
            )[0]

            mode = (
                query_params.get(
                    "mode",
                    [""],
                )[0].lower()
            )

            fp = (
                query_params.get(
                    "fp",
                    [""],
                )[0].lower()
            )

            service_name = (
                query_params.get(
                    "serviceName",
                    [""],
                )[0]
            )

            authority = (
                query_params.get(
                    "authority",
                    [""],
                )[0]
            )

            # XHTTP extra должен влиять на уникальность.
            extra = (
                parse_xhttp_extra(
                    query_params
                )
            )

            if extra:

                extra_signature = (
                    json.dumps(
                        extra,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )

    except Exception:
        pass

    path = (
        urllib.parse.unquote(
            path
        )
        or "/"
    )

    return (
        protocol,
        clean_ip,
        str(port),
        sni,
        net,
        path,
        pbk,
        uuid,
        security,
        flow,
        sid,
        mode,
        fp,
        service_name,
        authority,
        extra_signature,
    )


def get_final_dedup_key(
    link: str,
):
    """
    После теста.

    Ключ должен различать разные аккаунты на
    одном белом IP: UUID, mode, serviceName.

    Иначе пачка рабочих конфигов на одном
    endpoint+sni+path схлопывается в один.
    """

    host, port, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if not host or not port:
        return None

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    clean_ip = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    protocol = (
        link.split(
            "://",
            1,
        )[0].lower()
        if "://" in link
        else ""
    )

    sni = extract_sni_from_link(
        link
    )

    net = ""
    path = "/"
    security = ""
    fp = ""
    uuid = ""
    mode = ""
    service_name = ""
    flow = ""
    pbk = ""
    sid = ""

    try:

        if link.startswith(
            "vmess://"
        ):

            b64_data = (
                link.replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = (
                safe_b64decode(
                    b64_data
                )
            )

            data = json.loads(
                decoded
            )

            uuid = str(
                data.get(
                    "id",
                    "",
                )
            )

            net = str(
                data.get(
                    "net",
                    "raw",
                )
            ).lower()

            path = (
                str(
                    data.get(
                        "path",
                        "",
                    )
                )
                or "/"
            )

            security = str(
                data.get(
                    "tls",
                    "",
                )
            ).lower()

            fp = str(
                data.get(
                    "fp",
                    "",
                )
            ).lower()

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            uuid = (
                parsed.username
                or ""
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            net = (
                query_params.get(
                    "type",
                    query_params.get(
                        "net",
                        ["raw"],
                    ),
                )[0].lower()
            )

            path = (
                query_params.get(
                    "path",
                    [""],
                )[0]
                or "/"
            )

            security = (
                query_params.get(
                    "security",
                    [""],
                )[0].lower()
            )

            fp = (
                query_params.get(
                    "fp",
                    [""],
                )[0].lower()
            )

            mode = (
                query_params.get(
                    "mode",
                    [""],
                )[0].lower()
            )

            flow = (
                query_params.get(
                    "flow",
                    [""],
                )[0].lower()
            )

            pbk = query_params.get(
                "pbk",
                [""],
            )[0]

            sid = query_params.get(
                "sid",
                [""],
            )[0]

            service_name = (
                query_params.get(
                    "serviceName",
                    [""],
                )[0]
            )

    except Exception:
        pass

    path = (
        urllib.parse.unquote(
            path
        )
        or "/"
    )

    return (
        protocol,
        clean_ip,
        str(port),
        sni,
        net,
        path,
        security,
        fp,
        uuid,
        mode,
        service_name,
        flow,
        pbk,
        sid,
    )


# ============================================================
# PRE-PING DEDUP
# ============================================================

def clean_and_dedup(
    tagged_items: list,
) -> list:

    seen_strings = set()
    seen_keys = set()
    result = []

    for link, source in tagged_items:

        link = link.strip()

        if not link.startswith(
            SUPPORTED_PROTOCOLS
        ):
            continue

        # Полный текстовый дубль
        if link in seen_strings:
            continue

        seen_strings.add(link)

        # Логический дубль
        key = get_config_dedup_key(
            link
        )

        if not key:
            continue

        if key in seen_keys:
            continue

        seen_keys.add(key)

        result.append(
            (
                link,
                source,
            )
        )

    print(
        f"🧹 Дедуп ДО пинга: "
        f"было {len(tagged_items)}, "
        f"осталось {len(result)}."
    )

    return result


# ============================================================
# ADVANCED DEDUP
# ============================================================

def dedup_advanced(
    items_list: list,
    label: str = "",
) -> list:
    """
    Дедупликация уже проверенных конфигов.

    Используется ПОСЛЕ Xray.
    Здесь элементы имеют формат:

        (link, flag)

    или совместимый tuple/list.

    В отличие от clean_and_dedup():
    - не требует source;
    - использует get_final_dedup_key();
    - сохраняет первый встретившийся рабочий конфиг;
    - не режет количество конфигов;
    - не меняет WL/BL классификацию;
    - не применяет IP /24 лимиты;
    - не фильтрует протоколы.

    То есть эта функция решает только проблему дублей.
    """

    if not items_list:
        print(
            f"🧹 Дедуп {label}: "
            f"было 0, осталось 0."
        )
        return []

    seen_strings = set()
    seen_keys = set()
    result = []

    for item in items_list:

        if not isinstance(
            item,
            (tuple, list),
        ):
            continue

        if not item:
            continue

        link = str(
            item[0]
        ).strip()

        if not link.startswith(
            SUPPORTED_PROTOCOLS
        ):
            continue

        # Полный текстовый дубль.
        if link in seen_strings:
            continue

        seen_strings.add(
            link
        )

        # Логический дубль.
        key = get_final_dedup_key(
            link
        )

        if not key:
            continue

        if key in seen_keys:
            continue

        seen_keys.add(
            key
        )

        result.append(
            item
        )

    print(
        f"🧹 Дедуп {label}: "
        f"было {len(items_list)}, "
        f"осталось {len(result)}."
    )

    return result


# ============================================================
# BL LIMIT
# ============================================================

def limit_bl_configs_per_ip(
    items_list: list,
) -> list:
    """
    Лимиты применяются ТОЛЬКО к BL.

    Это важно:
    WL по словам / RU IP / RU SNI не должен попасть
    под BL-лимит только потому, что его IP нет в white_ips.
    """

    ip_counter = defaultdict(int)
    subnet_counter = defaultdict(int)

    grouped = defaultdict(list)

    for item in items_list:

        link = item[0]

        host, _, _ = (
            parse_host_port_and_name(
                link
            )
        )

        if not host:
            continue

        clean_host = (
            host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

        ip_str = (
            resolve_host_cached(
                clean_host
            )
            or clean_host
        )

        grouped[
            ip_str
        ].append(
            item
        )

    result = []

    for ip_str, items in grouped.items():

        for item in items:

            if (
                ip_counter[ip_str]
                >= MAX_CONFIGS_PER_IP_BL
            ):
                break

            try:

                ip_obj = ipaddress.ip_address(
                    ip_str
                )

                if ip_obj.version == 4:

                    subnet_key = str(
                        ipaddress.ip_network(
                            f"{ip_str}/24",
                            strict=False,
                        )
                    )

                else:

                    subnet_key = str(
                        ipaddress.ip_network(
                            f"{ip_str}/64",
                            strict=False,
                        )
                    )

                if (
                    subnet_counter[
                        subnet_key
                    ]
                    >= MAX_CONFIGS_PER_SUBNET_BL
                ):
                    continue

                subnet_counter[
                    subnet_key
                ] += 1

            except Exception:
                pass

            ip_counter[
                ip_str
            ] += 1

            result.append(
                item
            )

    print(
        f"✂️ BL лимиты ДО пинга: "
        f"было {len(items_list)}, "
        f"осталось {len(result)} | "
        f"IP={MAX_CONFIGS_PER_IP_BL}, "
        f"/24={MAX_CONFIGS_PER_SUBNET_BL}"
    )

    return result

