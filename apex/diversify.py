"""Diversity WL, фильтр протоколов BL, rename конфигов."""
from __future__ import annotations

import re
import json
import base64
import urllib.parse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import MAX_CONFIGS_PER_IP_WL, SUPPORTED_PROTOCOLS
from .parse import parse_host_port, parse_host_port_and_name, extract_sni_from_link
from .utils import extract_clean_flag, cc_to_flag, safe_b64decode
from .geoip import resolve_host_cached
from .dedup import get_final_dedup_key, get_config_dedup_key

def get_wl_item_info(
    item,
):
    link = item[0]

    host, port, orig_name = (
        parse_host_port_and_name(
            link
        )
    )

    clean_host = (
        host.strip(
            '[] \t\r\n\'"'
        ).lower()
        if host
        else ""
    )

    ip_str = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    flag = (
        item[1]
        if len(item) > 1
        else extract_clean_flag(
            orig_name
        )
    )

    sni = extract_sni_from_link(
        link
    )

    path = "/"

    try:

        if link.startswith(
            "vmess://"
        ):

            decoded = (
                safe_b64decode(
                    link
                    .replace(
                        "vmess://",
                        "",
                        1,
                    )
                    .strip()
                )
            )

            data = json.loads(
                decoded
            )

            sni = (
                data.get("sni")
                or data.get("host")
                or sni
                or ""
            )

            path = (
                str(
                    data.get(
                        "path",
                        "/",
                    )
                )
                or "/"
            )

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            path = (
                query_params.get(
                    "path",
                    ["/"],
                )[0]
                or "/"
            )

    except Exception:
        pass

    net = ""
    uuid = ""
    fp = ""
    security = ""
    mode = ""

    try:
        if link.startswith("vmess://"):
            decoded = safe_b64decode(
                link.replace("vmess://", "", 1).strip()
            )
            data = json.loads(decoded)
            net = str(data.get("net", "raw")).lower()
            uuid = str(data.get("id", ""))
            fp = str(data.get("fp", "")).lower()
            security = str(data.get("tls", "")).lower()
        else:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username or ""
            qp = urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
            )
            net = (
                qp.get("type", qp.get("net", ["raw"]))[0]
            ).lower()
            fp = (qp.get("fp", [""])[0] or "").lower()
            security = (
                qp.get("security", [""])[0] or ""
            ).lower()
            mode = (qp.get("mode", [""])[0] or "").lower()
    except Exception:
        pass

    return {
        "link": link,
        "ip": ip_str,
        "flag": flag,
        "sni": (sni or "").lower(),
        "path": urllib.parse.unquote(path),
        "source": (
            item[2] if len(item) > 2 else ""
        ),
        "net": net,
        "uuid": uuid,
        "fp": fp,
        "security": security,
        "mode": mode,
    }


def select_wl_diverse(
    alive_items: list,
) -> list:
    """
    WL diversity: max MAX_CONFIGS_PER_IP_WL на IP.

    Приоритет:
      white_ip / RU SNI / Reality / новый UUID / новый path
    """

    if not alive_items:
        return []

    grouped = defaultdict(list)

    for item in alive_items:
        info = get_wl_item_info(item)
        grouped[info["ip"]].append((item, info))

    result = []

    for ip_str, entries in grouped.items():
        selected = []
        used_sni = set()
        used_uuids = set()
        used_paths = set()
        used_pairs = set()

        def score(entry):
            item, info = entry
            s = 0
            src = str(info.get("source") or "")

            if info["sni"] and info["sni"] not in used_sni:
                s += 1000

            sni = info["sni"]
            if info.get("security") == "reality":
                s += 400

            # Всё русское — высокий приоритет
            if sni.endswith((".ru", ".su")) or any(
                x in sni
                for x in (
                    "yandex",
                    "vk.com",
                    "vk.ru",
                    "x5.ru",
                    "max.ru",
                    "gismeteo",
                    "rutube",
                    "rbc.ru",
                    "ozone",
                )
            ):
                s += 600

            if src.startswith("WHITE_IP"):
                s += 300
            if src.startswith("RU_EXIT"):
                s += 250

            if info.get("uuid") and info["uuid"] not in used_uuids:
                s += 450

            pair = (info["sni"], info["path"])
            if pair not in used_pairs:
                s += 250
            if info["path"] not in used_paths:
                s += 100

            return s

        remaining = list(entries)
        while remaining and len(selected) < MAX_CONFIGS_PER_IP_WL:
            remaining.sort(key=score, reverse=True)
            item, info = remaining.pop(0)
            selected.append(item)
            if info["sni"]:
                used_sni.add(info["sni"])
            if info.get("uuid"):
                used_uuids.add(info["uuid"])
            used_paths.add(info["path"])
            used_pairs.add((info["sni"], info["path"]))

        result.extend(selected)

    print(
        f"🎨 WL diversity: "
        f"до={len(alive_items)}, "
        f"после={len(result)}"
    )

    return result


# ============================================================
# BL PROTOCOL FILTER
#
# НЕ МЕНЯЮ.
# ============================================================

def filter_protocols_bl(
    alive_configs,
    minority_ratio=0.10,
):

    priority = []
    minority = []

    for item in alive_configs:

        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        proto = (
            link
            .split(
                "://",
                1,
            )[0]
            .lower()
        )

        if proto in (
            "vless",
            "hysteria2",
            "hy2",
        ):

            priority.append(
                item
            )

        else:

            minority.append(
                item
            )

    max_minority = max(
        10,
        int(
            len(priority)
            * (
                minority_ratio
                / (
                    1
                    - minority_ratio
                )
            )
        ),
    )

    if len(minority) > max_minority:

        minority = minority[
            :max_minority
        ]

    print(
        f"🎯 Фильтр BL протоколов: "
        f"VLESS/Hy2: "
        f"{len(priority)} шт. | "
        f"Старые: "
        f"{len(minority)} шт. "
        f"(лимит "
        f"{minority_ratio * 100:.0f}%)"
    )

    return (
        priority
        + minority
    )


# ============================================================
# RENAME
# ============================================================

def rename_config(
    link: str,
    index: int,
    tag: str,
    detected_flag: str,
) -> str:

    new_name = (
        f"{detected_flag} "
        f"{tag} Сервер {index}"
    )

    if link.startswith(
        "vmess://"
    ):

        try:

            b64_data = (
                link
                .replace(
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

            data["ps"] = (
                new_name
            )

            encoded = (
                base64.b64encode(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                    ).encode(
                        "utf-8"
                    )
                )
                .decode(
                    "utf-8"
                )
            )

            return (
                "vmess://"
                + encoded
            )

        except Exception:
            pass

    if "://" in link:

        main_part = link.split(
            "#",
            1,
        )[0]

        return (
            main_part
            + "#"
            + urllib.parse.quote(
                new_name
            )
        )

    return link

