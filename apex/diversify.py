"""Diversity WL, фильтр протоколов BL, rename конфигов."""
from __future__ import annotations

import re
import json
import base64
import urllib.parse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import (
    MAX_CONFIGS_PER_IP_WL,
    SUPPORTED_PROTOCOLS,
    RENAME_TEMPLATE,
    UTF8_CONFIG_NAMES,
)
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
# SANITIZE LINK (чистка грязных параметров от источников)
# ============================================================

_VALID_NETWORKS = frozenset({
    "tcp", "raw", "ws", "http", "h2", "grpc", "gun", "quic", "kcp", "mkcp",
})
_VALID_SECURITY = frozenset({
    "reality", "tls", "xtls", "none", "auto", "",
})
_VALID_FLOW = frozenset({
    "xtls-rprx-vision", "xtls-rprx-vision-udp443", "xtls-rprx-direct",
    "xtls-rprx-splice", "",
})


def _clean_param_value(raw: str) -> str:
    """Убирает мусор после #, пробелов, emoji и т.п. из значения параметра."""
    if not raw:
        return ""
    val = raw.split("#", 1)[0]
    val = re.split(r"[\s@\U0001F300-\U0001F9FF]+", val, maxsplit=1)[0]
    return val.strip().strip("'\"")


def sanitize_proxy_link(link: str) -> Optional[str]:
    """
    Чистит query-параметры ссылки от мусора источников
    (type=tcp#1 @channel, security=reality🔒 и т.п.).

    Возвращает очищенную ссылку без fragment (имя потом поставит rename)
    или None — если ссылка совсем битая и её лучше отсечь.
    """
    if not link or not isinstance(link, str) or "://" not in link:
        return None

    link = link.strip()
    proto, rest = link.split("://", 1)
    proto = proto.lower().strip()
    rest = rest.split("#", 1)[0]

    if proto == "vmess":
        try:
            decoded = safe_b64decode(rest)
            data = json.loads(decoded)
            if not isinstance(data, dict):
                return None

            net = _clean_param_value(str(data.get("net") or data.get("type") or "tcp")).lower()
            if net not in _VALID_NETWORKS:
                net = "tcp"
            data["net"] = net

            tls = _clean_param_value(str(data.get("tls") or "")).lower()
            if tls in ("reality", "tls", "xtls", "1", "true"):
                data["tls"] = tls if tls in ("reality", "tls", "xtls") else "tls"
            else:
                data["tls"] = ""

            for key in ("path", "host", "sni", "add"):
                if key in data and data[key]:
                    data[key] = _clean_param_value(str(data[key]))

            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            encoded = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
            return "vmess://" + encoded
        except Exception:
            return None

    if proto == "ss" and "@" not in rest:
        return f"{proto}://{rest}"

    if "@" not in rest:
        return None

    try:
        userinfo, hostport = rest.rsplit("@", 1)
        host_port_part = hostport.split("?", 1)[0]
        query = ""
        if "?" in hostport:
            query = hostport.split("?", 1)[1]

        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        cleaned: Dict[str, str] = {}

        for key, values in params.items():
            if not values:
                continue
            raw_val = values[0]
            key_l = key.lower()

            if key_l in ("type", "net", "network"):
                val = _clean_param_value(raw_val).lower()
                if val not in _VALID_NETWORKS:
                    val = "tcp"
                cleaned["type"] = val
            elif key_l == "security":
                val = _clean_param_value(raw_val).lower()
                if val not in _VALID_SECURITY:
                    if "reality" in val:
                        val = "reality"
                    elif "tls" in val or "xtls" in val:
                        val = "tls"
                    else:
                        val = "none"
                cleaned["security"] = val
            elif key_l == "flow":
                val = _clean_param_value(raw_val).lower()
                if val not in _VALID_FLOW:
                    if "vision" in val:
                        val = "xtls-rprx-vision"
                    else:
                        val = ""
                if val:
                    cleaned["flow"] = val
            elif key_l in (
                "sni", "host", "path", "pbk", "sid", "fp", "spx",
                "alpn", "serviceName", "mode", "headerType",
                "encryption", "packetEncoding",
            ):
                val = _clean_param_value(raw_val)
                if val:
                    cleaned[key] = val
            else:
                val = _clean_param_value(raw_val)
                if val:
                    cleaned[key] = val

        if "type" not in cleaned and proto in ("vless", "trojan"):
            cleaned["type"] = "tcp"

        new_query = urllib.parse.urlencode(cleaned, doseq=False)
        new_rest = f"{userinfo}@{host_port_part}"
        if new_query:
            new_rest += "?" + new_query
        return f"{proto}://{new_rest}"
    except Exception:
        return None


# ============================================================
# RENAME
# ============================================================

def rename_config(
    link: str,
    index: int,
    tag: str,
    detected_flag: str,
) -> str:
    """
    Всегда принудительно переименовывает конфиг.
    Для vmess — обновляет ps внутри JSON.
    Для остальных — заменяет/добавляет fragment (#name).
    Имя строится по RENAME_TEMPLATE из config
    ({flag}, {tag}, {index}).
    """
    flag = (detected_flag or "").strip() or "🌐"
    if not isinstance(flag, str):
        flag = "🌐"
    try:
        new_name = RENAME_TEMPLATE.format(
            flag=flag,
            tag=tag,
            index=index,
        )
    except Exception:
        new_name = f"{flag} {tag} Сервер {index}"
    # fragment: сырой UTF-8 или percent-encode
    if UTF8_CONFIG_NAMES:
        frag_name = new_name
    else:
        frag_name = urllib.parse.quote(new_name, safe="")

    if not link or not isinstance(link, str):
        return link

    link = link.strip()

    # ---- vmess: имя только внутри ps ----
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "", 1).strip()
            # убрать возможный старый fragment
            if "#" in b64_data:
                b64_data = b64_data.split("#", 1)[0]
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            if not isinstance(data, dict):
                raise ValueError("vmess payload is not dict")
            data["ps"] = new_name
            # компактный JSON — меньше проблем у клиентов
            payload = json.dumps(
                data,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            encoded = base64.b64encode(
                payload.encode("utf-8")
            ).decode("utf-8")
            # для единообразия добавляем и #name (многие клиенты его показывают)
            return "vmess://" + encoded + "#" + frag_name
        except Exception:
            # fallback: хотя бы fragment
            main = link.split("#", 1)[0]
            return main + "#" + frag_name

    # ---- все остальные протоколы (vless/trojan/ss/hy2/...) ----
    if "://" in link:
        main_part = link.split("#", 1)[0]
        return main_part + "#" + frag_name

    return link



# ============================================================
# CLASH YAML (базовый экспорт для Clash / Mihomo / Meta)
# ============================================================

def _clash_proxy_from_link(link: str, name: str) -> Optional[Dict[str, Any]]:
    """
    Минимальный конвертер ссылки → dict Clash proxy.
    Поддерживает vless / vmess / trojan / ss / hysteria2.
    Возвращает None если не удалось разобрать.
    """
    try:
        if not link or "://" not in link:
            return None

        proto, rest = link.split("://", 1)
        proto = proto.lower().strip()
        rest = rest.split("#", 1)[0]  # без имени

        if proto == "vmess":
            decoded = safe_b64decode(rest)
            data = json.loads(decoded)
            server = str(data.get("add") or data.get("host") or "").strip()
            port = int(data.get("port") or 0)
            if not server or not port:
                return None
            proxy: Dict[str, Any] = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": str(data.get("id") or ""),
                "alterId": int(data.get("aid") or 0),
                "cipher": str(data.get("scy") or "auto"),
                "network": str(data.get("net") or "tcp"),
            }
            tls = str(data.get("tls") or "").lower()
            if tls in ("tls", "1", "true"):
                proxy["tls"] = True
            sni = data.get("sni") or data.get("host") or ""
            if sni:
                proxy["servername"] = str(sni)
            path = data.get("path")
            if path:
                proxy["ws-opts"] = {"path": str(path)}
                if data.get("host"):
                    proxy["ws-opts"]["headers"] = {"Host": str(data["host"])}
            return proxy

        # parse generic URI
        if "@" not in rest:
            # ss pure base64 method:pass@host:port
            if proto == "ss":
                try:
                    decoded = safe_b64decode(rest)
                    if "@" in decoded:
                        userinfo, hostport = decoded.rsplit("@", 1)
                        method, password = userinfo.split(":", 1)
                        host, port_s = parse_host_port(hostport)
                        if host and port_s:
                            return {
                                "name": name,
                                "type": "ss",
                                "server": host.strip("[]"),
                                "port": int(port_s),
                                "cipher": method,
                                "password": password,
                            }
                except Exception:
                    pass
            return None

        userinfo, hostport = rest.rsplit("@", 1)
        host, port = parse_host_port(hostport.split("?")[0])
        if not host or not port:
            return None
        host = host.strip("[]")

        query = ""
        if "?" in rest:
            query = rest.split("?", 1)[1]
        params = urllib.parse.parse_qs(query, keep_blank_values=True)

        def pget(key: str, default: str = "") -> str:
            return (params.get(key, [default])[0] or default)

        if proto == "vless":
            proxy = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": int(port),
                "uuid": userinfo,
                "network": pget("type", "tcp") or "tcp",
                "udp": True,
            }
            security = pget("security", "").lower()
            if security == "reality":
                proxy["tls"] = True
                proxy["reality-opts"] = {
                    "public-key": pget("pbk"),
                    "short-id": pget("sid"),
                }
                if pget("sni"):
                    proxy["servername"] = pget("sni")
                if pget("fp"):
                    proxy["client-fingerprint"] = pget("fp")
            elif security in ("tls", "xtls"):
                proxy["tls"] = True
                if pget("sni"):
                    proxy["servername"] = pget("sni")
                if pget("fp"):
                    proxy["client-fingerprint"] = pget("fp")
            flow = pget("flow")
            if flow:
                proxy["flow"] = flow
            return proxy

        if proto == "trojan":
            proxy = {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": int(port),
                "password": userinfo,
                "udp": True,
            }
            if pget("sni"):
                proxy["sni"] = pget("sni")
            if pget("fp"):
                proxy["client-fingerprint"] = pget("fp")
            return proxy

        if proto == "ss":
            # userinfo is method:password (sometimes base64)
            method, password = userinfo, ""
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                try:
                    dec = safe_b64decode(userinfo)
                    if ":" in dec:
                        method, password = dec.split(":", 1)
                except Exception:
                    pass
            return {
                "name": name,
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password,
            }

        if proto in ("hysteria2", "hy2"):
            proxy = {
                "name": name,
                "type": "hysteria2",
                "server": host,
                "port": int(port),
                "password": userinfo,
            }
            if pget("sni"):
                proxy["sni"] = pget("sni")
            return proxy

    except Exception:
        return None
    return None


def _yaml_escape(s: str) -> str:
    """Простое экранирование для YAML double-quoted string."""
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", " ")
        .replace("\r", "")
    )


def links_to_clash_yaml(links: List[str]) -> str:
    """
    Собирает минимальный Clash-совместимый YAML (без внешних зависимостей):
    proxies:
      - name: "..."
        type: ...
        ...
    """
    out: List[str] = ["proxies:"]

    for idx, link in enumerate(links, 1):
        name = f"Server {idx}"
        if "#" in link:
            try:
                name = urllib.parse.unquote(link.split("#", 1)[1])
            except Exception:
                pass
        name = name.replace("\n", " ").replace("\r", "").strip() or f"Server {idx}"
        p = _clash_proxy_from_link(link, name)
        if not p:
            continue

        out.append(f'  - name: "{_yaml_escape(p["name"])}"')
        out.append(f'    type: {p["type"]}')
        out.append(f'    server: {p["server"]}')
        out.append(f'    port: {p["port"]}')

        for key in (
            "uuid",
            "password",
            "cipher",
            "alterId",
            "network",
            "flow",
            "sni",
            "servername",
            "client-fingerprint",
            "udp",
            "tls",
        ):
            if key not in p:
                continue
            val = p[key]
            if isinstance(val, bool):
                out.append(f"    {key}: {'true' if val else 'false'}")
            elif isinstance(val, (int, float)):
                out.append(f"    {key}: {val}")
            else:
                out.append(f'    {key}: "{_yaml_escape(str(val))}"')

        if "reality-opts" in p and isinstance(p["reality-opts"], dict):
            out.append("    reality-opts:")
            for rk, rv in p["reality-opts"].items():
                if rv:
                    out.append(f'      {rk}: "{_yaml_escape(str(rv))}"')

        if "ws-opts" in p and isinstance(p["ws-opts"], dict):
            out.append("    ws-opts:")
            path = p["ws-opts"].get("path")
            if path:
                out.append(f'      path: "{_yaml_escape(str(path))}"')
            headers = p["ws-opts"].get("headers")
            if headers and isinstance(headers, dict):
                out.append("      headers:")
                for hk, hv in headers.items():
                    out.append(f'        {hk}: "{_yaml_escape(str(hv))}"')

    out.append("")
    return "\n".join(out)
