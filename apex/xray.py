"""Xray: конвертация ссылок в outbound, проверка живости (часть 1)."""
from __future__ import annotations

import io
import json
import base64
import urllib.parse
import urllib.request
import re
import os
import socket
import subprocess
import time
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config as cfg
from .config import (
    SSL_CONTEXT,
    XRAY_START_TIMEOUT,
    XRAY_TEST_TIMEOUT,
    TCP_CHECK_TIMEOUT,
    WL_MIN_SUCCESS_COUNT,
    BL_MIN_SUCCESS_COUNT,
    SUPPORTED_PROTOCOLS,
    HEADERS,
    REMOVE_CF_WARP,
    REMOVE_PRIVATE_INVALID,
)
from .parse import parse_host_port, parse_host_port_and_name, extract_sni_from_link
from .utils import safe_b64decode, safe_b64encode, cc_to_flag, extract_clean_flag
from .geoip import fetch_country_from_ip, resolve_host_cached, is_valid_public_host, is_cloudflare_or_warp

def parse_xhttp_extra(
    query_params: dict,
) -> dict:
    """
    В источнике extra — URL-encoded JSON.

    Например:

      extra={
        "host": "",
        "path": "",
        "mode": "",
        "headers": {...},
        "xPaddingBytes": "...",
        "sessionIDPlacement": "...",
        "seqPlacement": "...",
        "xmux": {...},
        ...
      }

    Эти поля должны попасть НЕ внутрь
    xhttpSettings["extra"], а непосредственно
    в xhttpSettings.
    """

    raw = query_params.get(
        "extra",
        [""],
    )[0]

    if not raw:
        return {}

    try:

        decoded = urllib.parse.unquote(
            raw
        )

        data = json.loads(
            decoded
        )

        if isinstance(
            data,
            dict,
        ):
            return data

    except Exception:
        pass

    return {}


def first_param(
    params: dict,
    name: str,
    default: str = "",
) -> str:

    values = params.get(
        name
    )

    if not values:
        return default

    return str(
        values[0]
    )


def parse_bool_param(
    params: dict,
    *names,
    default=False,
) -> bool:

    for name in names:

        if name not in params:
            continue

        value = str(
            params[name][0]
        ).strip().lower()

        return value in (
            "1",
            "true",
            "yes",
            "on",
        )

    return default


# ============================================================
# LINK -> XRAY OUTBOUND
# ============================================================

def link_to_xray_outbound(
    link: str,
):
    try:

        main_part = link.split(
            "#",
            1,
        )[0]

        if "://" not in main_part:
            return None

        protocol, rest = (
            main_part.split(
                "://",
                1,
            )
        )

        protocol = protocol.lower()

        query_params = {}

        if "?" in rest:

            rest, query_part = (
                rest.split(
                    "?",
                    1,
                )
            )

            query_params = (
                urllib.parse.parse_qs(
                    query_part,
                    keep_blank_values=True,
                )
            )

        outbound = {
            "streamSettings": {}
        }

        # ====================================================
        # HYSTERIA2 / HY2
        #
        # Актуальная схема Xray (method, не network):
        #   protocol: "hysteria"
        #   settings: { version: 2, address, port }
        #   streamSettings.method: "hysteria"
        #   streamSettings.hysteriaSettings: { version: 2, auth }
        #   streamSettings.tlsSettings: { serverName, allowInsecure, alpn, ... }
        #   streamSettings.finalmask.udp: [ { type: salamander, settings: { password } } ]
        #   streamSettings.finalmask.quicParams: { brutalUp, brutalDown, udpHop }
        # ====================================================

        if protocol in (
            "hysteria2",
            "hy2",
        ):

            auth = ""
            host_port_raw = rest

            if "@" in rest:
                auth, host_port_raw = rest.rsplit("@", 1)
                auth = urllib.parse.unquote(auth)

            # Сохраняем полный port-list для udpHop, для settings.port — первый порт.
            # Форматы URI: host:443 | host:443,5000-6000 | host:20000-50000
            port_list_str = ""
            if ":" in host_port_raw:
                # отделяем host от port-части (с учётом IPv6 [addr]:ports)
                if host_port_raw.startswith("["):
                    if "]" not in host_port_raw:
                        return None
                    host_only, port_part = host_port_raw.split("]", 1)
                    host_only = host_only + "]"
                    port_part = port_part.lstrip(":")
                else:
                    host_only, port_part = host_port_raw.rsplit(":", 1)
                port_list_str = port_part.strip().rstrip("/")
            else:
                host_only = host_port_raw
                port_list_str = "443"

            # Первый порт для settings.port
            first_port_str = port_list_str.split(",")[0].strip()
            if "-" in first_port_str:
                first_port_str = first_port_str.split("-", 1)[0].strip()

            try:
                port = int(first_port_str)
            except (TypeError, ValueError):
                return None

            host = host_only.strip()
            if not host or not port:
                return None

            if not auth:
                auth = first_param(query_params, "auth", "") or first_param(
                    query_params, "password", ""
                )

            # SNI: только явный sni/peer; host — fallback только если нет явного
            sni_explicit = first_param(query_params, "sni", "") or first_param(
                query_params, "peer", ""
            )
            sni = sni_explicit or host

            allow_insecure = parse_bool_param(
                query_params,
                "allowInsecure",
                "insecure",
                default=False,
            )

            # ALPN: default h3 только если пользователь ничего не передал
            alpn_raw = first_param(query_params, "alpn", "")
            if alpn_raw:
                alpn_list = [x.strip() for x in alpn_raw.split(",") if x.strip()]
            else:
                alpn_list = ["h3"]

            fp = first_param(query_params, "fp", "") or first_param(
                query_params, "fingerprint", ""
            )

            tls_settings: Dict[str, Any] = {
                "serverName": sni,
                "allowInsecure": allow_insecure,
                "alpn": alpn_list,
            }
            if fp:
                tls_settings["fingerprint"] = fp

            pin = first_param(query_params, "pinSHA256", "")
            if pin:
                tls_settings["pinnedPeerCertSha256"] = pin.replace(":", "").lower()

            hysteria_settings: Dict[str, Any] = {
                "version": 2,
                "auth": auth,
            }

            # Bandwidth → finalmask.quicParams (актуальная схема Xray)
            # Поддерживаем и legacy up/down в hysteriaSettings для совместимости.
            def _norm_bw(val: str) -> str:
                v = (val or "").strip()
                if not v:
                    return ""
                low = v.lower().replace(" ", "")
                if any(
                    u in low
                    for u in (
                        "bps",
                        "kbps",
                        "mbps",
                        "gbps",
                        "tbps",
                        "kb",
                        "mb",
                        "gb",
                        "tb",
                        "k",
                        "m",
                        "g",
                    )
                ):
                    return v
                # голое число → Mbps
                try:
                    float(v)
                    return f"{v} mbps"
                except ValueError:
                    return v

            up = first_param(query_params, "up", "") or first_param(
                query_params, "upmbps", ""
            )
            down = first_param(query_params, "down", "") or first_param(
                query_params, "downmbps", ""
            )
            up_n = _norm_bw(up)
            down_n = _norm_bw(down)
            if up_n:
                hysteria_settings["up"] = up_n
            if down_n:
                hysteria_settings["down"] = down_n

            # finalmask
            finalmask: Dict[str, Any] = {}

            # Port hopping → quicParams.udpHop
            # multi-port если в URI больше одного сегмента или есть range
            is_multi = (
                "," in port_list_str
                or ("-" in port_list_str and port_list_str != first_port_str)
            )
            quic_params: Dict[str, Any] = {}
            if is_multi:
                quic_params["udpHop"] = {
                    "ports": port_list_str,
                }
            if up_n:
                quic_params["brutalUp"] = up_n
            if down_n:
                quic_params["brutalDown"] = down_n
            if quic_params:
                finalmask["quicParams"] = quic_params

            # Salamander / Gecko
            obfs = first_param(query_params, "obfs", "").lower()
            obfs_password = first_param(
                query_params, "obfs-password", ""
            ) or first_param(query_params, "obfsPassword", "")

            if obfs in ("salamander", "gecko") and obfs_password:
                sal_settings: Dict[str, Any] = {"password": obfs_password}
                # gecko: опциональный packetSize из query, если есть
                pkt = first_param(query_params, "obfs-packet-size", "") or first_param(
                    query_params, "packetSize", ""
                )
                if obfs == "gecko" and pkt:
                    sal_settings["packetSize"] = pkt
                finalmask["udp"] = [
                    {
                        "type": "salamander",
                        "settings": sal_settings,
                    }
                ]

            stream: Dict[str, Any] = {
                # Актуальный ключ Xray — method (network — устаревший alias)
                "method": "hysteria",
                "security": "tls",
                "tlsSettings": tls_settings,
                "hysteriaSettings": hysteria_settings,
            }
            if finalmask:
                stream["finalmask"] = finalmask

            outbound.update(
                {
                    "protocol": "hysteria",
                    "settings": {
                        "version": 2,
                        "address": host,
                        "port": port,
                    },
                    "streamSettings": stream,
                }
            )

            return outbound

        # ====================================================
        # SHADOWSOCKS
        # ====================================================

        if protocol == "ss":

            if "@" not in rest:

                decoded = (
                    safe_b64decode(
                        rest
                    )
                )

                if "@" not in decoded:
                    return None

                user_info, host_port = (
                    decoded.rsplit(
                        "@",
                        1,
                    )
                )

            else:

                user_info, host_port = (
                    rest.rsplit(
                        "@",
                        1,
                    )
                )

                if ":" not in user_info:

                    try:
                        user_info = (
                            safe_b64decode(
                                user_info
                            )
                        )

                    except Exception:
                        pass

            if ":" not in user_info:
                return None

            method, password = (
                user_info.split(
                    ":",
                    1,
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": host,
                                "port": port,
                                "method": method,
                                "password": password,
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # VLESS
        # ====================================================

        elif protocol == "vless":

            if "@" not in rest:
                return None

            user_info, host_port = (
                rest.rsplit(
                    "@",
                    1,
                )
            )

            user_info = (
                urllib.parse.unquote(
                    user_info
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if (
                not host
                or not port
                or not user_info
            ):
                return None

            flow = first_param(
                query_params,
                "flow",
                "",
            )

            user = {
                "id": user_info,
                "encryption": first_param(
                    query_params,
                    "encryption",
                    "none",
                ) or "none",
            }

            if flow:
                user[
                    "flow"
                ] = flow

            outbound.update(
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": port,
                                "users": [
                                    user
                                ],
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # TROJAN
        # ====================================================

        elif protocol == "trojan":

            if "@" not in rest:
                return None

            user_info, host_port = (
                rest.rsplit(
                    "@",
                    1,
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": host,
                                "port": port,
                                "password": (
                                    urllib.parse.unquote(
                                        user_info
                                    )
                                ),
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # VMESS
        # ====================================================

        elif protocol == "vmess":

            decoded = safe_b64decode(
                rest
            )

            data = json.loads(
                decoded
            )

            host = data.get(
                "add"
            )

            port = int(
                data.get(
                    "port"
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": port,
                                "users": [
                                    {
                                        "id": data.get(
                                            "id"
                                        ),
                                        "alterId": int(
                                            data.get(
                                                "aid",
                                                0,
                                            )
                                        ),
                                        "security": (
                                            data.get(
                                                "scy",
                                                "auto",
                                            )
                                            or "auto"
                                        ),
                                    }
                                ],
                            }
                        ]
                    },
                }
            )

            query_params = {
                "security": [
                    data.get(
                        "tls",
                        "",
                    )
                ],
                "sni": [
                    data.get(
                        "sni",
                        "",
                    )
                    or data.get(
                        "host",
                        "",
                    )
                ],
                "type": [
                    data.get(
                        "net",
                        "",
                    )
                ],
                "path": [
                    data.get(
                        "path",
                        "/",
                    )
                ],
                "host": [
                    data.get(
                        "host",
                        "",
                    )
                ],
                "alpn": [
                    data.get(
                        "alpn",
                        "",
                    )
                ],
                "fp": [
                    data.get(
                        "fp",
                        "",
                    )
                ],
            }

        else:
            return None

        # ====================================================
        # SECURITY
        # ====================================================

        security = first_param(
            query_params,
            "security",
            "",
        ).lower()

        if (
            protocol == "trojan"
            and not security
        ):
            security = "tls"

        if security in (
            "tls",
            "reality",
        ):

            outbound[
                "streamSettings"
            ]["security"] = security

            sni = (
                first_param(
                    query_params,
                    "sni",
                    "",
                )
                or first_param(
                    query_params,
                    "host",
                    "",
                )
            )

            fp = first_param(
                query_params,
                "fp",
                "",
            )

            alpn_raw = first_param(
                query_params,
                "alpn",
                "",
            )

            alpn_list = [
                x.strip()
                for x in alpn_raw.split(",")
                if x.strip()
            ]

            allow_insecure = (
                parse_bool_param(
                    query_params,
                    "allowInsecure",
                    "insecure",
                    default=False,
                )
            )

            if security == "tls":

                tls_settings = {
                    "serverName": sni,
                    "allowInsecure": (
                        allow_insecure
                    ),
                }

                if fp:
                    tls_settings[
                        "fingerprint"
                    ] = fp

                if alpn_list:
                    tls_settings[
                        "alpn"
                    ] = alpn_list

                outbound[
                    "streamSettings"
                ]["tlsSettings"] = (
                    tls_settings
                )

            else:

                # IMPORTANT:
                # current Xray uses "password" for
                # the REALITY public key.
                reality_settings = {
                    "serverName": sni,
                    "password": first_param(
                        query_params,
                        "pbk",
                        "",
                    ),
                    "shortId": first_param(
                        query_params,
                        "sid",
                        "",
                    ),
                    "fingerprint": (
                        fp
                        or "chrome"
                    ),
                }

                spx = first_param(
                    query_params,
                    "spx",
                    "",
                )

                if spx:
                    reality_settings[
                        "spiderX"
                    ] = spx

                # В некоторых старых ссылках поле
                # publicKey могло встречаться вместо pbk.
                if not reality_settings[
                    "password"
                ]:
                    reality_settings[
                        "password"
                    ] = first_param(
                        query_params,
                        "publicKey",
                        "",
                    )

                outbound[
                    "streamSettings"
                ]["realitySettings"] = (
                    reality_settings
                )

        # ====================================================
        # TRANSPORT
        #
        # CURRENT XRAY:
        # streamSettings.method
        # ====================================================

        net = (
            first_param(
                query_params,
                "type",
                "",
            )
            or first_param(
                query_params,
                "net",
                "",
            )
        ).lower()

        if not net:
            net = "raw"

        outbound[
            "streamSettings"
        ]["method"] = net

        path_val = urllib.parse.unquote(
            first_param(
                query_params,
                "path",
                "/",
            )
            or "/"
        )

        host_val = first_param(
            query_params,
            "host",
            "",
        )

        header_type = first_param(
            query_params,
            "headerType",
            "none",
        )

        # ====================================================
        # XHTTP
        # ====================================================

        if net in (
            "xhttp",
            "splithttp",
        ):

            # У текущего Xray transport method называется xhttp.
            outbound[
                "streamSettings"
            ]["method"] = "xhttp"

            extra_data = parse_xhttp_extra(
                query_params
            )

            xhttp_settings = dict(
                extra_data
            )

            # query-параметры имеют приоритет
            # только когда они реально заданы.

            if host_val:
                xhttp_settings[
                    "host"
                ] = host_val

            if path_val:
                xhttp_settings[
                    "path"
                ] = path_val

            mode_val = first_param(
                query_params,
                "mode",
                "",
            )

            if mode_val:
                xhttp_settings[
                    "mode"
                ] = mode_val

            xhttp_settings.setdefault(
                "host",
                "",
            )

            xhttp_settings.setdefault(
                "path",
                "/",
            )

            xhttp_settings.setdefault(
                "mode",
                "auto",
            )

            outbound[
                "streamSettings"
            ]["xhttpSettings"] = (
                xhttp_settings
            )

        # ====================================================
        # WEB SOCKET
        # ====================================================

        elif net == "ws":

            ws_settings = {
                "path": path_val,
            }

            if host_val:
                ws_settings[
                    "headers"
                ] = {
                    "Host": host_val
                }

            else:
                ws_settings[
                    "headers"
                ] = {}

            outbound[
                "streamSettings"
            ]["wsSettings"] = (
                ws_settings
            )

        # ====================================================
        # GRPC
        # ====================================================

        elif net == "grpc":

            grpc_settings = {
                "serviceName": (
                    first_param(
                        query_params,
                        "serviceName",
                        "",
                    )
                    or path_val.lstrip("/")
                )
            }

            authority = first_param(
                query_params,
                "authority",
                "",
            )

            if authority:
                grpc_settings[
                    "authority"
                ] = authority

            # mode=gun / multi → multiMode в Xray
            grpc_mode = first_param(
                query_params,
                "mode",
                "",
            ).lower()

            if grpc_mode in (
                "gun",
                "multi",
                "true",
                "1",
            ):
                grpc_settings[
                    "multiMode"
                ] = True

            outbound[
                "streamSettings"
            ]["grpcSettings"] = (
                grpc_settings
            )

        # ====================================================
        # HTTP UPGRADE
        # ====================================================

        elif net == "httpupgrade":

            outbound[
                "streamSettings"
            ]["httpupgradeSettings"] = {
                "path": path_val,
                "host": host_val,
            }

        # ====================================================
        # HTTP / H2
        # ====================================================

        elif net in (
            "http",
            "h2",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "http"

            outbound[
                "streamSettings"
            ]["httpSettings"] = {
                "path": path_val,
                "host": (
                    [host_val]
                    if host_val
                    else []
                ),
            }

        # ====================================================
        # mKCP
        # ====================================================

        elif net in (
            "kcp",
            "mkcp",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "mkcp"

            outbound[
                "streamSettings"
            ]["kcpSettings"] = {
                "header": {
                    "type": header_type
                }
            }

        # ====================================================
        # RAW
        # ====================================================

        elif net in (
            "tcp",
            "raw",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "raw"

            header_type = first_param(
                query_params,
                "headerType",
                "",
            )

            if header_type:
                outbound[
                    "streamSettings"
                ]["rawSettings"] = {
                    "header": {
                        "type": header_type
                    }
                }

        return outbound

    except Exception:
        return None



# ============================================================
# XRAY RUNTIME / ALIVE CHECKS
# ============================================================

def xray_core_ready() -> bool:
    """Бинарь Xray есть рядом с проектом?"""
    name = "xray.exe" if os.name == "nt" else "xray"
    return os.path.exists(name)


def ensure_xray_core() -> bool:
    """
    Гарантирует наличие бинаря Xray: если его нет в корне и включён
    AUTO_DOWNLOAD_XRAY — скачивает с GitHub releases нужной платформы
    и распаковывает. На Actions это no-op (там ставится шагом workflow),
    локально решает установку без ручных действий.
    """
    if xray_core_ready():
        return True
    if not cfg.AUTO_DOWNLOAD_XRAY:
        return False

    import zipfile

    url = (
        cfg.XRAY_CORE_URL_WINDOWS
        if os.name == "nt"
        else cfg.XRAY_CORE_URL_LINUX
    )
    member = "xray.exe" if os.name == "nt" else "xray"

    print("📥 Скачиваю ядро Xray...")

    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=300, context=SSL_CONTEXT) as resp:
                data = resp.read()
            break
        except Exception as e:
            if attempt == 2:
                print(f"⚠️ Не удалось скачать ядро Xray: {e}")
                return False
            print(f"   ↺ попытка {attempt + 2}/3...")

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            target = next(n for n in zf.namelist() if n.split("/")[-1] == member)
            with open(member, "wb") as f:
                f.write(zf.read(target))
        if os.name != "nt":
            os.chmod(member, 0o755)
        print(f"✅ Ядро Xray готово: {member} ({len(data) // 1024 // 1024} MB архив)")
        return True
    except Exception as e:
        print(f"⚠️ Не удалось распаковать ядро Xray: {e}")
        return False


def get_xray_executable():
    if os.name == "nt":
        candidates = [
            "./xray.exe",
            "xray.exe",
            "xray",
        ]
    else:
        candidates = [
            "./xray",
            "xray",
        ]

    for exe in candidates:

        if "/" in exe or "\\" in exe:

            if os.path.exists(exe):
                return exe

        else:
            return exe

    return (
        "xray.exe"
        if os.name == "nt"
        else "xray"
    )


def print_xray_version():

    exe = get_xray_executable()

    try:

        result = subprocess.run(
            [
                exe,
                "version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        version_text = (
            result.stdout.strip()
            or result.stderr.strip()
        )

        print(
            "🧩 Xray version:"
        )

        print(
            version_text[:1000]
        )

    except Exception as e:

        print(
            f"⚠️ Не удалось узнать "
            f"версию Xray: {e}"
        )


def get_xray_cmd() -> list:
    return [
        get_xray_executable(),
        "run",
        "-c",
        "stdin:",
    ]


# ============================================================
# HYSTERIA2 (официальное ядро, опционально)
# ============================================================

def get_hy2_executable() -> str:
    return cfg.HY2_CORE_FILE


def hy2_core_ready() -> bool:
    return os.path.exists(get_hy2_executable())


def download_hy2_core() -> bool:
    """Скачивает официальное ядро hysteria2, если его ещё нет."""
    exe = get_hy2_executable()
    if os.path.exists(exe):
        return True

    url = (
        cfg.HY2_CORE_URL_WINDOWS
        if os.name == "nt"
        else cfg.HY2_CORE_URL_LINUX
    )

    print("📥 Скачиваю ядро Hysteria2...")

    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=300, context=SSL_CONTEXT) as resp:
                data = resp.read()
            with open(exe, "wb") as f:
                f.write(data)
            break
        except Exception as e:
            if attempt == 2:
                print(f"⚠️ Не удалось скачать ядро Hysteria2: {e}")
                return False
            print(f"   ↺ попытка {attempt + 2}/3...")

    if os.name != "nt":
        os.chmod(exe, 0o755)
    print(f"✅ Ядро Hysteria2 скачано: {exe} ({len(data) // 1024 // 1024} MB)")
    return True


def _hy2_client_config_text(link: str, local_port: int) -> str:
    """hysteria2-ссылка → YAML-конфиг клиента официального ядра (без pyyaml)."""
    host, port, _ = parse_host_port_and_name(link)
    clean = link.split("#", 1)[0]
    params = {}
    if "?" in clean:
        params = urllib.parse.parse_qs(
            clean.split("?", 1)[1], keep_blank_values=True
        )

    def p(name, default=""):
        return str(params.get(name, [default])[0] or default)

    auth = ""
    rest = clean.split("://", 1)[1]
    if "@" in rest.split("?", 1)[0]:
        auth = urllib.parse.unquote(rest.split("?", 1)[0].rsplit("@", 1)[0])
    if not auth:
        auth = p("auth") or p("password")

    sni = p("sni") or p("peer") or host
    insecure = p("allowInsecure") or p("insecure")
    # server всегда в кавычках: "[2001:db8::1]:443" без кавычек YAML не парсится
    lines = [
        f"server: {_yaml_q(f'{host}:{port}')}",
        f"auth: {_yaml_q(auth)}",
        "tls:",
        f"  sni: {_yaml_q(sni)}",
        f"  insecure: {'true' if insecure.lower() in ('1', 'true') else 'false'}",
    ]

    # pinSHA256 — пин серверного сертификата (официальное поле TLS-секции)
    pin = p("pinSHA256")
    if pin:
        lines.append(f"  pinSHA256: {_yaml_q(pin)}")

    # ECH — Encrypted Client Hello: base64-конфиг с сервера
    # parse_qs декодирует '+' как пробел — в base64 возвращаем на место
    ech = p("ech").replace(" ", "+")
    if ech:
        lines.append(f"  ech: {_yaml_q(ech)}")

    lines += [
        "http:",
        f"  listen: 127.0.0.1:{local_port}",
    ]

    # obfs: тип берём из ссылки — salamander И gecko (это разные типы
    # в официальном ядре, gecko не превращаем в salamander)
    obfs = p("obfs").lower()
    obfs_pw = p("obfs-password") or p("obfsPassword")
    if obfs in ("salamander", "gecko") and obfs_pw:
        lines += [
            "obfs:",
            f"  type: {obfs}",
            f"  {obfs}:",
            f"    password: {_yaml_q(obfs_pw)}",
        ]
        pkt = p("obfs-packet-size") or p("packetSize")
        if obfs == "gecko" and pkt.isdigit() and 512 <= int(pkt) <= 2048:
            lines += [
                f"    minPacketSize: {pkt}",
                f"    maxPacketSize: {pkt}",
            ]

    up = p("up") or p("upmbps")
    down = p("down") or p("downmbps")
    if up or down:
        lines.append("bandwidth:")
        if up:
            lines.append(f"  up: {_yaml_q(up if ' ' in up else up + ' mbps')}")
        if down:
            lines.append(f"  down: {_yaml_q(down if ' ' in down else down + ' mbps')}")

    return "\n".join(lines) + "\n"


def _yaml_q(s: str) -> str:
    s = str(s).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def check_via_hysteria2(link: str, timeout: float = 8.0, min_success_count: int = 1):
    """
    Тест hy2 через официальное ядро (http-proxy listener).
    Возвращает (is_ok, cc, reason) — как check_via_xray_detailed.
    """
    if not hy2_core_ready() and not download_hy2_core():
        return False, None, "Ядро Hysteria2 недоступно", None

    port = get_free_port()
    conf_text = _hy2_client_config_text(link, port)

    fd, conf_path = tempfile.mkstemp(suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(conf_text)

        proc = None
        try:
            proc = subprocess.Popen(
                [get_hy2_executable(), "client", "-c", conf_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # ядро стартует дольше Xray (QUIC handshake)
            if not wait_for_port(port, timeout=5.0):
                return False, None, "Локальное ядро Hysteria2 не запустилось", None

            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({
                    "http": f"http://127.0.0.1:{port}",
                    "https": f"http://127.0.0.1:{port}",
                })
            )

            test_urls = [
                "https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
                "https://www.microsoft.com/connecttest.txt",
            ]
            success = 0
            for url_t in test_urls:
                try:
                    req = urllib.request.Request(url_t, headers=HEADERS)
                    with opener.open(req, timeout=timeout) as resp:
                        if resp.status in (200, 204):
                            success += 1
                except Exception:
                    pass

            if success < min_success_count:
                return False, None, f"Hysteria2: тест провален ({success}/3)", None

            cc, exit_ip = get_exit_country_via_proxy(opener, timeout)
            return True, cc, f"Hysteria2 OK ({success}/3)", exit_ip

        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
    finally:
        try:
            os.remove(conf_path)
        except Exception:
            pass


# ============================================================
# XRAY CHECK
# ============================================================

def get_free_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as s:

        s.bind(
            (
                "127.0.0.1",
                0,
            )
        )

        return s.getsockname()[1]


def wait_for_port(
    port: int,
    timeout: float = XRAY_START_TIMEOUT,
) -> bool:

    start = time.time()

    while (
        time.time() - start
        < timeout
    ):

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    port,
                ),
                timeout=0.05,
            ):
                return True

        except (
            OSError,
            ConnectionRefusedError,
        ):
            time.sleep(0.01)

    return False


def get_exit_country_via_proxy(
    opener,
    timeout,
):
    """Возвращает (country_code, exit_ip): ip-api отдаёт наш внешний IP в 'query'."""
    results = []
    exit_ip = None

    try:

        req = urllib.request.Request(
            "http://ip-api.com/json?fields=status,countryCode",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            if (
                data.get("status")
                == "success"
                and data.get(
                    "countryCode"
                )
            ):

                results.append(
                    (
                        "ip-api",
                        data[
                            "countryCode"
                        ].upper(),
                    )
                )
                # внешний IP соединения — для лимитов по выходу
                if data.get("query"):
                    exit_ip = str(data["query"])

    except Exception:
        pass

    try:

        req = urllib.request.Request(
            "https://api.ip2location.io/",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            if data.get(
                "country_code"
            ):

                results.append(
                    (
                        "ip2location",
                        data[
                            "country_code"
                        ].upper(),
                    )
                )

    except Exception:
        pass

    try:

        req = urllib.request.Request(
            "https://api.ip.sb/geoip",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            cc = (
                data.get(
                    "country_code"
                )
                or data.get(
                    "country"
                )
            )

            if cc:

                results.append(
                    (
                        "ip.sb",
                        cc.upper(),
                    )
                )

    except Exception:
        pass

    if not results:
        return None, None

    counts = {}

    for _, cc in results:

        counts[cc] = (
            counts.get(
                cc,
                0,
            )
            + 1
        )

    for cc, count in (
        counts.items()
    ):

        if count >= 2:
            return cc, exit_ip

    for name, cc in results:

        if name == "ip-api":
            return cc, exit_ip

    return results[0][1], exit_ip


def check_via_xray_detailed(
    outbound_obj: dict,
    timeout: float = XRAY_TEST_TIMEOUT,
    min_success_count: int = 2,
):

    port = get_free_port()

    config = {
        "log": {
            "loglevel": "none"
        },
        "inbounds": [
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {
                    "auth": "noauth"
                },
            }
        ],
        "outbounds": [
            outbound_obj
        ],
    }

    proc = None

    try:

        cmd = get_xray_cmd()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        payload = json.dumps(
            config,
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )

        proc.stdin.write(
            payload
        )

        proc.stdin.flush()
        proc.stdin.close()

        if not wait_for_port(
            port,
            XRAY_START_TIMEOUT,
        ):
            return (
                False,
                None,
                "Локальный Xray не запустился",
                None,
            )

        proxy_handler = (
            urllib.request.ProxyHandler(
                {
                    "http": (
                        "http://127.0.0.1:"
                        f"{port}"
                    ),
                    "https": (
                        "http://127.0.0.1:"
                        f"{port}"
                    ),
                }
            )
        )

        opener = (
            urllib.request.build_opener(
                proxy_handler
            )
        )

        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.microsoft.com/connecttest.txt",
        ]

        success_count = 0

        for url in test_urls:

            try:

                req = urllib.request.Request(
                    url,
                    headers=HEADERS,
                )

                with opener.open(
                    req,
                    timeout=timeout,
                ) as resp:

                    if resp.status in (
                        200,
                        204,
                    ):
                        success_count += 1

            except Exception:
                pass

        if (
            success_count
            >= min_success_count
        ):

            cc, exit_ip = (
                get_exit_country_via_proxy(
                    opener,
                    timeout,
                )
            )

            return (
                True,
                cc,
                f"OK ({success_count}/3)",
                exit_ip,
            )

        return (
            False,
            None,
            f"Тест провален "
            f"({success_count}/3)",
            None,
        )

    except Exception as e:

        return (
            False,
            None,
            f"Ошибка: "
            f"{type(e).__name__}: {e}",
            None,
        )

    finally:

        if proc:

            try:

                proc.terminate()
                proc.wait(
                    timeout=0.5
                )

            except Exception:

                try:
                    proc.kill()
                except Exception:
                    pass


def tcp_port_open(host: str, port: int, timeout: float = TCP_CHECK_TIMEOUT) -> bool:
    """Быстрая проверка, что host:port принимает TCP. Без этого Xray не гоняем."""
    if not host or not port:
        return False
    clean = host.strip('[] \t\r\n\'"')
    try:
        infos = socket.getaddrinfo(
            clean, int(port), type=socket.SOCK_STREAM
        )
    except Exception:
        return False

    for family, socktype, proto, _canon, sockaddr in infos:
        s = None
        try:
            s = socket.socket(family, socktype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            return True
        except Exception:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return False


def check_proxy_alive_detailed(
    link: str,
    min_success_count: int = 2,
):

    host, port, orig_name = (
        parse_host_port_and_name(
            link
        )
    )

    if not host or not port:
        return (
            False,
            None,
            "Некорректный формат "
            "хоста/порта",
            None,
            None,
        )

    if REMOVE_PRIVATE_INVALID and not is_valid_public_host(
        host
    ):
        return (
            False,
            None,
            "Некорректный формат "
            "хоста/порта",
            None,
            None,
        )

    if REMOVE_CF_WARP and is_cloudflare_or_warp(
        host
    ):
        return (
            False,
            None,
            "Отфильтрован "
            "(Cloudflare/WARP)",
            None,
            None,
        )

    is_hysteria2 = link.startswith(
        (
            "hysteria2://",
            "hy2://",
        )
    )

    # TCP pre-check только для TCP-протоколов.
    # Hysteria2 работает поверх UDP/QUIC — TCP-проверка бессмысленна.
    if not is_hysteria2:
        if not tcp_port_open(host, port):
            return (
                False,
                None,
                "TCP: порт закрыт/недоступен",
                None,
                None,
            )

    outbound = (
        link_to_xray_outbound(
            link
        )
    )

    if not outbound:
        return (
            False,
            None,
            "Ошибка генерации "
            "JSON для Xray",
            None,
            None,
        )

    # Hysteria2: если включено официальное ядро — тестируем им,
    # Xray остаётся fallback'ом (часть hy2-серверов Xray не берёт).
    if is_hysteria2 and cfg.HYSTERIA2_CORE:
        hy_ok, hy_cc, hy_reason, hy_ip = check_via_hysteria2(
            link,
            timeout=XRAY_TEST_TIMEOUT + 2,
            min_success_count=min_success_count,
        )
        if not hy_ok:
            hy_ok, hy_cc, hy_reason, hy_ip = check_via_xray_detailed(
                outbound,
                timeout=XRAY_TEST_TIMEOUT,
                min_success_count=min_success_count,
            )
        if hy_ok:
            final_flag = (
                cc_to_flag(hy_cc)
                if hy_cc
                else extract_clean_flag(orig_name)
            )
            return (True, (link, final_flag), hy_reason, hy_cc, hy_ip)
        return (False, None, hy_reason, None, None)

    is_ok, cc, reason, exit_ip = (
        check_via_xray_detailed(
            outbound,
            timeout=XRAY_TEST_TIMEOUT,
            min_success_count=min_success_count,
        )
    )

    if is_ok:

        final_flag = (
            cc_to_flag(cc)
            if cc
            else extract_clean_flag(
                orig_name
            )
        )

        return (
            True,
            (
                link,
                final_flag,
            ),
            reason,
            cc,
            exit_ip,
        )

    return (
        False,
        None,
        reason,
        None,
        None,
    )




# ============================================================
# OUTBOUND -> LINK
# ============================================================

def xray_outbound_to_link(ob: dict) -> str:
    """Xray outbound JSON → share-ссылка (vless/vmess/trojan/ss)."""
    if not isinstance(ob, dict):
        return ""
    proto = str(ob.get("protocol") or "").lower()
    if proto in ("freedom", "blackhole", "dns", "block", "direct"):
        return ""

    tag = str(ob.get("tag") or ob.get("remarks") or "xray")
    settings = ob.get("settings") or {}
    stream = ob.get("streamSettings") or {}
    # Актуальный ключ — method; network оставлен как fallback для старых JSON
    network = str(
        stream.get("method") or stream.get("network") or "tcp"
    ).lower()
    security = str(stream.get("security") or "").lower()

    try:
        if proto == "vless":
            vnext = (settings.get("vnext") or [{}])[0]
            user = (vnext.get("users") or [{}])[0]
            address = vnext.get("address") or ""
            port = int(vnext.get("port") or 0)
            uuid = user.get("id") or ""
            if not address or not port or not uuid:
                return ""
            params = {
                "encryption": user.get("encryption") or "none",
                "type": network,
            }
            flow = user.get("flow") or ""
            if flow:
                params["flow"] = flow
            if security:
                params["security"] = security
            if security == "reality":
                rs = stream.get("realitySettings") or {}
                # Актуальный Xray хранит public key в "password",
                # старые/чужие JSON — в "publicKey". Читаем оба.
                pbk = rs.get("publicKey") or rs.get("password")
                if pbk:
                    params["pbk"] = pbk
                if rs.get("serverName"):
                    params["sni"] = rs["serverName"]
                if rs.get("fingerprint"):
                    params["fp"] = rs["fingerprint"]
                if rs.get("shortId"):
                    params["sid"] = rs["shortId"]
                if rs.get("spiderX"):
                    params["spx"] = rs["spiderX"]
            elif security in ("tls", "xtls"):
                ts = stream.get("tlsSettings") or {}
                sni = (ts.get("serverName") or "")
                if sni:
                    params["sni"] = sni
                fp = ((ts.get("fingerprint") if isinstance(ts, dict) else None)
                      or (stream.get("tlsSettings") or {}).get("fingerprint"))
                if fp:
                    params["fp"] = fp
            if network == "ws":
                ws = stream.get("wsSettings") or {}
                if ws.get("path"):
                    params["path"] = ws["path"]
                host = (ws.get("headers") or {}).get("Host") or (ws.get("headers") or {}).get("host")
                if host:
                    params["host"] = host
            elif network == "grpc":
                gs = stream.get("grpcSettings") or {}
                if gs.get("serviceName"):
                    params["serviceName"] = gs["serviceName"]
                mode = gs.get("multiMode")
                if mode is True or str(gs.get("mode") or "").lower() in ("multi", "true"):
                    params["mode"] = "multi"
                elif gs.get("mode"):
                    params["mode"] = str(gs["mode"])
            elif network in ("xhttp", "splithttp"):
                xs = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
                if xs.get("path"):
                    params["path"] = xs["path"]
                if xs.get("host"):
                    params["host"] = xs["host"]
                if xs.get("mode"):
                    params["mode"] = xs["mode"]
            q = urllib.parse.urlencode(params, doseq=True)
            return f"vless://{uuid}@{address}:{port}?{q}#{urllib.parse.quote(tag)}"

        if proto == "trojan":
            servers = (settings.get("servers") or [{}])[0]
            address = servers.get("address") or ""
            port = int(servers.get("port") or 0)
            password = servers.get("password") or ""
            if not address or not port or not password:
                return ""
            params = {"type": network}
            if security:
                params["security"] = security or "tls"
            ts = stream.get("tlsSettings") or stream.get("realitySettings") or {}
            if ts.get("serverName"):
                params["sni"] = ts["serverName"]
            if network == "ws":
                ws = stream.get("wsSettings") or {}
                if ws.get("path"):
                    params["path"] = ws["path"]
            q = urllib.parse.urlencode(params)
            return f"trojan://{urllib.parse.quote(password)}@{address}:{port}?{q}#{urllib.parse.quote(tag)}"

        if proto in ("shadowsocks", "ss"):
            servers = (settings.get("servers") or [{}])[0]
            address = servers.get("address") or ""
            port = int(servers.get("port") or 0)
            password = servers.get("password") or ""
            method = servers.get("method") or "aes-128-gcm"
            if not address or not port or not password:
                return ""
            userinfo = safe_b64encode(f"{method}:{password}").rstrip("=")
            return f"ss://{userinfo}@{address}:{port}#{urllib.parse.quote(tag)}"

        if proto == "vmess":
            vnext = (settings.get("vnext") or [{}])[0]
            user = (vnext.get("users") or [{}])[0]
            address = vnext.get("address") or ""
            port = int(vnext.get("port") or 0)
            uuid = user.get("id") or ""
            if not address or not port or not uuid:
                return ""
            obj = {
                "v": "2",
                "ps": tag,
                "add": address,
                "port": port,
                "id": uuid,
                "aid": user.get("alterId") or 0,
                "scy": user.get("security") or "auto",
                "net": network,
                "type": "none",
                "tls": security if security in ("tls", "reality") else "",
            }
            if network == "ws":
                ws = stream.get("wsSettings") or {}
                obj["path"] = ws.get("path") or "/"
                obj["host"] = (ws.get("headers") or {}).get("Host") or ""
            return "vmess://" + safe_b64encode(
                json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            )

        # Hysteria2: Xray protocol == "hysteria"
        # (старые/чужие JSON могли писать hysteria2/hy2 — тоже принимаем)
        if proto in ("hysteria", "hysteria2", "hy2"):
            # Наша структура: settings.address / settings.port
            # Чужие/старые: settings.servers[0]
            address = settings.get("address") or ""
            port = settings.get("port") or 0
            if not address or not port:
                servers = (settings.get("servers") or [{}])[0]
                address = servers.get("address") or address
                port = servers.get("port") or port

            try:
                port = int(port)
            except (TypeError, ValueError):
                return ""

            if not address or not port:
                return ""

            # auth: hysteriaSettings.auth (наш формат)
            # fallback: servers[0].password / settings.password
            hy = stream.get("hysteriaSettings") or {}
            password = (
                hy.get("auth")
                or settings.get("password")
                or ((settings.get("servers") or [{}])[0].get("password") if settings.get("servers") else "")
                or ""
            )

            params: Dict[str, str] = {}

            # TLS
            ts = stream.get("tlsSettings") or {}
            sni = ts.get("serverName") or ""
            if sni:
                params["sni"] = str(sni)
            if ts.get("allowInsecure"):
                params["insecure"] = "1"
            alpn = ts.get("alpn")
            if isinstance(alpn, list) and alpn:
                params["alpn"] = ",".join(str(x) for x in alpn)
            elif isinstance(alpn, str) and alpn:
                params["alpn"] = alpn
            fp = ts.get("fingerprint") or ""
            if fp:
                params["fp"] = str(fp)
            pin = ts.get("pinnedPeerCertSha256") or ""
            if pin:
                params["pinSHA256"] = str(pin)

            # Bandwidth: quicParams.brutal* предпочтительнее, иначе hy.up/down
            fm = stream.get("finalmask") or {}
            qp = fm.get("quicParams") or {}
            up = qp.get("brutalUp") or hy.get("up") or ""
            down = qp.get("brutalDown") or hy.get("down") or ""
            if up:
                params["up"] = str(up)
            if down:
                params["down"] = str(down)

            # Port hopping
            udp_hop = qp.get("udpHop") or {}
            hop_ports = udp_hop.get("ports") or ""
            port_in_uri = str(port)
            if hop_ports:
                port_in_uri = str(hop_ports)

            # Salamander / Gecko
            for mask in (fm.get("udp") or []):
                if not isinstance(mask, dict):
                    continue
                if str(mask.get("type") or "").lower() == "salamander":
                    ms = mask.get("settings") or {}
                    pw = ms.get("password") or ""
                    if pw:
                        params["obfs"] = "salamander"
                        params["obfs-password"] = str(pw)
                    if ms.get("packetSize"):
                        params["obfs"] = "gecko"
                        params["obfs-packet-size"] = str(ms["packetSize"])
                    break

            q = urllib.parse.urlencode(params)
            auth = urllib.parse.quote(str(password), safe="") if password else ""
            return (
                f"hysteria2://{auth}@{address}:{port_in_uri}"
                + (f"?{q}" if q else "")
                + f"#{urllib.parse.quote(tag)}"
            )
    except Exception:
        return ""
    return ""

