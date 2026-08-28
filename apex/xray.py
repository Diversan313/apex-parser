"""Xray: конвертация ссылок в outbound, проверка живости (часть 1)."""
from __future__ import annotations

import json
import base64
import urllib.parse
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

from .config import (
    XRAY_START_TIMEOUT,
    XRAY_TEST_TIMEOUT,
    TCP_CHECK_TIMEOUT,
    WL_MIN_SUCCESS_COUNT,
    BL_MIN_SUCCESS_COUNT,
    SUPPORTED_PROTOCOLS,
    HEADERS,
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

        # В этой проверке Hysteria2 по-прежнему
        # не запускаем через Xray HTTP-inbound.
        if protocol in (
            "hysteria2",
            "hy2",
        ):
            return None

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
    results = []

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
        return None

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
            return cc

    for name, cc in results:

        if name == "ip-api":
            return cc

    return results[0][1]


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

            cc = (
                get_exit_country_via_proxy(
                    opener,
                    timeout,
                )
            )

            return (
                True,
                cc,
                f"OK ({success_count}/3)",
            )

        return (
            False,
            None,
            f"Тест провален "
            f"({success_count}/3)",
        )

    except Exception as e:

        return (
            False,
            None,
            f"Ошибка: "
            f"{type(e).__name__}: {e}",
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

    if (
        not host
        or not port
        or not is_valid_public_host(
            host
        )
    ):
        return (
            False,
            None,
            "Некорректный формат "
            "хоста/порта",
            None,
        )

    if is_cloudflare_or_warp(
        host
    ):
        return (
            False,
            None,
            "Отфильтрован "
            "(Cloudflare/WARP)",
            None,
        )

    # TCP pre-check: полностью мёртвые host:port не гоняем через Xray
    if not tcp_port_open(host, port):
        return (
            False,
            None,
            "TCP: порт закрыт/недоступен",
            None,
        )

    if link.startswith(
        (
            "hysteria2://",
            "hy2://",
        )
    ):
        return (
            False,
            None,
            "Hysteria2 не поддерживается "
            "этим Xray-check",
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
        )

    is_ok, cc, reason = (
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
        )

    return (
        False,
        None,
        reason,
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
    network = str(stream.get("network") or "tcp").lower()
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
                if rs.get("publicKey"):
                    params["pbk"] = rs["publicKey"]
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

        if proto in ("hysteria2", "hy2"):
            servers = (settings.get("servers") or [{}])[0]
            address = servers.get("address") or ""
            port = int(servers.get("port") or 0)
            password = servers.get("password") or ""
            if not address or not port:
                return ""
            params = {}
            ts = stream.get("tlsSettings") or {}
            if ts.get("serverName"):
                params["sni"] = ts["serverName"]
            if ts.get("allowInsecure"):
                params["insecure"] = "1"
            q = urllib.parse.urlencode(params)
            auth = urllib.parse.quote(password) if password else ""
            return (
                f"hysteria2://{auth}@{address}:{port}"
                + (f"?{q}" if q else "")
                + f"#{urllib.parse.quote(tag)}"
            )
    except Exception:
        return ""
    return ""

