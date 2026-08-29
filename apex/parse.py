"""Парсинг хостов, портов, SNI, имён из конфиг-ссылок."""
from __future__ import annotations

import re
import socket
import urllib.parse
import base64
import json
import ipaddress
from typing import Optional, Tuple, List, Set, Any

from .config import DOMAIN_REGEX, SUPPORTED_PROTOCOLS
from .geoip import is_valid_public_host, resolve_host_cached
from .utils import safe_b64decode

def parse_host_port(
    server_part: str,
):
    if not server_part:
        return None, None

    server_part = server_part.rstrip(
        "/"
    )

    try:

        if server_part.startswith(
            "["
        ):

            if "]" not in server_part:
                return None, None

            host_b, rest = (
                server_part.split(
                    "]",
                    1,
                )
            )

            host = host_b + "]"

            port_str = (
                rest
                .lstrip(":")
                .split("/")[0]
                .split("?")[0]
                .split(",")[0]
            )
            # range "5000-6000" → 5000
            if "-" in port_str:
                port_str = port_str.split("-", 1)[0]

            return (
                host,
                int(port_str),
            )

        if ":" in server_part:

            host, port_str = (
                server_part.rsplit(
                    ":",
                    1,
                )
            )

            port_str = (
                port_str
                .split("/")[0]
                .split("?")[0]
                .split(",")[0]
            )
            # Port hopping / range: "443,5000-6000" or "5000-6000"
            if "-" in port_str:
                port_str = port_str.split("-", 1)[0]

            return (
                host,
                int(port_str),
            )

    except Exception:
        pass

    return None, None


# ============================================================
# PARSE LINK
# ============================================================

def parse_host_port_and_name(
    link: str,
):
    try:

        orig_name = ""

        if "#" in link:

            orig_name = (
                urllib.parse.unquote(
                    link.split(
                        "#",
                        1,
                    )[1]
                )
            )

        clean_link = link.split(
            "#",
            1,
        )[0]

        if clean_link.startswith(
            (
                "vless://",
                "trojan://",
                "ss://",
                "hysteria2://",
                "hy2://",
            )
        ):

            protocol, rest = (
                clean_link.split(
                    "://",
                    1,
                )
            )

            rest = rest.split(
                "?",
                1,
            )[0]

            if protocol == "ss":

                if "@" not in rest:

                    try:
                        decoded = safe_b64decode(
                            rest
                        )

                        if "@" in decoded:

                            _, host_port = (
                                decoded.rsplit(
                                    "@",
                                    1,
                                )
                            )

                            host, port = (
                                parse_host_port(
                                    host_port
                                )
                            )

                            return (
                                host,
                                port,
                                orig_name,
                            )

                    except Exception:
                        pass

                else:

                    _, host_port = (
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

                    return (
                        host,
                        port,
                        orig_name,
                    )

            else:

                if "@" in rest:
                    rest = (
                        rest.rsplit(
                            "@",
                            1,
                        )[1]
                    )

                host, port = (
                    parse_host_port(
                        rest
                    )
                )

                return (
                    host,
                    port,
                    orig_name,
                )

        elif clean_link.startswith(
            "vmess://"
        ):

            b64_data = (
                clean_link
                .replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            return (
                data.get(
                    "add"
                ),
                int(
                    data.get(
                        "port"
                    )
                ),
                data.get(
                    "ps",
                    "",
                ),
            )

    except Exception:
        pass

    return None, None, ""


# ============================================================
# SNI
# ============================================================

def extract_sni_from_link(
    link: str,
) -> str:

    try:

        if "?" in link:

            query_part = (
                link.split(
                    "?",
                    1,
                )[1]
                .split(
                    "#",
                    1,
                )[0]
            )

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            sni = (
                params.get(
                    "sni",
                    [""],
                )[0]
                or params.get(
                    "host",
                    [""],
                )[0]
            )

            if sni:
                return (
                    urllib.parse.unquote(
                        sni
                    )
                    .lower()
                    .strip()
                )

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

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            return (
                data.get(
                    "sni"
                )
                or data.get(
                    "host"
                )
                or ""
            ).lower().strip()

    except Exception:
        pass

    return ""


# ============================================================
# ALL HOSTS / IPS
# ============================================================

def extract_all_hosts_and_ips_from_link(
    link: str,
) -> list:

    hosts = set()

    main_host, _, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if main_host:

        hosts.add(
            main_host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    sni = extract_sni_from_link(
        link
    )

    if sni:

        hosts.add(
            sni.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    if "?" in link:

        try:

            query_part = (
                link.split(
                    "?",
                    1,
                )[1]
                .split(
                    "#",
                    1,
                )[0]
            )

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            h_param = params.get(
                "host",
                [""],
            )[0]

            if h_param:

                hosts.add(
                    urllib.parse.unquote(
                        h_param
                    )
                    .strip(
                        '[] \t\r\n\'"'
                    )
                    .lower()
                )

        except Exception:
            pass

    ip_matches = re.findall(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        link,
    )

    for ip_cand in ip_matches:

        try:

            ip_obj = ipaddress.ip_address(
                ip_cand
            )

            if ip_obj.is_global:
                hosts.add(
                    ip_cand
                )

        except ValueError:
            pass

    return list(hosts)


# ============================================================
# WHITE IP
# ============================================================

def parse_ip_or_resolve(
    item: str,
) -> set:

    if not item:
        return set()

    item = item.strip()

    if (
        not item
        or item.startswith("#")
    ):
        return set()

    if "://" in item:

        try:

            parsed = urllib.parse.urlparse(
                item
            )

            item = (
                parsed.netloc
                or item.split(
                    "://",
                    1,
                )[1]
            )

        except Exception:
            pass

    item = (
        item.split("/")[0]
        .split("?")[0]
        .split("#")[0]
        .strip()
    )

    host, _ = parse_host_port(
        item
    )

    if not host:
        host = item

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not is_valid_public_host(
        clean_host
    ):
        return set()

    try:

        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if ip_obj.is_global:
            return {
                str(ip_obj)
            }

    except ValueError:
        pass

    resolved_ip = (
        resolve_host_cached(
            clean_host
        )
    )

    if resolved_ip:
        try:

            ip_obj = ipaddress.ip_address(
                resolved_ip
            )

            if ip_obj.is_global:
                return {
                    resolved_ip
                }

        except ValueError:
            pass

    return set()


def find_matched_ip_for_link(
    link: str,
    white_ips: set,
):

    if not white_ips:
        return None

    hosts = (
        extract_all_hosts_and_ips_from_link(
            link
        )
    )

    for host in hosts:

        if not host:
            continue

        clean_host = host.strip(
            '[] \t\r\n\'"'
        ).lower()

        if not is_valid_public_host(
            clean_host
        ):
            continue

        if clean_host in white_ips:
            return clean_host

        resolved_ip = (
            resolve_host_cached(
                clean_host
            )
        )

        if (
            resolved_ip
            and resolved_ip in white_ips
        ):
            return resolved_ip

    return None
