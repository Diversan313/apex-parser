"""GeoIP (MaxMind offline + online), DNS cache, Cloudflare/WARP check."""
from __future__ import annotations

import os
import socket
import json
import ipaddress
import urllib.request
from typing import Optional

from . import config
from .config import (
    MMDB_PATH,
    MMDB_URL,
    HEADERS,
    SSL_CONTEXT,
    DNS_CACHE,
    DNS_LOCK,
    GEO_ONLINE_CACHE,
    GEO_LOCK,
    CF_NETWORKS,
    TCP_CHECK_TIMEOUT,
    DOMAIN_REGEX,
)

def download_geoip_db():
    if os.path.exists(MMDB_PATH):
        return

    print("📥 Скачиваю оффлайн базу GeoIP...")

    try:
        req = urllib.request.Request(
            MMDB_URL,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=30,
            context=SSL_CONTEXT,
        ) as response:
            data = response.read()

        with open(MMDB_PATH, "wb") as f:
            f.write(data)

        print("✅ База GeoIP успешно загружена!")

    except Exception as e:
        print(f"⚠️ Ошибка загрузки базы GeoIP: {e}")


def init_geoip():
    download_geoip_db()

    if config.maxminddb and os.path.exists(MMDB_PATH):
        try:
            config.GEO_READER = config.maxminddb.open_database(MMDB_PATH)
        except Exception:
            config.GEO_READER = None



def is_valid_public_host(host: str) -> bool:
    if not host:
        return False

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if (
        not clean_host
        or clean_host.isdigit()
    ):
        return False

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return False

        return True

    except ValueError:
        pass

    if (
        "." not in clean_host
        or clean_host.startswith(".")
        or clean_host.endswith(".")
    ):
        return False

    if not DOMAIN_REGEX.match(
        clean_host
    ):
        return False

    if clean_host.endswith(
        (
            ".local",
            ".localhost",
            ".internal",
            ".lan",
            ".home",
            ".arpa",
            ".invalid",
            ".test",
        )
    ):
        return False

    return True


# ============================================================
# DNS
# ============================================================

def resolve_host_cached(clean_host: str):
    clean_host = clean_host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not is_valid_public_host(
        clean_host
    ):
        return None

    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[
                clean_host
            ]

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if ip_obj.is_global:

            with DNS_LOCK:
                DNS_CACHE[
                    clean_host
                ] = clean_host

            return clean_host

    except ValueError:
        pass

    try:
        socket.setdefaulttimeout(
            2.0
        )

        ip = socket.gethostbyname(
            clean_host
        )

        ip_obj = ipaddress.ip_address(
            ip
        )

        resolved_ip = (
            ip
            if ip_obj.is_global
            else None
        )

    except Exception:
        resolved_ip = None

    with DNS_LOCK:
        DNS_CACHE[
            clean_host
        ] = resolved_ip

    return resolved_ip


# ============================================================
# GEO
# ============================================================

def fetch_country_from_ip(
    ip_str: str,
):
    if not ip_str:
        return None

    if not is_valid_public_host(
        ip_str
    ):
        return None

    if config.GEO_READER:

        try:
            record = config.GEO_READER.get(
                ip_str
            )

            if (
                record
                and "country" in record
                and "iso_code"
                in record["country"]
            ):
                return (
                    record["country"]
                    ["iso_code"]
                )

        except Exception:
            pass

    with GEO_LOCK:

        if ip_str in GEO_ONLINE_CACHE:
            return GEO_ONLINE_CACHE[
                ip_str
            ]

    try:
        url = (
            "http://ip-api.com/json/"
            + ip_str
            + "?fields=status,countryCode"
        )

        req = urllib.request.Request(
            url,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=2.0,
            context=SSL_CONTEXT,
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

            cc = data[
                "countryCode"
            ].upper()

            with GEO_LOCK:
                GEO_ONLINE_CACHE[
                    ip_str
                ] = cc

            return cc

    except Exception:
        pass

    return None


# ============================================================
# CLOUDFLARE
# ============================================================

def is_cloudflare_or_warp(
    host: str,
) -> bool:

    try:

        clean_host = host.strip(
            '[] \t\r\n\'"'
        ).lower()

        if not is_valid_public_host(
            clean_host
        ):
            return True

        if any(
            bad in clean_host
            for bad in (
                "localhost",
                "127.0.0.1",
                ".ir",
                ".cn",
                ".cf",
                ".ga",
                ".gq",
                ".ml",
                ".tk",
            )
        ):
            return True

        ip_str = resolve_host_cached(
            clean_host
        )

        if not ip_str:
            return True

        ip_obj = ipaddress.ip_address(
            ip_str
        )

        if not ip_obj.is_global:
            return True

        if ip_obj.version == 4:

            for network in CF_NETWORKS:

                if ip_obj in network:
                    return True

        elif ip_obj.version == 6:

            if str(
                ip_obj
            ).startswith(
                (
                    "2400:cb00:",
                    "2606:4700:",
                    "2803:f800:",
                    "2405:b500:",
                    "2405:8100:",
                    "2a06:98c0:",
                    "2c0f:f248:",
                )
            ):
                return True

    except Exception:
        return True

    return False


