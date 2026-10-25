"""GeoIP (MaxMind offline + online), DNS cache, Cloudflare/WARP check."""
from __future__ import annotations

import os
import socket
import json
import time
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


    except Exception as e:
        print(f"warn: geoip база: {e}")


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

    # getaddrinfo, а не gethostbyname: bounded-патч из netlimit
    # ограничивает только getaddrinfo — gethostbyname висел дольше
    # DNS_RESOLVE_TIMEOUT и тянул стадии без нашего контроля
    try:
        infos = socket.getaddrinfo(clean_host, None)
    except Exception:
        resolved_ip = None
    else:
        resolved_ip = None
        # IPv4 в приоритете: белые базы и CF-подсети в основном IPv4
        infos.sort(key=lambda t: 0 if t[0] == socket.AF_INET else 1)
        for info in infos:
            try:
                ip_obj = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if ip_obj.is_global:
                resolved_ip = info[4][0]
                break

    with DNS_LOCK:
        DNS_CACHE[
            clean_host
        ] = resolved_ip

    return resolved_ip


def resolve_hosts_bulk(
    hosts,
    workers: int = None,
    deadline_s: float = None,
) -> int:
    """
    Параллельный прогрев DNS-кэша для списка хостов.

    Резолв собран в одну волну с жёстким потолком: классификация и
    CF-фильтр дальше берут адреса только из кэша и не ходят в сеть из
    последовательных циклов по всем кандидатам. Мёртвые домены не должны
    растягивать прогон — после deadline_s неотправленные хосты
    пропускаются (у них просто не будет DNS-уровня матчинга).
    Возвращает число успешно резолвнутых хостов.
    """
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

    uniq = [h for h in dict.fromkeys(hosts) if h]
    if not uniq:
        return 0

    workers = workers or config.DNS_BULK_WORKERS
    budget = deadline_s if deadline_s is not None else config.DNS_BULK_DEADLINE
    deadline = time.monotonic() + budget

    resolved = 0
    submitted = 0
    dns_t0 = time.monotonic()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = set()
        it = iter(uniq)

        # скользящее окно: очередь в pool держим короткой, чтобы дедлайн
        # обрезал только неотправленный хвост
        for _ in range(workers * 2):
            h = next(it, None)
            if h is None:
                break
            pending.add(pool.submit(resolve_host_cached, h))
            submitted += 1

        while pending and time.monotonic() < deadline:
            done_futs, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
            for fut in done_futs:
                try:
                    if fut.result():
                        resolved += 1
                except Exception:
                    pass
                h = next(it, None)
                if h is not None:
                    pending.add(pool.submit(resolve_host_cached, h))
                    submitted += 1

    # хвост pending короткий: каждый резолв ограничен DNS_RESOLVE_TIMEOUT,
    # exit из пула ждёт его сам
    skipped = len(uniq) - submitted
    if skipped > 0:
        print(f"warn: dns: {skipped} хостов пропущены по дедлайну {int(budget)}с")
    print(
        f"dns: {resolved}/{len(uniq)} хостов "
        f"за {int(time.monotonic() - dns_t0)}с"
    )
    return resolved


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


def is_cf_ip(ip_str: str) -> bool:
    """IP принадлежит подсетям Cloudflare/WARP? (без DNS, только по CIDR)"""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    if ip_obj.version == 4:
        return any(ip_obj in n for n in config.CF_NETWORKS)
    return any(ip_obj in n for n in config.CF_IPV6_NETWORKS)


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

            for network in config.CF_IPV6_NETWORKS:

                if ip_obj in network:
                    return True

    except Exception:
        return True

    return False


