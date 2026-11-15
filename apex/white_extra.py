"""Расширенные белые источники входа: twl-снапшот и ASN-порог.

Два доказательства белого входа поверх white_ip.txt:
- twl_white.json — IP, измеренные сканом мобильного интернета в режиме
  БС (снапшот архивного репозитория, обновлений больше нет);
- доверенный ASN — владелец сети, у которого в белых базах (наша +
  twl) не меньше K подсетей: хостеры ставят сервера в белые диапазоны
  операторов и их CDN, поэтому белый у части адресов владельца почти
  всегда означает белое у остальных.
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.request

from . import config as cfg

_TWL_IPS = set()       # int-адреса измеренных белых IP
_TWL_NETS = []         # CIDR-записи twl — для подсчёта подсетей владельца
_ASN_READER = None
_TRUSTED_ASN = set()


def _download(url: str, path: str, attempts: int = 3) -> bool:
    last = None
    for _ in range(attempts):
        try:
            req = urllib.request.Request(url, headers=cfg.HEADERS)
            with urllib.request.urlopen(
                req, timeout=120, context=cfg.SSL_CONTEXT
            ) as resp:
                data = resp.read()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            return True
        except Exception as e:
            last = e
    print(f"warn: {os.path.basename(path)} не скачан: {last}, источник пропущен")
    return False


def _load_twl() -> None:
    if not cfg.TWL_WHITE_ENABLED:
        return
    if not os.path.exists(cfg.TWL_WHITE_FILE) and not _download(
        cfg.TWL_WHITE_URL, cfg.TWL_WHITE_FILE
    ):
        return
    try:
        with open(cfg.TWL_WHITE_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f)
        for entry in entries:
            cidr = str(entry.get("cidr") or "").strip()
            if cidr:
                try:
                    _TWL_NETS.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
            for ip in entry.get("ips", []):
                try:
                    _TWL_IPS.add(int(ipaddress.ip_address(ip)))
                except ValueError:
                    pass
        print(f"twl_white: {len(_TWL_IPS)} измеренных IP")
    except Exception as e:
        print(f"warn: twl_white чтение: {e}, источник пропущен")


def _count_trusted(reader, nets: list, threshold: int) -> set:
    """ASN владельцев с >= threshold подсетями среди переданных net-записей."""
    counts: dict = {}
    for net in nets:
        try:
            rec = reader.get(str(net.network_address))
        except Exception:
            continue
        asn = rec.get("autonomous_system_number") if rec else None
        if asn:
            counts[asn] = counts.get(asn, 0) + 1
    return {a for a, c in counts.items() if c >= threshold}


def _init_asn() -> None:
    """Доверие к ASN строится ТОЛЬКО по измеренному twl-списку.

    Заявочные CIDR нашей базы шумные (в них попали AWS, DoD, зарубежные
    блоки): по ним порог доверял мусорным владельцам — их сервера живы
    с раннера, но операторы эти адреса не пропускают. Измеренные подсети
    twl — прямое доказательство пропуска; нашей базе остаётся роль прямого
    evidence (host_in_white_ips), обобщать с неё нельзя.
    """
    global _ASN_READER, _TRUSTED_ASN
    if not cfg.ASN_WHITE_ENABLED:
        return
    try:
        import maxminddb
    except ImportError:
        print("warn: maxminddb не установлен, ASN-слой пропущен")
        return
    if not os.path.exists(cfg.MMDB_ASN_PATH) and not _download(
        cfg.MMDB_ASN_URL, cfg.MMDB_ASN_PATH
    ):
        return
    try:
        _ASN_READER = maxminddb.open_database(cfg.MMDB_ASN_PATH)
    except Exception as e:
        print(f"warn: ASN-база не открылась: {e}")
        return

    threshold = int(cfg.ASN_WHITE_MIN_SUBNETS)
    _TRUSTED_ASN = _count_trusted(_ASN_READER, _TWL_NETS, threshold)
    print(
        f"asn_white: {len(_TRUSTED_ASN)} доверенных ASN (порог {threshold} CIDR в twl)"
    )


def init_white_extra(white_networks: list) -> None:
    """Загрузка расширенных источников; white_networks — CIDR-строки white_ip.txt."""
    _load_twl()
    _init_asn()


def ip_in_twl(ip_str: str) -> bool:
    """IP в измеренном twl-списке?"""
    try:
        return int(ipaddress.ip_address(str(ip_str).strip())) in _TWL_IPS
    except ValueError:
        return False


def is_asn_white(ip_str: str) -> bool:
    """IP принадлежит доверенному ASN?"""
    if _ASN_READER is None or not _TRUSTED_ASN:
        return False
    try:
        rec = _ASN_READER.get(
            str(ipaddress.ip_address(str(ip_str).strip()))
        )
    except Exception:
        return False
    asn = rec.get("autonomous_system_number") if rec else None
    return bool(asn) and asn in _TRUSTED_ASN
