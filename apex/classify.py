"""Классификация конфигов: WL / BL по keywords, SNI, RU. AI / Torrent."""
from __future__ import annotations

import re
import random
import urllib.parse
from typing import Tuple

from .config import (
    WL_KEYWORDS_REGEX,
    BL_KEYWORDS_REGEX,
    AI_KEYWORDS_REGEX,
    TORRENT_KEYWORDS_REGEX,
    TORRENT_NEGATIVE_REGEX,
    RU_SNI_RATIO,
)
from .sni_whitelist import link_has_whitelisted_sni, is_sni_in_mobile_whitelist
from .parse import (
    extract_sni_from_link,
    parse_host_port_and_name,
    find_matched_ip_for_link,
)
from .geoip import (
    resolve_host_cached,
    fetch_country_from_ip,
    is_valid_public_host,
)

def _prepare_text(link: str, orig_name: str = "") -> str:
    full_text = f"{link} {orig_name}"
    try:
        full_text = urllib.parse.unquote(full_text)
    except Exception:
        pass
    return full_text


def is_wl_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:
    return bool(WL_KEYWORDS_REGEX.search(_prepare_text(link, orig_name)))


def is_bl_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:
    return bool(BL_KEYWORDS_REGEX.search(_prepare_text(link, orig_name)))


def is_ai_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:
    return bool(AI_KEYWORDS_REGEX.search(_prepare_text(link, orig_name)))


def is_torrent_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:
    """
    Положительное совпадение по torrent-ключевым словам,
    но если рядом есть негатив (NOT / НЕ / НЕ ДЛЯ и т.п.) — False.
    """
    text = _prepare_text(link, orig_name)
    if not TORRENT_KEYWORDS_REGEX.search(text):
        return False
    if TORRENT_NEGATIVE_REGEX.search(text):
        return False
    return True


def is_ru_sni(link: str) -> bool:
    """
    Только суффикс .ru / .su.
    Точные домены БС — через arch/lists/whitelist.txt,
    не через хардкод.
    """
    sni = extract_sni_from_link(link)
    if sni and sni.endswith((".ru", ".su")):
        return True

    link_low = link.lower()
    if re.search(
        r"sni=[^&]*\.(ru|su)(?:&|$)",
        link_low,
    ):
        return True

    return False


def classify_config(
    link: str,
    white_ips: set,
    ru_sni_ratio: float = RU_SNI_RATIO,
) -> str:

    # 1. IP из white_ip.txt
    if find_matched_ip_for_link(link, white_ips):
        return "WL"

    host, _, orig_name = parse_host_port_and_name(link)

    if not host or not is_valid_public_host(host):
        return "BL"

    # 2. Ключевые слова ЧС / Blacklist → принудительно BL
    if is_bl_by_keywords(link, orig_name):
        return "BL"

    # 3. Ключевые слова БС / Белый → WL
    if is_wl_by_keywords(link, orig_name):
        return "WL"

    # 3. SNI из официального mobile whitelist
    #    (arch/lists/whitelist.txt) → всегда WL
    if link_has_whitelisted_sni(link):
        return "WL"

    # 4. Страна endpoint = RU
    clean_ip = resolve_host_cached(
        host.strip('[] \t\r\n\'"').lower()
    )

    if clean_ip:
        cc = fetch_country_from_ip(clean_ip)
        if cc and cc.upper() == "RU":
            return "WL"

    # 5. Прочие .ru/.su SNI → только доля RU_SNI_RATIO
    if is_ru_sni(link):
        return (
            "WL"
            if random.random() < ru_sni_ratio
            else "BL"
        )

    return "BL"


# ============================================================
# UNSAFE FILTER
# ============================================================

def is_unsafe_config(link: str) -> bool:
    """
    Небезопасные конфиги (для REMOVE_UNSAFE):
    - allowInsecure / insecure = 1 — глушит проверку сертификата,
      открывает MITM;
    - plaintext-транспорт без TLS/Reality у vless / vmess
      (trojan и hysteria2 всегда шифрованы, ss — шифрован методом).
    """
    try:
        if link.startswith("vmess://"):
            from .utils import safe_b64decode
            import json as _json
            data = _json.loads(
                safe_b64decode(link.replace("vmess://", "", 1).strip())
            )
            if str(data.get("tls", "")).lower() not in ("tls", "reality", "xtls"):
                return True
            if str(data.get("allowInsecure", "")).lower() in ("1", "true"):
                return True
            return False

        if link.startswith(("trojan://", "ss://", "hysteria2://", "hy2://")):
            # шифрованы протоколом; проверяем только insecure-параметр
            params = urllib.parse.parse_qs(
                link.split("?", 1)[1].split("#", 1)[0],
                keep_blank_values=True,
            ) if "?" in link else {}
            insecure = str(
                params.get("allowInsecure", params.get("insecure", [""]))[0]
            ).lower()
            return insecure in ("1", "true")

        if link.startswith("vless://"):
            params = urllib.parse.parse_qs(
                link.split("?", 1)[1].split("#", 1)[0],
                keep_blank_values=True,
            ) if "?" in link else {}
            security = str(params.get("security", [""])[0]).lower()
            if security not in ("tls", "reality", "xtls"):
                return True
            insecure = str(
                params.get("allowInsecure", params.get("insecure", [""]))[0]
            ).lower()
            return insecure in ("1", "true")

    except Exception:
        pass

    return False
