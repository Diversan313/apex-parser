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
)
from .geoip import (
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


def _host_in_white_ips(link: str, white_ips: set) -> bool:
    """
    Быстрая проверка: хост или SNI из ссылки прямо в white_ips.
    Без DNS — на 100k кандидатов это секунды, а не часы.
    """
    if not white_ips:
        return False

    from .parse import parse_host_port_and_name, extract_sni_from_link
    host, _, _ = parse_host_port_and_name(link)
    if host:
        clean = host.strip('[] \t\r\n\'"').lower()
        if clean in white_ips:
            return True

    sni = extract_sni_from_link(link)
    if sni and sni.lower() in white_ips:
        return True

    return False


def classify_config(
    link: str,
    white_ips: set,
    ru_sni_ratio: float = RU_SNI_RATIO,
) -> str:

    # 1. IP из white_ip.txt
    if _host_in_white_ips(link, white_ips):
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

    # (DNS и GeoIP убраны из классификации: на 50k+ хостов это
    #  часы последовательных DNS-запросов. RU-эндпоинты ловятся
    #  позже — chunker определяет exit-country параллельно,
    #  и BL_RU_TO_WL перекидывает их в WL.)

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

# SS: шифрование принимаем только AEAD (белый список). Не-AEAD шифры
# (CFB/CTR/RC4/потоковые) уязвимы к подделке трафика, поэтому любой
# неизвестный метод считаем небезопасным — новые безопасные шифры
# добавляются сюда явно, а не через чёрный список.
_SS_AEAD_CIPHERS = frozenset({
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "chacha20-poly1305", "xchacha20-ietf-poly1305",
})
_SS_2022_KEY_LEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

_TRUE_VALUES = ("1", "true", "yes", "on")


def _query_insecure(params: dict) -> bool:
    """allowInsecure / insecure / skip-cert-verify / verify=0 в query."""
    for key in ("allowinsecure", "insecure", "skip-cert-verify"):
        val = str(params.get(key, [""])[0] or "").strip().lower()
        if val in _TRUE_VALUES:
            return True
    # verify=0 встречается в ссылках с серверной валидацией сертификата
    return str(params.get("verify", [""])[0] or "").strip() == "0"


def _ss_method_and_password(link: str):
    """
    Достаёт (method, password) из ss-ссылки в обоих форматах:
    plain method:pass@host:port и base64(method:pass)@host:port.
    """
    main = link.split("#", 1)[0].split("?", 1)[0]
    body = main[len("ss://"):]
    if "@" not in body:
        return None
    userinfo = body.rsplit("@", 1)[0]
    if ":" in userinfo:
        return userinfo.split(":", 1)
    try:
        from .utils import safe_b64decode
        decoded = safe_b64decode(userinfo)
        if ":" in decoded:
            return decoded.split(":", 1)
    except Exception:
        pass
    return None


def _ss_2022_key_broken(method: str, password: str) -> bool:
    """
    SS2022 требует пароль = base64-ключ ровно нужной длины.
    Кривая длина ломает конфиг во всех клиентах.
    Мультиключ (key1:key2) не проверяем: это валидный формат Xray-core.
    """
    if ":" in password:
        password = password.split(":", 1)[0]
    try:
        import base64 as _b64
        decoded = _b64.b64decode(password + "=" * (-len(password) % 4))
        return len(decoded) != _SS_2022_KEY_LEN[method]
    except Exception:
        return False


def is_unsafe_config(link: str) -> bool:
    """
    Небезопасные конфиги (для REMOVE_UNSAFE):

    - allowInsecure / insecure / skip-cert-verify / verify=0 — глушит
      проверку сертификата, открывает MITM;
    - plaintext-транспорт без TLS/Reality/XTLS у vless / vmess
      (trojan и hysteria2 шифрованы протоколом);
    - vmess: scy=none (шифрование выключено) и aid>0 (legacy-QTLS);
    - ss: шифр не из AEAD-набора; у SS2022 — кривая длина ключа.
    """
    try:
        main = link.split("#", 1)[0]
        # параметры кейс-инсенситивны: источники шлют и allowInsecure, и allowinsecure
        params = {
            k.lower(): v
            for k, v in urllib.parse.parse_qs(
                main.split("?", 1)[1],
                keep_blank_values=True,
            ).items()
        } if "?" in main else {}

        if _query_insecure(params):
            return True

        if link.startswith("vmess://"):
            from .utils import safe_b64decode
            import json as _json
            data = _json.loads(
                safe_b64decode(link.replace("vmess://", "", 1).strip())
            )
            if str(data.get("tls", "")).lower() not in ("tls", "reality", "xtls"):
                return True
            # scy=none — vmess вообще без внутреннего шифрования
            if str(data.get("scy", "auto")).lower() == "none":
                return True
            # aid>0 — legacy-QTLS, уязвимая схема аутентификации
            try:
                if int(data.get("aid") or 0) > 0:
                    return True
            except (TypeError, ValueError):
                pass
            return False

        if link.startswith("ss://"):
            pair = _ss_method_and_password(link)
            if not pair:
                return False
            method = pair[0].strip().lower()
            method = method.split(";")[0]  # plugin-часть после ';' не метод
            if method.startswith("2022-blake3-"):
                return _ss_2022_key_broken(method, pair[1])
            return method not in _SS_AEAD_CIPHERS

        if link.startswith("vless://"):
            security = str(params.get("security", [""])[0]).lower()
            return security not in ("tls", "reality", "xtls")

    except Exception:
        pass

    return False
