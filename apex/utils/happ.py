"""Расшифровка happ://crypt* — зашифрованных ссылок на подписки.

Формат happ://crypt5/<payload>:
  payload — перестановка блоков по 4 символа (половины блока меняются
  местами). После перестановки: 8 символов маркера (по 4 с краёв)
  выбирают RSA-ключ, далее 12 символов nonce и упаковка:
  <длина_сегмента><1 символ><сегмент_b64><rsa_b64>.
  Сегмент — ChaCha20Poly1305-шифр промежуточной строки, RSA-часть —
  зашифрованный ключ ChaCha (с перестановкой пар символов и base64).
Итог расшифровки — текст со ссылкой на подписку (http/https).

Старые happ://crypt .. crypt4 — просто RSA-блоки (PKCS1v15) подряд.
"""
from __future__ import annotations

import base64
import json
import os
import re
from typing import Optional

try:
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

_KEYS_PATH = os.path.join(os.path.dirname(__file__), "keys", "happ_keys.json")

# Кэш распарсенных PEM-ключей: {marker: private_key}, {"crypt": key, ...}
_KEY_CACHE: dict = {}

_HAPP_RE = re.compile(
    r"happ://crypt\d*/[A-Za-z0-9\-_+/=]{16,}"
)
_URL_RE = re.compile(r"https?://[^\s<>\"'(){}|\\^`\[\]]+", re.IGNORECASE)


def happ_available() -> bool:
    return _HAS_CRYPTO and os.path.exists(_KEYS_PATH)


def _b64d_bytes(s: str) -> bytes:
    """Base64 (urlsafe-совместимый) → bytes. Для бинарных данных (ключи, шифртекст)."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _swap_pairs(s: str) -> str:
    """Меняет местами каждую пару соседних символов (инволюция)."""
    arr = list(s)
    for i in range(0, len(arr) - 1, 2):
        arr[i], arr[i + 1] = arr[i + 1], arr[i]
    return "".join(arr)


def _swap_blocks(s: str) -> str:
    """В каждом 4-символьном блоке меняет половины местами (инволюция)."""
    head = len(s) - (len(s) % 4)
    out = []
    for off in range(0, head, 4):
        out.append(s[off + 2: off + 4])
        out.append(s[off: off + 2])
    out.append(s[head:])
    return "".join(out)


def _load_v5_keys() -> dict:
    if "v5_loaded" not in _KEY_CACHE:
        try:
            with open(_KEYS_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            keys = {}
            for marker, pem_b64 in raw.get("v5", {}).items():
                pem = (
                    "-----BEGIN PRIVATE KEY-----\n"
                    f"{pem_b64}\n"
                    "-----END PRIVATE KEY-----\n"
                )
                keys[marker] = _serialization.load_pem_private_key(
                    pem.encode(), password=None
                )
            _KEY_CACHE["v5_loaded"] = True
            _KEY_CACHE.update(keys)
        except Exception as e:
            print(f"⚠️ Не удалось загрузить happ-ключи v5: {e}")
            _KEY_CACHE["v5_loaded"] = True
    return _KEY_CACHE


def _load_legacy_key(name: str):
    """crypt .. crypt4 — индекс по порядку в файле."""
    cache_key = f"legacy:{name}"
    if cache_key in _KEY_CACHE:
        return _KEY_CACHE[cache_key]
    try:
        with open(_KEYS_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        for entry in raw.get("legacy", []):
            if entry.get("name") != name:
                continue
            pem = (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                f"{entry['key']}\n"
                "-----END RSA PRIVATE KEY-----\n"
            )
            key = _serialization.load_pem_private_key(
                pem.encode(), password=None
            )
            _KEY_CACHE[cache_key] = key
            return key
    except Exception as e:
        print(f"⚠️ Не удалось загрузить happ-ключ {name}: {e}")
    _KEY_CACHE[cache_key] = None
    return None


def _decrypt_crypt5(payload: str) -> str:
    data = _swap_blocks(payload)

    if len(data) < 30:
        raise ValueError("короткий payload")

    marker = data[:4] + data[-4:]
    body = data[4:-4]

    nonce = body[:12].encode("utf-8")
    rest = body[12:]

    m = re.match(r"^(\d+)", rest)
    if not m:
        raise ValueError("нет длины сегмента")
    seg_len = int(m.group(1))
    packed = rest[len(m.group(1)):]

    if len(packed) < 1 + seg_len:
        raise ValueError("сегмент обрезан")

    seg_b64 = packed[1: 1 + seg_len]
    rsa_b64 = packed[1 + seg_len:]

    keys = _load_v5_keys()
    rsa_key = keys.get(marker)
    if rsa_key is None:
        raise ValueError(f"неизвестный маркер {marker!r}")

    rsa_plain = rsa_key.decrypt(
        _b64d_bytes(rsa_b64), _rsa_padding.PKCS1v15()
    ).decode("latin-1")

    chacha_key = _b64d_bytes(_swap_pairs(rsa_plain))
    intermediate = ChaCha20Poly1305(chacha_key).decrypt(
        nonce, _b64d_bytes(seg_b64), None
    ).decode("utf-8")

    return _b64d_bytes(_swap_pairs(intermediate)).decode("utf-8")


def _decrypt_legacy(name: str, payload: str) -> str:
    key = _load_legacy_key(name)
    if key is None:
        raise ValueError(f"нет ключа для {name}")

    chunk = key.key_size // 8
    raw = _b64d_bytes(payload)

    parts = []
    for i in range(0, len(raw), chunk):
        parts.append(key.decrypt(raw[i: i + chunk], _rsa_padding.PKCS1v15()))
    return b"".join(parts).decode("utf-8")


def decrypt_happ_link(link: str) -> Optional[str]:
    """happ://crypt*/... → расшифрованный текст (или None при неудаче)."""
    if not _HAS_CRYPTO:
        return None

    link = link.strip()
    path = link[7:] if link.startswith("happ://") else link

    try:
        if path.startswith("crypt5/"):
            return _decrypt_crypt5(path[len("crypt5/"):])
        for legacy in ("crypt4/", "crypt3/", "crypt2/", "crypt/"):
            if path.startswith(legacy):
                return _decrypt_legacy(
                    legacy.rstrip("/"), path[len(legacy):]
                )
    except Exception:
        return None

    return None


def extract_happ_links(text: str) -> list:
    """Все happ://crypt* ссылки из текста (без повторов)."""
    seen = set()
    result = []
    for m in _HAPP_RE.findall(text or ""):
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def happ_link_to_subscription_url(link: str) -> Optional[str]:
    """happ-ссылка → первый http(s)-URL из расшифрованного текста."""
    decrypted = decrypt_happ_link(link)
    if not decrypted:
        return None
    urls = _URL_RE.findall(decrypted)
    return urls[0] if urls else None
