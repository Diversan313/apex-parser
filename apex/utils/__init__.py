"""Утилиты проекта.

base.py  — мелкие общие помощники (base64, флаги, санитайзер ссылок)
happ.py  — расшифровка happ://crypt* ссылок на подписки
keys/    — ключи для happ-расшифровки (публично извлекаемые из клиентов Happ)
"""
from .base import (
    safe_b64decode,
    safe_b64encode,
    fmt_bytes,
    cc_to_flag,
    extract_clean_flag,
    sanitize_v2rayng_link,
)

__all__ = [
    "safe_b64decode",
    "safe_b64encode",
    "fmt_bytes",
    "cc_to_flag",
    "extract_clean_flag",
    "sanitize_v2rayng_link",
]
