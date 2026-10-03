"""Kameleon — локальная маскировка личности клиента при запросах подписок.

Многие серверы отдают конфиги только узнанным клиентам, поэтому каждый
запрос уходит от правдоподобной личности (User-Agent / HWID / OS).

Логика ретраев: юзер в конфиге перечисляет клиентов и ОС через запятую —
ровно эти варианты и тестируются (по одному на попытку, в случайном
порядке, ОС берётся случайная из списка). Никаких отдель счётчиков:
сколько вписал — столько и попыток.

Как пользоваться (функции модуля):
    parse_csv(s)            — "a, b ,c" -> ["a", "b", "c"]
    available_apps()        — клиенты из конфига (или весь встроенный набор)
    available_oses()        — ОС из конфига (или весь встроенный набор)
    random_identity()       — случайная личность из разрешённых
    identity_headers(i)     — dict заголовков для личности
    fetch_kameleon(url)     — скачать URL: пробует все варианты клиент x ОС
                              из конфига, пока один не сработает
"""
from __future__ import annotations

import random
import ssl
import string
import urllib.parse
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .base import safe_b64decode
from .. import config as cfg
from ..config import HEADERS, SSL_CONTEXT, SSL_VERIFY_SOURCES

# ------------------------------------------------------------
# Встроенные наборы (используются, если в конфиге список пуст)
# ------------------------------------------------------------

_ALL_APPS = ("happ", "v2raytun", "incy", "streisand", "v2box", "hiddify")
_ALL_OSES = ("android", "ios", "win", "macos", "linux")

_APP_VERSIONS = {
    "happ": "3.24.0",
    "v2raytun": "5.23.74",
    "incy": "3.2.2",
    "streisand": "1.6.14",
    "v2box": "9.5.1",
    "hiddify": "2.5.7",
}


def parse_csv(s: str) -> list:
    """'a, b ,c' -> ['a', 'b', 'c']; пустая строка -> []."""
    if not s:
        return []
    return [p.strip().lower() for p in str(s).split(",") if p.strip()]


def available_apps() -> list:
    items = [a for a in parse_csv(cfg.KAMELEON_APPS) if a in _ALL_APPS]
    return items or list(_ALL_APPS)


def available_oses() -> list:
    items = [o for o in parse_csv(cfg.KAMELEON_OSES) if o in _ALL_OSES]
    return items or list(_ALL_OSES)


def _rand_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _rand_digits(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))


def _bump_version(v: str) -> str:
    """3.24.0 -> 3.24.<случайный патч> — лёгкая рандомизация версии."""
    parts = v.split(".")
    if len(parts) >= 3:
        parts[-1] = _rand_digits(1)
        return ".".join(parts)
    return v


@dataclass
class Identity:
    """Личность клиента: приложение, ОС, версия, HWID."""
    app: str = "happ"
    os: str = "android"
    version: str = "3.24.0"
    hwid: str = ""
    extra: dict = field(default_factory=dict)

    def user_agent(self) -> str:
        app, os_name, ver = self.app, self.os, self.version
        os_pretty = {
            "android": "Android", "ios": "iOS", "win": "Windows",
            "macos": "macOS", "linux": "Linux",
        }.get(os_name, os_name.capitalize())

        if app == "happ":
            return f"Happ/{ver}/{os_pretty}/{_rand_hex(20)}"
        if app == "v2raytun":
            android_api = _rand_digits(2).lstrip("0") or "14"
            if os_name == "android":
                return f"v2raytun/{ver} (Android {android_api})"
            return f"v2raytun/{ver} ({os_pretty})"
        if app == "incy":
            return f"INCY/{ver}/{os_name}"
        if app == "streisand":
            return f"Streisand/{ver} ({os_pretty})"
        if app == "v2box":
            return f"V2Box/{ver} ({os_pretty})"
        if app == "hiddify":
            return f"Hiddify/{ver} ({os_pretty})"
        return f"{app}/{ver}"


def random_identity() -> Identity:
    """Случайная личность из клиентов/ОС, разрешённых в конфиге."""
    app = random.choice(available_apps())
    os_name = random.choice(available_oses())
    return Identity(
        app=app,
        os=os_name,
        version=_bump_version(_APP_VERSIONS.get(app, "1.0.0")),
        hwid=_rand_hex(16),
    )


def identity_headers(identity: Identity) -> dict:
    """Заголовки запроса для личности (поверх базовых HEADERS)."""
    h = dict(HEADERS)
    h["User-Agent"] = identity.user_agent()
    if identity.hwid:
        h["X-HWID"] = identity.hwid
        h["X-Device-Id"] = identity.hwid
    h["X-Device-OS"] = identity.os
    h["Accept"] = "*/*"
    return h


# ------------------------------------------------------------
# Скачивание с перебором вариантов из конфига
# ------------------------------------------------------------

def _looks_like_subscription(content: str) -> bool:
    """Грубая проверка, что ответ похож на подписку/конфиги."""
    if not content:
        return False
    markers = ("vless://", "vmess://", "trojan://", "ss://",
               "hysteria2://", "hy2://", "tuic://")
    if any(m in content for m in markers):
        return True
    try:
        decoded = safe_b64decode(content.strip()[:4096])
        return any(m in decoded for m in markers)
    except Exception:
        return False


def _try_variant(url: str, app: str, os_name: str, timeout: int,
                 check: Callable[[str], bool]) -> Optional[str]:
    """Одна попытка: личность app+os -> запрос -> контент, если прошёл checker.

    SSL: при SSL_VERIFY_SOURCES сначала строгая проверка; битый серт ->
    одноразовый fallback на контекст без проверки (как в fetch.py).
    """
    identity = random_identity()
    identity.app = app
    identity.os = os_name
    headers = identity_headers(identity)

    def _do(use_ctx):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=use_ctx) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    content = None
    if SSL_VERIFY_SOURCES:
        try:
            content = _do(None)  # системный контекст с проверкой сертификата
        except Exception as e:
            cert_err = isinstance(e, ssl.SSLCertVerificationError) or (
                isinstance(e, urllib.error.URLError)
                and isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError)
            )
            if not cert_err:
                return None
            content = None  # битый серт -> fallback ниже
    if content is None:
        try:
            content = _do(SSL_CONTEXT)  # контекст без проверки
        except Exception:
            return None
    return content if check(content) else None


def fetch_kameleon(
    url: str,
    timeout: int = 12,
    checker: Optional[Callable[[str], bool]] = None,
    parallel: Optional[bool] = None,
    max_workers: Optional[int] = None,
) -> Optional[str]:
    """
    Скачать URL, перебирая ВСЕ варианты клиент x ОС из конфига
    (len(APPS) x len(OSES); хочешь меньше — пиши короче списки).

    parallel=True  — все варианты летят одновременно, берётся первый
                     успешный; худший случай по времени = один таймаут.
    parallel=False — последовательный перебор (меньше запросов к
                     источнику, но дольше в худшем случае).

    checker(content) — необязательная проверка «это то, что нужно»;
    по умолчанию содержимое должно быть похоже на подписку.

    Возвращает текст ответа, если checker его принял,
    иначе None (варианты исчерпаны).
    """
    check = checker or _looks_like_subscription

    # по умолчанию поведение берётся из конфига
    if parallel is None:
        parallel = bool(cfg.KAMELEON_PARALLEL)
    if max_workers is None:
        max_workers = int(cfg.KAMELEON_MAX_WORKERS)

    variants = [
        (app, os_name)
        for app in available_apps()
        for os_name in available_oses()
    ]
    random.shuffle(variants)

    if not variants:
        return None

    if parallel:
        workers = min(max(1, max_workers), len(variants))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(_try_variant, url, app, os_name, timeout, check): (app, os_name)
                for app, os_name in variants
            }
            for fut in as_completed(futures):
                content = fut.result()
                if content:
                    return content
            return None

    for app, os_name in variants:
        content = _try_variant(url, app, os_name, timeout, check)
        if content:
            return content
    return None
