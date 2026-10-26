"""Prox — внешние сервисы для гео-заблокированных источников и happ-декрипта.

Раннер GitHub сидит на серваках Azure: RU-сервисы для него отвечают 403 или
заглушкой с 200. Kameleon подменяет личность, но IP остаётся прежним.
Prox — третий уровень цепочки (локально → Kameleon → Prox): тот же URL
забирает сторонний сервис своим IP — kfwl отдаёт base64 тела, linllc
пропускает как есть. Сюда же fallback расшифровки happ-ссылок: локальный
набор ключей отстаёт от новых маркеров, внешний декрипт закрывает разрыв
(иногда сервис бывает недоступен, тогда тихий None).
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.request
from collections import deque

from .. import config as cfg
from .netlimit import read_bounded

_RATE_LOCK = threading.Lock()
_RATE_WINDOWS: dict = {}

_CONCURRENCY_SEM = threading.BoundedSemaphore(int(cfg.PROX_CONCURRENCY))

_RATE_PER_MIN = {
    "kfwl": 180,
    "linllc": 60,
    "happ": 60,
}


def _kfwl_url(url: str) -> str:
    # Путь-сегменты. b64 — единственный формат с исходным телом подписки:
    # без сегмента kfwl отдаёт HTML-витрину для людей, не машинный ответ.
    return f"https://p.kfwl.lol/ua=happ/os=android/b64/{url}"


def _linllc_url(url: str) -> str:
    return f"https://p.linllc.site/sub/{url}"


def _decode_b64(raw: bytes):
    try:
        text = raw.decode("ascii", errors="strict")
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return None


def _decode_raw(raw: bytes):
    return raw.decode("utf-8", errors="ignore")


_SERVICES = {
    "kfwl": (_kfwl_url, _decode_b64),
    "linllc": (_linllc_url, _decode_raw),
}

_HAPP_DECRYPT_URL = "https://api.ioo.ir/v1/happ/decrypt"


def _parse_services(spec: str) -> list:
    return [s.strip().lower() for s in (spec or "").split(",") if s.strip()]


def _rate_slot(name: str, deadline: float) -> bool:
    """Слот в rate-окне 60с. Дольше остатка deadline не ждём."""
    limit = _RATE_PER_MIN.get(name, 60)
    while True:
        with _RATE_LOCK:
            now = time.monotonic()
            window = _RATE_WINDOWS.setdefault(name, deque())
            while window and now - window[0] >= 60.0:
                window.popleft()
            if len(window) < limit:
                window.append(now)
                return True
            wait = 60.0 - (now - window[0]) + 0.05
        if time.monotonic() + wait >= deadline - 0.5:
            return False
        time.sleep(wait)


def prox_fetch(url: str, timeout: float):
    """Контент источника через сторонний сервис или None.

    timeout — потолок на весь вызов: ожидание rate-слота, connect и
    чтение тела укладываются в него. Сервисы перебираются по порядку из
    PROX_SERVICES; сбой одного — молчаливый переход к следующему.
    """
    if not cfg.PROX_ENABLED:
        return None
    deadline = time.monotonic() + timeout
    for name in _parse_services(cfg.PROX_SERVICES):
        entry = _SERVICES.get(name)
        if entry is None or not _rate_slot(name, deadline):
            continue
        build, decode = entry
        with _CONCURRENCY_SEM:
            remaining = deadline - time.monotonic()
            if remaining <= 0.5:
                return None
            try:
                req = urllib.request.Request(build(url), headers=cfg.HEADERS)
                with urllib.request.urlopen(
                    req, timeout=min(cfg.PROX_TIMEOUT, remaining)
                ) as resp:
                    if resp.status != 200:
                        continue
                    raw = read_bounded(resp, deadline)
            except Exception:
                continue
            return decode(raw)
    return None


def happ_decrypt_fallback(link: str, timeout: float = 10.0):
    """happ-ссылка → URL подписки через внешний декрипт-сервис.

    Локальные ключи не покрывают новые маркеры и форматы; сервис держит
    свежие (crypt … crypt5.2). Контракт: POST {"link": …} →
    {"ok": true, "result": url}. Недоступен — None, источник теряется
    так же, как без fallback.
    """
    if not cfg.PROX_ENABLED:
        return None
    deadline = time.monotonic() + timeout
    if not _rate_slot("happ", deadline):
        return None
    try:
        req = urllib.request.Request(
            _HAPP_DECRYPT_URL,
            data=json.dumps({"link": link}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None
    if payload.get("ok") and payload.get("result"):
        return str(payload["result"])
    return None
