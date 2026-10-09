"""Ограничители сетевых операций, которым не помогают обычные таймауты.

Два места, где urlopen(timeout=N) НЕ ограничивает суммарное время:

1. getaddrinfo() — блокирующий системный вызов; сокетные таймауты на него
   не действуют, реальный потолок задаёт только конфигурация резолвера ОС.
2. Чтение тела ответа — timeout в urlopen действует на каждую recv
   отдельно: сервер, присылающий байты с зазором меньше таймаута
   (tarpit/медленный origin), держит read() бесконечно.
"""
from __future__ import annotations

import socket
import threading
import time

from ..config import DNS_RESOLVE_TIMEOUT, SOURCE_MAX_BYTES

_READ_CHUNK = 64 * 1024

_orig_getaddrinfo = socket.getaddrinfo
_install_lock = threading.Lock()


def _bounded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    # Резолв выполняем в daemon-потоке и ждём не дольше лимита.
    # Зависший getaddrinfo остаётся в фоне и умирает сам, когда ответит
    # резолвер ОС; daemon-поток не держит выход процесса.
    box = {}

    def _run():
        try:
            box["res"] = _orig_getaddrinfo(host, port, family, type, proto, flags)
        except BaseException as e:
            box["err"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(DNS_RESOLVE_TIMEOUT)

    if "res" in box:
        return box["res"]
    if "err" in box:
        raise box["err"]
    # код ошибки не важен: gaierror — OSError, fetch трактует его как
    # транзиентную сетевую ошибку
    raise socket.gaierror(-3, f"resolution exceeded {DNS_RESOLVE_TIMEOUT}s")


def install_network_limits() -> None:
    """Вешает bounded-обёртку на socket.getaddrinfo. Повторный вызов — no-op."""
    with _install_lock:
        if socket.getaddrinfo is _bounded_getaddrinfo:
            return
        global _orig_getaddrinfo
        _orig_getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _bounded_getaddrinfo


def read_bounded(response, deadline: float, max_bytes: int = None) -> bytes:
    """Тело ответа до EOF с жёсткими пределами времени и размера.

    read1() делает не больше одной recv за вызов и возвращается, как только
    пришёл любой объём данных — поэтому проверка дедлайна между итерациями
    ограничивает суммарное время даже против «капающего» сервера. Простой
    read(chunk) внутри одного вызова мог бы ждать наполнения буфера
    бесконечно.

    deadline — absolute time.monotonic(). При превышении — TimeoutError
    (транзиентная для fetch: источник уйдёт в обычный ретрай).
    """
    if max_bytes is None:
        max_bytes = SOURCE_MAX_BYTES
    read1 = getattr(response, "read1", None)
    buf = []
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"body read exceeded deadline ({total} bytes)")
        piece = read1(_READ_CHUNK) if read1 else response.read(_READ_CHUNK)
        if not piece:
            break
        buf.append(piece)
        total += len(piece)
        if total >= max_bytes:
            # префикс тела достаточен: подписка валидна с начала,
            # хвост из-за лимита не теряет смысла
            break
    return b"".join(buf)
