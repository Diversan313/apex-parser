"""Chunker: один Xray на чанк, несколько чанков параллельно.

Обычный путь — процесс Xray на каждый конфиг. Здесь на чанк поднимается
один Xray с пачкой mixed-inbound'ов; чанки сами идут параллельно
(несколько процессов Xray одновременно). Порты выделяются из
фиксированных диапазонов ниже ephemeral, чтобы избежать EADDRINUSE
и исчерпания портов.

Публичный API:
    test_links_chunked(items, min_success_count) — [(link, src)] →
        {link: 6-tuple}; ссылки без вердикта в чанке добираются
        одиночным fallback'ом.
"""
from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from typing import Optional

from . import config as cfg
from .config import MAX_WORKERS
from .parse import parse_host_port_and_name
from .utils import extract_clean_flag, cc_to_flag
from .xray import (
    get_exit_country_via_proxy,
    get_xray_executable,
    link_to_xray_outbound,
    tcp_port_open,
    wait_for_port,
)

_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.microsoft.com/connecttest.txt",
)

# Диапазоны портов ниже ephemeral (Linux ~32768, Windows ~49152).
_PORT_BASE = 20000
_PORT_RANGE = 2000
_PORT_HARD_MAX = 32000 if os.name != "nt" else 49000

_CHUNK_HARD_CAP = 64


def _cfg(name: str, default):
    return getattr(cfg, name, default)


# ============================================================
# ТЮНЕР
# ============================================================

def _available_ram_kb() -> Optional[int]:
    """Свободная RAM в KB. Linux: /proc/meminfo; Windows: GlobalMemoryStatusEx."""
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except Exception:
        pass

    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatusEx()
            status.dwLength = ctypes.sizeof(MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.ullAvailPhys // 1024
        except Exception:
            pass

    return None


def _auto_chunk_size() -> int:
    cpu = os.cpu_count() or 2
    size = max(8, min(48, cpu * 4))
    ram_kb = _available_ram_kb()
    if ram_kb is not None and ram_kb < 2_000_000:
        size = max(8, size // 2)
    return size


def _auto_parallel_chunks() -> int:
    """Сколько shared-Xray процессов крутить одновременно."""
    cpu = os.cpu_count() or 2
    ram_kb = _available_ram_kb()
    # Процесс на каждое ядро: TLS-handshake'и идут параллельно,
    # один Xray на все чанки превращает runner в последовательный прокси.
    by_cpu = max(1, min(8, cpu))
    if ram_kb is not None:
        by_ram = max(1, int(ram_kb / 150_000))
        return max(1, min(by_cpu, by_ram, 8))
    return by_cpu


class ChunkTuner:
    def __init__(self):
        fixed = int(_cfg("XRAY_CHUNKER_SIZE", 0) or 0)
        self.size = min(max(fixed, 8), _CHUNK_HARD_CAP) if fixed else _auto_chunk_size()

    def adjust(self, chunk_len: int, started_all: bool, missing: int) -> None:
        if not started_all:
            self.size = max(8, self.size // 2)
        elif missing > chunk_len // 4:
            self.size = max(8, int(self.size * 0.75))
        else:
            self.size = min(_CHUNK_HARD_CAP, int(self.size * 1.25) + 1)


# ============================================================
# ПОРТЫ
# ============================================================

_port_lock = threading.Lock()
_port_slot = 0


def _next_port_base() -> int:
    """Циклический base для чанка, чтобы параллельные процессы не пересекались."""
    global _port_slot
    with _port_lock:
        slots = max(1, (_PORT_HARD_MAX - _PORT_BASE) // _PORT_RANGE)
        base = _PORT_BASE + (_port_slot % slots) * _PORT_RANGE
        _port_slot += 1
        return base


def _free_ports(count: int, base: int) -> list:
    """Bind-проверка: connect не видит TIME_WAIT, Xray без SO_REUSEADDR падает."""
    ports = []
    candidate = base + random.randint(0, 50)
    limit = min(base + _PORT_RANGE, _PORT_HARD_MAX)
    while len(ports) < count and candidate < limit:
        if candidate in ports:
            candidate += 1
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.bind(("127.0.0.1", candidate))
            s.close()
            ports.append(candidate)
        except OSError:
            pass
        candidate += 1
    return ports


def _build_chunk_config(outbounds: list, ports: list) -> dict:
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }
    for outbound, port in zip(outbounds, ports):
        tag = f"proxy{port}"
        outbound["tag"] = tag
        config["outbounds"].append(outbound)
        config["inbounds"].append({
            "tag": f"mixed{port}",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "mixed",
            "settings": {"auth": "noauth", "udp": True},
        })
        config["routing"]["rules"].append({
            "type": "field",
            "inboundTag": [f"mixed{port}"],
            "outboundTag": tag,
        })
    return config


# ============================================================
# ПРОГОН ОДНОГО ЧАНКА
# ============================================================

def _test_port(port: int, timeout: float, min_success_count: int):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        })
    )

    def probe(url: str):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
            )
            t0 = time.monotonic()
            with opener.open(req, timeout=timeout) as resp:
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                if resp.status in (200, 204):
                    return elapsed_ms
        except Exception:
            pass
        return None

    # URL'ы зондируем параллельно: последовательный прогон превращает
    # мёртвый порт в 3 таймаута подряд (18с) и держит барьер чанка.
    with ThreadPoolExecutor(max_workers=len(_TEST_URLS)) as pool:
        pings = list(pool.map(probe, _TEST_URLS))

    success = sum(1 for p in pings if p is not None)
    best_ping_ms = min((p for p in pings if p is not None), default=None)
    if success < min_success_count:
        return False, f"Тест провален ({success}/3)", None
    return True, f"OK ({success}/3)", best_ping_ms


def _wait_ports_parallel(ports: list, timeout: float) -> list:
    """Параллельное ожидание с общим дедлайном — не суммируем таймауты."""
    if not ports:
        return []
    deadline = time.monotonic() + timeout
    opened = []

    def probe(port: int) -> Optional[int]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if wait_for_port(port, timeout=min(remaining, 0.5)):
            return port
        # короткий ретрай до дедлайна
        while time.monotonic() < deadline:
            if wait_for_port(port, timeout=0.1):
                return port
        return None

    workers = min(len(ports), max(4, (os.cpu_count() or 2) * 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(probe, ports):
            if res is not None:
                opened.append(res)
    return opened


def _test_chunk(links: list, min_success_count: int, timeout: float):
    """
    Один shared-Xray на чанк. Возвращает (results, started_all).
    Ссылки без вердикта не попадают в results — их заберёт fallback.
    """
    results = {}
    outbounds = []
    port_links = []
    for link in links:
        outbound = link_to_xray_outbound(link)
        if not outbound:
            results[link] = (
                False, None, "Ошибка генерации JSON для Xray", None, None, None
            )
            continue
        outbounds.append(outbound)
        port_links.append(link)

    if not outbounds:
        return results, True

    base = _next_port_base()
    ports = _free_ports(len(outbounds), base)
    if len(ports) < len(outbounds):
        # не хватило портов в диапазоне — урезаем, остальное уйдёт в fallback
        outbounds = outbounds[:len(ports)]
        port_links = port_links[:len(ports)]

    if not ports:
        return results, False

    config = _build_chunk_config(outbounds, ports)
    port_to_link = dict(zip(ports, port_links))

    proc = None
    started_all = True
    try:
        proc = subprocess.Popen(
            [get_xray_executable(), "run", "-c", "stdin:"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.stdin.write(json.dumps(config, ensure_ascii=False).encode("utf-8"))
        proc.stdin.flush()
        proc.stdin.close()

        base_to = float(_cfg("XRAY_CHUNKER_START_TIMEOUT", 2.5))
        start_timeout = base_to + len(ports) * 0.02
        opened = _wait_ports_parallel(ports, start_timeout)
        started_all = len(opened) == len(ports)

        if proc.poll() is not None:
            return results, False

        for closed in set(ports) - set(opened):
            results[port_to_link[closed]] = (
                False, None, "Локальный Xray не запустился", None, None, None,
            )

        def run_one(port: int):
            ok, reason, ping_ms = _test_port(port, timeout, min_success_count)
            link = port_to_link[port]
            if not ok:
                return link, (False, None, reason, None, None, None)
            cc, exit_ip = get_exit_country_via_proxy(
                urllib.request.build_opener(
                    urllib.request.ProxyHandler({
                        "http": f"http://127.0.0.1:{port}",
                        "https": f"http://127.0.0.1:{port}",
                    })
                ),
                timeout,
            )
            orig_name = link.split("#", 1)[1] if "#" in link else ""
            flag = cc_to_flag(cc) if cc else extract_clean_flag(orig_name)
            return link, (True, (link, flag), reason, cc, exit_ip, ping_ms)

        max_workers = max(1, int(_cfg("XRAY_CHUNKER_MAX_WORKERS", 12)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = [pool.submit(run_one, p) for p in opened]
            for fut in as_completed(futs):
                try:
                    link, verdict = fut.result()
                    results[link] = verdict
                except Exception:
                    pass

    except Exception:
        started_all = False
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    return results, started_all


# ============================================================
# ПУБЛИЧНЫЙ ВХОД
# ============================================================

def _prefilter_tcp(items: list, results: dict) -> list:
    """TCP pre-check до сборки чанка; hy2 пропускаем (UDP)."""
    to_test = []

    def probe(item):
        link, _src = item
        host, port, _ = parse_host_port_and_name(link)
        is_hy2 = link.startswith(("hysteria2://", "hy2://"))
        if not host or not port:
            return link, (False, None, "Некорректный формат хоста/порта", None, None, None)
        if not is_hy2 and not tcp_port_open(host, port):
            return link, (False, None, "TCP: порт закрыт/недоступен", None, None, None)
        return None

    with ThreadPoolExecutor(max_workers=_cfg("TCP_PREFILTER_WORKERS", 60)) as pool:
        for res in pool.map(probe, items):
            if res is None:
                continue
            link, verdict = res
            results[link] = verdict
    for link, _ in items:
        if link not in results:
            to_test.append(link)
    return to_test


def test_links_chunked(items: list, min_success_count: int):
    """
    Тестирует [(link, src)] → {link: 6-tuple}.

    Формат совпадает с check_proxy_alive_detailed.
    Чанки идут параллельно (несколько shared-Xray одновременно).
    """
    from .xray import check_proxy_alive_detailed

    results = {}

    if not _cfg("XRAY_CHUNKER_ENABLED", True):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(check_proxy_alive_detailed, link, min_success_count): link
                for link, _ in items
            }
            for future in as_completed(futures):
                link = futures[future]
                try:
                    results[link] = future.result()
                except Exception:
                    pass
        return results

    to_test = _prefilter_tcp(items, results)
    if not to_test:
        return results

    tuner = ChunkTuner()
    parallel = max(1, int(_cfg("XRAY_CHUNKER_PARALLEL", 0) or 0) or _auto_parallel_chunks())
    timeout = float(_cfg("XRAY_TEST_TIMEOUT", 6.0))

    # нарезаем все чанки заранее
    chunks = []
    pos = 0
    while pos < len(to_test):
        size = tuner.size
        chunk = to_test[pos:pos + size]
        pos += len(chunk)
        chunks.append(chunk)

    results_lock = threading.Lock()

    def run_chunk(chunk: list):
        chunk_results, started_all = _test_chunk(chunk, min_success_count, timeout)
        missing = [l for l in chunk if l not in chunk_results]
        if missing:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(missing))) as ex:
                futs = {
                    ex.submit(check_proxy_alive_detailed, link, min_success_count): link
                    for link in missing
                }
                for fut in as_completed(futs):
                    link = futs[fut]
                    try:
                        chunk_results[link] = fut.result()
                    except Exception:
                        pass
        with results_lock:
            results.update(chunk_results)
            tuner.adjust(len(chunk), started_all, len(missing))
        return len(chunk)

    # параллельный прогон чанков
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futs = [pool.submit(run_chunk, c) for c in chunks]
        # таймаут на чанк: старт + тест + запас
        chunk_deadline = timeout * 3 + float(_cfg("XRAY_CHUNKER_START_TIMEOUT", 2.5)) + 15.0
        for fut in as_completed(futs):
            try:
                fut.result(timeout=chunk_deadline)
            except Exception:
                pass

    return results
