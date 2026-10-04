"""Chunker: тестирование конфигов чанками — один процесс Xray на чанк.

Обычный путь — отдельный процесс Xray на каждый конфиг: старт процесса
и ожидание inbound'а стоят дороже самой проверки. Здесь на чанк
поднимается один Xray с пачкой mixed-inbound'ов, каждый порт через
routing завёрнут в свой outbound, порты тестируются пулом потоков.

Размер чанка адаптивный: стартовое значение считается по CPU/RAM машины,
дальше тюнер сжимает чанк при проблемах и растит при стабильной работе.

Публичный API:
    test_links_chunked(items, min_success_count) — прогнать [(link, src)],
        вернуть {link: 6-tuple результата}; для ссылок, не получивших
        вердикт в чанке, включается одиночный fallback.
"""
from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
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

_CHUNK_HARD_CAP = 64


def _cfg(name: str, default):
    return getattr(cfg, name, default)


# ============================================================
# ТЮНЕР РАЗМЕРА ЧАНКА
# ============================================================

def _available_ram_kb() -> Optional[int]:
    """MemAvailable из /proc/meminfo (Linux); на Windows — None."""
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return None


def _auto_chunk_size() -> int:
    """Стартовый размер чанка по ресурсам машины."""
    cpu = os.cpu_count() or 2
    size = max(8, min(48, cpu * 4))
    ram_kb = _available_ram_kb()
    if ram_kb is not None and ram_kb < 2_000_000:
        size = max(8, size // 2)
    return size


class ChunkTuner:
    """Держит текущий размер чанка и подстраивает его по результатам."""

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
# КОНФИГ ЧАНКА
# ============================================================

def _free_port_sequence(count: int) -> list:
    """
    Порты для инбаундов чанка. Каждую позицию проверяем bind()'ом:
    connect-проба не видит TIME_WAIT, а Xray без SO_REUSEADDR
    на таком порту упадёт с EADDRINUSE.
    """
    ports = []
    base = random.randint(20000, 45000)
    candidate = base
    while len(ports) < count:
        if candidate in ports or candidate >= 65000:
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
    """HTTP-тест одного инбаунда. Возвращает (ok, reason, ping_ms)."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        })
    )
    success = 0
    best_ping_ms = None
    for url in _TEST_URLS:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
            )
            t0 = time.monotonic()
            with opener.open(req, timeout=timeout) as resp:
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                if resp.status in (200, 204):
                    success += 1
                    if best_ping_ms is None or elapsed_ms < best_ping_ms:
                        best_ping_ms = elapsed_ms
        except Exception:
            pass
    if success < min_success_count:
        return False, f"Тест провален ({success}/3)", None
    return True, f"OK ({success}/3)", best_ping_ms


def _wait_ports_parallel(ports: list, timeout: float) -> list:
    """Параллельное ожидание открытия портов с общим дедлайном."""
    if not ports:
        return []

    deadline = time.monotonic() + timeout
    opened = []

    def probe(port: int) -> Optional[int]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if wait_for_port(port, timeout=remaining):
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
    Поднимает один Xray на чанк и тестирует каждый порт.

    Возвращает (results, started_all):
      results — {link: 6-tuple}; ссылка без вердикта (порт не открылся,
      процесс умер) в results не попадает — её заберёт fallback;
      started_all — все ли инбаунды поднялись (сигнал тюнеру).
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

    ports = _free_port_sequence(len(outbounds))
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

        base_timeout = float(_cfg("XRAY_CHUNKER_START_TIMEOUT", 3.0))
        start_timeout = base_timeout + len(ports) * 0.03
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

        max_workers = max(1, int(_cfg("XRAY_CHUNKER_MAX_WORKERS", 8)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = [pool.submit(run_one, p) for p in opened]
            for fut in as_completed(futs):
                link, verdict = fut.result()
                results[link] = verdict

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
    """Отсекает конфиги с мёртвым сервером до сборки чанка (hy2 мимо — UDP)."""
    to_test = []

    def probe(item):
        link, src = item
        host, port, _ = parse_host_port_and_name(link)
        is_hy2 = link.startswith(("hysteria2://", "hy2://"))
        if not host or not port:
            return link, (False, None, "Некорректный формат хоста/порта", None, None, None)
        if not is_hy2 and not tcp_port_open(host, port):
            return link, (False, None, "TCP: порт закрыт/недоступен", None, None, None)
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
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
    Тестирует [(link, src)] и возвращает {link: 6-tuple}.

    Формат результата совпадает с check_proxy_alive_detailed, поэтому
    счётчики и списки в main.py работают без изменений.

    Ссылки, не получившие вердикт в чанке (падение процесса, невалидный
    outbound), добираются одиночным fallback'ом.
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

    tuner = ChunkTuner()
    pos = 0
    while pos < len(to_test):
        chunk = to_test[pos:pos + tuner.size]
        pos += len(chunk)

        timeout = float(_cfg("XRAY_TEST_TIMEOUT", 6.0))
        chunk_results, started_all = _test_chunk(chunk, min_success_count, timeout)
        results.update(chunk_results)

        missing = [l for l in chunk if l not in chunk_results]
        if missing:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(check_proxy_alive_detailed, link, min_success_count): link
                    for link in missing
                }
                for future in as_completed(futures):
                    link = futures[future]
                    try:
                        results[link] = future.result()
                    except Exception:
                        pass

        tuner.adjust(len(chunk), started_all, len(missing))

    return results
