"""Проверки chunker: сборка конфига чанка, тюнер, раздача портов (без сети)."""
import sys

from apex import config as cfg
from apex.chunker import (
    ChunkTuner,
    _build_chunk_config,
    _free_ports,
    _auto_chunk_size,
    _auto_parallel_chunks,
)
from apex.xray import link_to_xray_outbound


def check_build_chunk_config():
    links = [
        "vless://u@192.0.2.10:443?type=tcp&security=reality&pbk=K&sid=ab&sni=x.com&fp=chrome#t1",
        "vless://u@192.0.2.11:443?type=ws&security=tls&sni=x.com&path=%2Fws#t2",
        "hysteria2://pass@192.0.2.12:443?sni=x.com#t3",
        "ss://YWVzLTI1Ni1nY206cGFzcw@192.0.2.13:8388#t4",
        "trojan://pass@192.0.2.14:443?security=tls&sni=x.com#t5",
    ]
    outbounds = [link_to_xray_outbound(l) for l in links]
    assert all(outbounds), "парсинг outbound'ов сломан"
    ports = _free_ports(len(outbounds), 30000)
    assert len(ports) == len(outbounds)
    assert len(set(ports)) == len(ports)
    conf = _build_chunk_config(outbounds, ports)
    assert len(conf["inbounds"]) == 5
    assert len(conf["outbounds"]) == 5 + 2  # + direct/block
    assert len(conf["routing"]["rules"]) == 5
    # каждая пара inbound->outbound связана тегами
    for inbound, rule in zip(conf["inbounds"], conf["routing"]["rules"]):
        assert rule["inboundTag"] == [inbound["tag"]]


def check_tuner_adjust():
    cfg.XRAY_CHUNKER_SIZE = 0
    t = ChunkTuner()
    s0 = t.size
    assert 8 <= s0 <= 48
    t.adjust(20, False, 5)  # порты не поднялись -> сжатие вдвое
    assert t.size == max(8, s0 // 2)
    t.adjust(20, True, 10)  # много fallback -> 0.75
    t.adjust(20, True, 0)   # стабильно -> рост
    assert t.size >= 8


def check_tuner_fixed_and_cap():
    cfg.XRAY_CHUNKER_SIZE = 24
    assert ChunkTuner().size == 24
    cfg.XRAY_CHUNKER_SIZE = 500
    assert ChunkTuner().size == 64  # жёсткий кап
    cfg.XRAY_CHUNKER_SIZE = 0


def check_autosize_sane():
    import os
    size = _auto_chunk_size()
    assert 8 <= size <= 48
    parallel = _auto_parallel_chunks()
    assert 1 <= parallel <= 8
    assert size <= _CHUNK_CAP if (_CHUNK_CAP := 64) else True


def check_watchdog_kills_overdue_chunks():
    # регрессия: таймаут на чанк через result(timeout) у as_completed
    # не срабатывал никогда — watchdog обязан реально снимать процессы
    from apex.chunker import (
        _register_chunk_proc,
        _unregister_chunk_proc,
        kill_overdue_chunks,
        _CHUNK_PROCS,
    )

    class _FakeProc:
        def __init__(self):
            self.killed = False

        def kill(self):
            self.killed = True

    overdue = _FakeProc()
    fresh = _FakeProc()
    try:
        _register_chunk_proc(901, overdue)
        _register_chunk_proc(902, fresh)

        # свежие чанки не трогаем
        assert kill_overdue_chunks(3600.0) == 0
        assert not overdue.killed and not fresh.killed

        # просроченные — снимаем; реестр чистит сам чанк в finally,
        # kill здесь не удаляет записи
        assert kill_overdue_chunks(0.0) == 2
        assert overdue.killed and fresh.killed
        assert 901 in _CHUNK_PROCS and 902 in _CHUNK_PROCS

        _unregister_chunk_proc(901)
        _unregister_chunk_proc(902)
        assert 901 not in _CHUNK_PROCS and 902 not in _CHUNK_PROCS
        assert kill_overdue_chunks(0.0) == 0
    finally:
        _unregister_chunk_proc(901)
        _unregister_chunk_proc(902)
