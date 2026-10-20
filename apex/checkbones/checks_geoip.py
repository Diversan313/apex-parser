"""Проверки DNS: bounded-резолв и bulk-прогрев (быстрые пути без сети)."""
import time

from apex.geoip import resolve_host_cached, resolve_hosts_bulk


def check_resolve_offline_paths():
    # невалидные/неглобальные хосты не ходят в сеть
    assert resolve_host_cached("") is None
    assert resolve_host_cached("bad host") is None
    assert resolve_host_cached("127.0.0.1") is None
    # литеральный глобальный IP резолвится сам в себя, без DNS-запроса
    assert resolve_host_cached("8.8.8.8") == "8.8.8.8"


def check_resolve_hosts_bulk_no_network():
    # невалидные хосты: волна completes без единого сетевого запроса,
    # без исключений и без зависания — на больших списках поведение то же,
    # дедлайн стадии режет только неотправленный хвост
    hosts = ["localhost", "127.0.0.1", "bad host", ""]
    t0 = time.monotonic()
    resolved = resolve_hosts_bulk(hosts, workers=4, deadline_s=10)
    assert resolved == 0
    assert time.monotonic() - t0 < 10
