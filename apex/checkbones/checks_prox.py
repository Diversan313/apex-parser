"""Проверки Prox: URL-билдеры, rate-окно, элиджибилность, фолбэк, интеграция."""
import base64
import http.server
import json
import os
import threading
import time

from apex import config as cfg
from apex.utils import prox
from apex.fetch import _prox_eligible, fetch_single_url_with_details

CONFIG = "vless://u@1.2.3.4:443?type=tcp&security=tls#t1"


def check_url_builders():
    assert prox._kfwl_url("https://example.com/sub") == (
        "https://p.kfwl.lol/ua=happ/os=android/b64/https://example.com/sub"
    )
    assert prox._linllc_url("https://example.com/sub") == (
        "https://p.linllc.site/sub/https://example.com/sub"
    )


def check_b64_decode():
    original = "vless://u@1.2.3.4:443#тест"
    encoded = base64.b64encode(original.encode()).decode()
    assert prox._decode_b64(encoded.encode()) == original
    # битый base64 → None, не исключение
    assert prox._decode_b64(b"!!!not-base64!!!") is None
    assert prox._decode_raw(b"plain text") == "plain text"


def check_rate_window():
    # чистим окна перед проверкой
    prox._RATE_WINDOWS.clear()
    # окно пусто → слот есть
    assert prox._rate_slot("kfwl", time.monotonic() + 5)
    # заполняем окно до лимита
    limit = prox._RATE_PER_MIN["kfwl"]
    now = time.monotonic()
    window = prox._RATE_WINDOWS["kfwl"]
    for _ in range(limit):
        window.append(now - 0.1)
    # окно переполнено свежими метками → слота нет
    assert not prox._rate_slot("kfwl", time.monotonic() + 0.5)
    # старые метки (>60с) выпадают из окна → слот есть
    prox._RATE_WINDOWS["kfwl"].clear()
    for _ in range(limit):
        window.append(time.monotonic() - 61.0)
    assert prox._rate_slot("kfwl", time.monotonic() + 5)
    # сброс после проверки
    prox._RATE_WINDOWS.clear()


def check_prox_eligible():
    base = {"configs": [], "http_status": None, "conn_blocked": False}
    # гео-блок: 401/403/406/451
    for status in (401, 403, 406, 451):
        info = dict(base, http_status=status)
        assert _prox_eligible(info), status
    # 404 — мимо, объект не существует
    assert not _prox_eligible(dict(base, http_status=404))
    # обрыв соединения
    assert _prox_eligible(dict(base, conn_blocked=True))
    # 200 без конфигов — заглушка
    assert _prox_eligible(dict(base, http_status=200, configs=[]))
    # 200 с конфигами — источник живой
    assert not _prox_eligible(dict(base, http_status=200, configs=[CONFIG]))
    # выключенный Prox
    cfg.PROX_ENABLED = 0
    try:
        assert not _prox_eligible(dict(base, http_status=403))
    finally:
        cfg.PROX_ENABLED = 1


def check_happ_fallback_wiring():
    # локальный ключ знает маркер → фолбэк не вызывается
    # (реальная ссылка из локального набора расшифровывается на месте)
    from apex.utils import happ
    from apex.fetch import _extract_subscription_configs

    info = {"is_base64": False, "is_json": False, "is_yaml": False,
            "happ_decrypted": 0, "total_lines": 0}
    # мусорная happ-ссылка: локальный декрипт падает → фолбэк → сервис
    # недоступен (или замокан) → None → happ_decrypted не растёт
    garbage = "happ://crypt5/garbage-not-a-real-link"
    cfg.PROX_ENABLED = 0
    try:
        configs = _extract_subscription_configs(garbage, info, 0)
        assert configs == []
        assert info["happ_decrypted"] == 0
    finally:
        cfg.PROX_ENABLED = 1


def check_happ_fallback_local_stub():
    # happ_decrypt_fallback против локального стаб-сервера
    class Stub(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            payload = {
                "ok": True,
                "mode": "crypt5.2",
                "engine": "local",
                "result": "https://example.com/decrypted",
            }
            if body.get("link") != "happ://crypt5/test":
                payload = {"ok": False, "result": None}
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        prox._RATE_WINDOWS.clear()
        old_url = prox._HAPP_DECRYPT_URL
        prox._HAPP_DECRYPT_URL = f"http://127.0.0.1:{port}/v1/happ/decrypt"
        result = prox.happ_decrypt_fallback("happ://crypt5/test")
        assert result == "https://example.com/decrypted", result
        # битая ссылка → ok:false → None
        assert prox.happ_decrypt_fallback("happ://crypt5/bad") is None
    finally:
        prox._HAPP_DECRYPT_URL = old_url
        prox._RATE_WINDOWS.clear()
        srv.shutdown()


def check_prox_fetch_integration():
    # локальный стаб отдаёт 403 → _try_prox замокан → конфиги + маркер
    import apex.fetch as F

    class Stub(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/blocked":
                self.send_response(403)
                self.end_headers()
                return
            body = CONFIG.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    original_kameleon = cfg.KAMELEON_ENABLED
    original_fetch = F.prox_fetch
    cfg.KAMELEON_ENABLED = False
    F.prox_fetch = lambda url, timeout: CONFIG + "\n"
    try:
        info = F.fetch_single_url_with_details(
            f"http://127.0.0.1:{port}/blocked", retries=0
        )
        assert info["prox"], info
        assert len(info["configs"]) == 1, info
        assert info["http_status"] == 200
        assert info["error"] is None
    finally:
        F.prox_fetch = original_fetch
        cfg.KAMELEON_ENABLED = original_kameleon
        srv.shutdown()


def check_prox_fetch_disabled():
    import apex.fetch as F

    class Stub(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(403)
            self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    original_enabled = cfg.PROX_ENABLED
    cfg.PROX_ENABLED = 0
    try:
        info = F.fetch_single_url_with_details(
            f"http://127.0.0.1:{port}/blocked", retries=0
        )
        # Prox выключен → 403, конфигов нет, маркера нет
        assert not info["prox"], info
        assert info["configs"] == []
        assert info["http_status"] == 403
    finally:
        cfg.PROX_ENABLED = original_enabled
        srv.shutdown()
