"""Проверки Kameleon: личности, заголовки, подбор маски на заглушке сервера."""
import http.server
import random
import threading

from apex.utils.kameleon import (
    available_apps,
    available_oses,
    fetch_kameleon,
    identity_headers,
    parse_csv,
    random_identity,
)


def check_parse_csv():
    assert parse_csv("happ, v2raytun ,INCY") == ["happ", "v2raytun", "incy"]
    assert parse_csv("") == []
    assert parse_csv(None) == []


def check_apps_from_config():
    # конфиг - источник правды; пустые списки = весь встроенный набор
    assert "happ" in available_apps()
    assert "android" in available_oses()


def check_identity_variety():
    import apex.utils.kameleon as k
    ids = [k.random_identity() for _ in range(50)]
    uas = {i.user_agent() for i in ids}
    assert len(uas) >= 20, f"слишком мало уникальных UA: {len(uas)}"
    for ua in uas:
        assert any(
            ua.startswith(p)
            for p in ("Happ/", "v2raytun/", "INCY/", "Streisand/", "V2Box/", "Hiddify/")
        ), ua


def check_identity_headers():
    from apex.utils.kameleon import Identity
    idn = Identity(app="happ", os="ios", version="3.24.0", hwid="a1b2c3d4e5f67890")
    h = identity_headers(idn)
    assert h["User-Agent"].startswith("Happ/3.24.0/iOS/")
    assert h["X-HWID"] == "a1b2c3d4e5f67890" == h["X-Device-Id"]
    assert h["X-Device-OS"] == "ios"


SLOW = True


def check_masquerade_picks_identity():
    """Сервер пускает только Happ-клиентов: Kameleon обязан подобрать маску."""
    CONFIG = "vless://uuid@1.2.3.4:443?type=tcp&security=tls#t1"

    class OnlyHapp(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            body = (CONFIG if ua.startswith("Happ/") else "denied").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OnlyHapp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        content = fetch_kameleon(f"http://127.0.0.1:{srv.server_address[1]}/sub")
        assert content and "vless://uuid" in content
    finally:
        srv.shutdown()
