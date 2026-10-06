"""Проверки fetch: fix_github_url, транзиентные ошибки, извлечение конфигов, SSL-заглушки."""
import base64
import http.server
import ssl
import tempfile
import threading
import datetime
import os
import sys
import urllib.error

from apex.fetch import (
    _extract_subscription_configs,
    _is_transient_error,
    fetch_single_url_with_details,
    fix_github_url,
)


def check_github_url_fix():
    commit = "0123456789abcdef0123456789abcdef01234567"
    assert fix_github_url(
        f"https://raw.githubusercontent.com/u/r/commit/{commit}/f.txt"
    ) == "https://raw.githubusercontent.com/u/r/main/f.txt"
    # обычные ссылки не трогаются
    same = "https://raw.githubusercontent.com/u/r/main/f.txt"
    assert fix_github_url(same) == same


def check_transient_classification():
    e404 = urllib.error.HTTPError("u", 404, "Not Found", None, None)
    e429 = urllib.error.HTTPError("u", 429, "Too Many", None, None)
    e503 = urllib.error.HTTPError("u", 503, "Busy", None, None)
    assert not _is_transient_error(e404)
    assert _is_transient_error(e429)
    assert _is_transient_error(e503)
    import socket
    assert _is_transient_error(socket.timeout())


def check_extract_plain_and_b64():
    info = {"is_base64": False, "is_json": False, "happ_decrypted": 0, "total_lines": 0}
    link = "vless://u@1.2.3.4:443?type=tcp&security=tls#t1"
    got = _extract_subscription_configs(link, info, 0)
    assert len(got) == 1 and "vless://u@1.2.3.4" in got[0]
    b64 = base64.b64encode((link + "\n").encode()).decode()
    got = _extract_subscription_configs(b64, info, 0)
    assert len(got) == 1 and info["is_base64"]


def check_extract_vmess():
    info = {"is_base64": False, "is_json": False, "happ_decrypted": 0, "total_lines": 0}
    raw = '{"add":"1.2.3.4","port":"443","id":"x","tls":"tls","net":"ws","path":"/w"}'
    link = "vmess://" + base64.b64encode(raw.encode()).decode()
    got = _extract_subscription_configs(link, info, 0)
    assert got and got[0].startswith("vmess://")


# --- серверные заглушки (тяжёлый пакет: SLOW) ---

SLOW = True

CONFIG = "vless://uuid@1.2.3.4:443?type=tcp&security=tls#t1"


class _Stub(http.server.BaseHTTPRequestHandler):
    hits = {"404": 0, "flaky": 0}

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/404":
            self.hits["404"] += 1
            self.send_response(404)
            self.end_headers()
        elif self.path == "/flaky":
            self.hits["flaky"] += 1
            if self.hits["flaky"] == 1:
                self.send_response(429)
                self.end_headers()
            else:
                body = CONFIG.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            body = CONFIG.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _start_stub():
    _Stub.hits = {"404": 0, "flaky": 0}
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def check_no_retry_on_404():
    srv, port = _start_stub()
    try:
        info = fetch_single_url_with_details(f"http://127.0.0.1:{port}/404", retries=3)
        assert _Stub.hits["404"] == 1  # перманентный фейл без ретраев
        assert info["configs"] == []
    finally:
        srv.shutdown()


def check_retry_on_429():
    srv, port = _start_stub()
    try:
        info = fetch_single_url_with_details(f"http://127.0.0.1:{port}/flaky", retries=3)
        assert info["configs"], info
    finally:
        srv.shutdown()


def check_happ_decrypt_roundtrip():
    from apex.utils import happ

    link = (
        "vless://u@1.2.3.4:443?type=tcp&security=tls#n"
    )
    # шифруем сами себя по crypt5 на реальных ключах и расшифровываем
    import json as _json
    import base64 as _b64
    import os as _os
    import random as _random
    import string as _string
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import padding as _rpad
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    def b64e(b):
        return _b64.b64encode(b).decode()

    def swap_pairs(s):
        a = list(s)
        for i in range(0, len(a) - 1, 2):
            a[i], a[i + 1] = a[i + 1], a[i]
        return "".join(a)

    def swap_blocks(s):
        head = len(s) - (len(s) % 4)
        out = []
        for off in range(0, head, 4):
            out.append(s[off + 2: off + 4])
            out.append(s[off: off + 2])
        out.append(s[head:])
        return "".join(out)

    keys = _json.load(open(os.path.join("apex", "utils", "keys", "happ_keys.json"), encoding="utf-8"))
    marker = list(keys["v5"].keys())[0]
    pem = f"-----BEGIN PRIVATE KEY-----\n{keys['v5'][marker]}\n-----END PRIVATE KEY-----"
    priv = _ser.load_pem_private_key(pem.encode(), password=None)

    final = "https://example.com/sub-checkbones.txt\n"
    inter = swap_pairs(b64e(final.encode()))
    ck = _os.urandom(32)
    nonce = "".join(_random.choices(_string.ascii_lowercase, k=12)).encode()
    seg = b64e(ChaCha20Poly1305(ck).encrypt(nonce, inter.encode(), None))
    rsa = b64e(priv.public_key().encrypt(swap_pairs(b64e(ck)).encode("latin-1"), _rpad.PKCS1v15()))
    body = nonce.decode() + str(len(seg)) + "X" + seg + rsa
    enc_link = "happ://crypt5/" + swap_blocks(marker[:4] + body + marker[4:])

    url = happ.happ_link_to_subscription_url(enc_link)
    assert url == final.strip(), url
