"""Проверки Happ: round-trip на реальных ключах + извлечение ссылок из текста."""
import os
import random
import string

from apex.utils import happ


def _roundtrip(final: str) -> str:
    """Шифруем сами себя по crypt5 и расшифровываем нашим модулем."""
    import base64 as b64
    import json as json
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import padding as rpad
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    def b64e(b):
        return b64.b64encode(b).decode()

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

    keys_path = os.path.join("apex", "utils", "keys", "happ_keys.json")
    keys = json.load(open(keys_path, encoding="utf-8"))
    marker = list(keys["v5"].keys())[0]
    pem = f"-----BEGIN PRIVATE KEY-----\n{keys['v5'][marker]}\n-----END PRIVATE KEY-----"
    priv = ser.load_pem_private_key(pem.encode(), password=None)

    inter = swap_pairs(b64e(final.encode()))
    ck = os.urandom(32)
    nonce = "".join(random.choices(string.ascii_lowercase, k=12)).encode()
    seg = b64e(ChaCha20Poly1305(ck).encrypt(nonce, inter.encode(), None))
    rsa = b64e(priv.public_key().encrypt(swap_pairs(b64e(ck)).encode("latin-1"), rpad.PKCS1v15()))
    body = nonce.decode() + str(len(seg)) + "X" + seg + rsa
    enc = "happ://crypt5/" + swap_blocks(marker[:4] + body + marker[4:])

    dec = happ.decrypt_happ_link(enc)
    assert dec and final.strip() in dec, dec
    url = happ.happ_link_to_subscription_url(enc)
    assert url == final.strip(), url
    return enc


def check_crypt5_roundtrip():
    _roundtrip("https://example.com/checkbones-sub.txt\n")


def check_extract_from_text():
    enc = _roundtrip("https://example.com/x.txt\n")
    found = happ.extract_happ_links(f"текст до {enc} текст после")
    assert found == [enc]


def check_garbage_returns_none():
    assert happ.decrypt_happ_link("happ://crypt5/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") is None
    assert happ.happ_link_to_subscription_url("мусор") is None
