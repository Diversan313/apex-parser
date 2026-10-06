"""Проверки классификации: порядок правил WL/BL и небезопасные конфиги."""
import base64

from apex.classify import classify_config, is_unsafe_config


def _vmess(d: str) -> str:
    return "vmess://" + base64.b64encode(d.encode()).decode()


def check_classification_order():
    empty = set()
    # 1. невалидный host -> BL
    assert classify_config("vless://u@bad host:443?security=tls", empty, 0.0) == "BL"
    # 3. BL-keywords сильнее WL-keywords
    link = "vless://u@1.2.3.4:443?type=tcp#блэклист обход"
    assert classify_config(link, empty, 0.0) == "BL"
    # 4. WL-keywords -> WL
    assert classify_config("vless://u@1.2.3.4:443?type=tcp#белый список lte", empty, 0.0) == "WL"
    # 8. ничего не подошло -> BL
    assert classify_config("vless://u@1.2.3.4:443?type=tcp", empty, 0.0) == "BL"


def check_unsafe_vless():
    assert is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=none")
    assert is_unsafe_config("vless://u@1.2.3.4:443?type=tcp")
    assert is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=tls&allowInsecure=1")
    assert is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=tls&allowinsecure=true")
    assert is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=tls&skip-cert-verify=1")
    # xtls - это шифрование, не флагается
    assert not is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=xtls&flow=xtls-rprx-direct")
    assert not is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=K&sid=s&sni=x.com")


def check_unsafe_vmess():
    bad = _vmess('{"add":"1.2.3.4","port":"443","id":"x","tls":"","net":"tcp"}')
    assert is_unsafe_config(bad)
    bad_scy = _vmess('{"add":"1.2.3.4","port":"443","id":"x","tls":"tls","scy":"none","net":"tcp"}')
    assert is_unsafe_config(bad_scy)
    bad_aid = _vmess('{"add":"1.2.3.4","port":"443","id":"x","tls":"tls","aid":64,"net":"tcp"}')
    assert is_unsafe_config(bad_aid)
    good = _vmess('{"add":"1.2.3.4","port":"443","id":"x","tls":"tls","aid":0,"net":"tcp"}')
    assert not is_unsafe_config(good)


def check_unsafe_ss():
    # rc4-md5 в base64-userinfo
    assert is_unsafe_config("ss://cmM0LW1kNTpwYXNz@1.2.3.4:8388#t")
    # aes-256-cfb в plain userinfo
    assert is_unsafe_config("ss://aes-256-cfb:pass@1.2.3.4:8388#t")
    # SS2022 с кривой длиной ключа
    assert is_unsafe_config("ss://2022-blake3-aes-256-gcm:YWJj@1.2.3.4:8388#t")
    # AEAD проходит
    import base64 as b
    good_user = b.b64encode(b"aes-256-gcm:pass").decode()
    assert not is_unsafe_config(f"ss://{good_user}@1.2.3.4:8388#t")
    # SS2022 валидный ключ (32 байта) и мультиключ
    key32 = b.b64encode(b"A" * 32).decode()
    assert not is_unsafe_config(f"ss://2022-blake3-aes-256-gcm:{key32}@1.2.3.4:8388#t")
    assert not is_unsafe_config(f"ss://2022-blake3-aes-256-gcm:{key32}:psk2@1.2.3.4:8388#t")


def check_unsafe_hy2_trojan():
    assert is_unsafe_config("hysteria2://p@1.2.3.4:443?sni=x&insecure=1")
    assert is_unsafe_config("hysteria2://p@1.2.3.4:443?sni=x&insecure=true")
    assert not is_unsafe_config("hysteria2://p@1.2.3.4:443?sni=x.com")
    assert is_unsafe_config("trojan://p@1.2.3.4:443?security=tls&sni=x&skip-cert-verify=1")
    assert not is_unsafe_config("trojan://p@1.2.3.4:443?security=tls&sni=x.com")
