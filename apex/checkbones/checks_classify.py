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


def check_unsafe_verify_variants():
    # все варианты отключения серверной валидации сертификата
    base = "vless://u@1.2.3.4:443?type=tcp&security=tls&verify="
    for bad in ("0", "false", "no", "off", "FALSE", "Off"):
        assert is_unsafe_config(base + bad), bad
    assert not is_unsafe_config(base + "1")
    assert not is_unsafe_config("vless://u@1.2.3.4:443?type=tcp&security=tls")


def check_white_network_index():
    from apex.classify import build_white_network_index, ip_in_white_networks

    idx = build_white_network_index([
        "1.2.3.0/24",
        "5.6.7.8/32",
        "не-подсеть",
        "2001:db8::/32",
    ])
    assert ip_in_white_networks("1.2.3.99", idx)
    assert ip_in_white_networks("1.2.3.4", idx)
    assert ip_in_white_networks("5.6.7.8", idx)
    assert ip_in_white_networks("2001:db8::1", idx)
    assert not ip_in_white_networks("1.2.4.1", idx)
    assert not ip_in_white_networks("8.8.8.8", idx)
    assert not ip_in_white_networks("не-ip", idx)
    assert not ip_in_white_networks("1.2.3.99", None)

    # пересекающиеся подсети: без слияния интервалов bisect по «хвостовой»
    # сети давал ложный промах на адресах старшей
    idx2 = build_white_network_index(["100.64.0.0/10", "100.100.0.0/16"])
    assert ip_in_white_networks("100.120.1.1", idx2)
    assert ip_in_white_networks("100.100.5.5", idx2)
    assert not ip_in_white_networks("100.128.0.1", idx2)


def check_host_white_dns_tier():
    # домен с резолвом из DNS-кэша в белой базе должен уходить в WL,
    # а не гибнуть в BL; сама классификация в сеть не ходит
    from apex.classify import host_in_white_ips, build_white_network_index, classify_config
    from apex.config import DNS_CACHE, DNS_LOCK

    host_a = "apex-check-a.example.com"
    host_b = "apex-check-b.example.com"
    link_a = f"vless://u@{host_a}:443?type=tcp&security=tls#t"
    link_b = f"vless://u@{host_b}:443?type=tcp&security=tls#t"
    try:
        with DNS_LOCK:
            DNS_CACHE[host_a] = "203.0.113.10"
            DNS_CACHE[host_b] = "198.51.100.77"

        # резолв из кэша попал в белый IP
        assert host_in_white_ips(link_a, {"203.0.113.10"}, None)
        # резолв из кэша попал в CIDR-подсеть базы
        idx = build_white_network_index(["198.51.100.0/24"])
        assert host_in_white_ips(link_b, set(), idx)

        # холодный кэш: без сетевого резолва, быстрый отказ
        link_c = "vless://u@apex-check-c.example.com:443?type=tcp&security=tls#t"
        assert not host_in_white_ips(link_c, {"203.0.113.10"}, None)

        # классификация через DNS-уровень уходит в WL
        assert classify_config(link_a, {"203.0.113.10"}, 0.0, None) == "WL"
        assert classify_config(link_b, set(), 0.0, idx) == "WL"

        # литеральный IP-хост внутри подсети базы
        link_ip = "vless://u@198.51.100.9:443?type=tcp&security=tls#t"
        assert host_in_white_ips(link_ip, set(), idx)
        assert classify_config(link_ip, set(), 0.0, idx) == "WL"
    finally:
        with DNS_LOCK:
            DNS_CACHE.pop(host_a, None)
            DNS_CACHE.pop(host_b, None)
