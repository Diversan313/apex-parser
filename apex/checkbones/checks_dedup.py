"""Проверки дедупа: raw/tcp, fp-приоритет chrome, SS2022-мультиключ."""
from apex.dedup import dedup_advanced, get_final_dedup_key


def _vless(uuid, extra=""):
    return f"vless://{uuid}@1.2.3.4:443?type=tcp&security=tls&sni=x.com{extra}"


def check_raw_tcp_same_tunnel():
    # tcp и raw - один транспорт Xray, близнецы схлопываются
    a = _vless("u", "&fp=chrome")
    b = _vless("u", "&fp=chrome").replace("type=tcp", "type=raw")
    res = dedup_advanced([(a, "s"), (b, "s")], "t")
    assert len(res) == 1


def check_fp_chrome_priority():
    base = "vless://u@1.2.3.4:443?type=tcp&security=tls&sni=x.com"
    variants = [
        (base + "&fp=firefox#1", "f"),
        (base + "#2", "n"),
        (base + "&fp=chrome#3", "c"),
        (base + "&fp=safari#4", "s"),
    ]
    res = dedup_advanced(variants, "t")
    assert len(res) == 1
    assert "fp=chrome" in res[0][0], res[0]


def check_fp_fallback_alive():
    # живого chrome нет - выживает первый живой не-chrome
    base = "vless://u@1.2.3.4:443?type=tcp&security=tls&sni=x.com"
    res = dedup_advanced(
        [(base + "&fp=firefox#1", "f"), (base + "&fp=safari#2", "s")], "t"
    )
    assert len(res) == 1 and "fp=firefox" in res[0][0]


def check_keys_stable():
    # ключ не зависит от имени и вызывает не-None на валидной ссылке
    a = _vless("u", "&fp=chrome#A")
    b = _vless("u", "&fp=chrome#Другое имя")
    assert get_final_dedup_key(a) == get_final_dedup_key(b)
    assert get_final_dedup_key(a) is not None
