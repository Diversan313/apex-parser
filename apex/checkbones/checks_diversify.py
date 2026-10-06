"""Проверки sanitize/rename/YAML: HEAL, белый список параметров, теги."""
import urllib.parse
import yaml

from apex.diversify import (
    filter_protocols_bl,
    links_to_clash_yaml,
    rename_config,
    sanitize_proxy_link,
)


def check_param_whitelist():
    s = sanitize_proxy_link(
        "vless://u@1.2.3.4:443?encryption=none&security=reality&pbk=K&sid=s"
        "&sni=x.com&type=tcp&flow=xtls-rprx-vision&source_name=junk&provider_id=junk#t"
    )
    assert "source_name" not in s and "provider_id" not in s
    for keep in ("encryption=none", "flow=xtls-rprx-vision", "pbk=K", "sid=s", "sni=x.com", "type=tcp"):
        assert keep in s, (keep, s)


def check_legit_params_survive():
    cases = [
        ("vless://u@1.2.3.4:443?type=ws&security=tls&sni=x&path=%2Fws&ed=2048&eh=Sec-WebSocket-Protocol#t", ["ed", "eh"]),
        ("vless://u@1.2.3.4:443?type=kcp&security=tls&seed=sd&headerType=srtp#t", ["seed"]),
        ("ss://YWVzLTEyOC1nY206cHc@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#t", ["plugin"]),
        ("trojan://p@1.2.3.4:443?security=tls&servername=x.com&peer=x.com#t", ["servername", "peer"]),
        ("hysteria2://p@1.2.3.4:443,5000?sni=x&mport=443-5000#t", ["mport"]),
        ("vless://u@1.2.3.4:443?security=reality&pbk=K&sid=s&sni=x&type=tcp&spx=%2F#t", ["spx"]),
    ]
    for link, need in cases:
        s = sanitize_proxy_link(link)
        ps = set(urllib.parse.parse_qs(s.split("?", 1)[1]).keys()) if "?" in s else set()
        for k in need:
            assert k in ps, (k, s)


def check_heal_ads():
    s = sanitize_proxy_link(
        "vless://u@1.2.3.4:443?security=reality&type=tcp"
        "&host=%2F%3FTELEGRAM--X--X--X&sni=x.com&pbk=K&sid=s#t"
    )
    assert "host=" not in s and "TELEGRAM" not in s
    # bandwidth не режется
    s2 = sanitize_proxy_link("hysteria2://p@1.2.3.4:443?up=50 mbps&down=200 mbps&sni=x#t")
    assert "up=50" in s2 and "mbps" in s2


def check_rename_tags():
    # суффикс /CF внутри скобки и отключается
    item = ("vless://u@1.2.3.4:443?type=tcp&security=tls&sni=x.com#n", "🇺🇸", "s", "US", "104.16.1.1", 100)
    from apex.main import _wl_bl_tag_fn, _item_exit_ip
    from apex.dedup import get_final_dedup_key
    from apex import config as cfg

    wl_keys = {get_final_dedup_key(item[0])}
    tag = _wl_bl_tag_fn(wl_keys)
    assert tag(item) == "[WL/CF]"
    cfg.RENAME_CF_SUFFIX = ""
    assert tag(item) == "[WL]"
    cfg.RENAME_CF_SUFFIX = "CF"

    # rename рендерит имя по шаблону
    renamed = rename_config(item[0], 1, tag(item), "🇺🇸")
    assert "#🇺🇸 [WL/CF] Сервер 1" in renamed or "%5BWL%2FCF%5D" in renamed


def check_yaml_valid():
    links = [
        "vless://u@1.2.3.4:443?type=ws&security=tls&sni=x.com&path=%2Fws#A",
        "vless://u@2.2.2.2:443?type=tcp&security=reality&pbk=K&sid=s&sni=y.com#B",
        "hysteria2://p@3.3.3.3:443?sni=z.com#C",
        "ss://YWVzLTI1Ni1nY206cGFzcw@4.4.4.4:8388#D",
    ]
    doc = yaml.safe_load(links_to_clash_yaml(links))
    assert doc and "proxies" in doc and len(doc["proxies"]) == 4
    by_type = {p["type"] for p in doc["proxies"]}
    assert by_type == {"vless", "hysteria2", "ss"}


def check_bl_protocol_filter():
    # приоритет vless/hy2, старые режутся по доле
    items = [("vless://a@1.1.1.1:1#x", "f")] * 90 + [("vmess://" + "x" * 40, "f")] * 50
    out = filter_protocols_bl(items, minority_ratio=0.10)
    assert len(out) == 100  # 90 приоритетных + 10 старых (max(10, 10% от 90))
