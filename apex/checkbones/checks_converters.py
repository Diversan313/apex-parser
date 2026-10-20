"""Проверки converters: Clash YAML и sing-box JSON -> share-ссылки."""
import base64
import json

from apex.utils.converters import (
    clash_proxy_to_link,
    foreign_yaml_to_links,
    singbox_outbound_to_link,
    singbox_json_to_links,
)
from apex.xray import link_to_xray_outbound
from apex.parse import parse_host_port_and_name


_CLASH_YAML = """proxies:
  - name: "reality node"
    type: vless
    server: 145.223.68.58
    port: 443
    uuid: edb50d20-2d3e-4c1e-8a75-a17168a89aa5
    flow: xtls-rprx-vision
    tls: true
    servername: www.apple.com
    client-fingerprint: firefox
    reality-opts:
      public-key: qc2DcqT9zPPZr6ePZ7ukxACW
      short-id: "0f4a1b2c"
    network: tcp
  - name: "ws node"
    type: vmess
    server: vm.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    alterId: 0
    cipher: auto
    tls: true
    servername: vm-sni.com
    network: ws
    ws-opts:
      path: /vmpath
      headers:
        Host: vmhost.com
  - name: "hy2"
    type: hysteria2
    server: hy.example.net
    port: 443
    ports: 443-8443
    password: hy2pass
    obfs: salamander
    obfs-password: salpass
    sni: hy-sni.net
    skip-cert-verify: true
  - name: "ssr"
    type: ssr
    server: 1.1.1.1
    port: 443
"""

_SINGBOX_JSON = json.dumps({
    "outbounds": [
        {"type": "direct", "tag": "direct"},
        {"type": "vless", "tag": "sb", "server": "1.2.3.4", "server_port": 443,
         "uuid": "u-1", "flow": "xtls-rprx-vision",
         "tls": {"enabled": True, "server_name": "x.com",
                 "utls": {"enabled": True, "fingerprint": "chrome"},
                 "reality": {"enabled": True, "public_key": "pbk1",
                             "short_id": ["sid1"]}},
         "transport": {"type": "ws", "path": "/sb", "headers": {"Host": "sbhost.com"}}},
        {"type": "shadowsocks", "tag": "ss", "server": "5.6.7.8", "server_port": 8388,
         "method": "aes-256-gcm", "password": "sspass",
         "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=obfshost.com"},
    ]
})


def _parses(link, host, port):
    ob = link_to_xray_outbound(link)
    h, p, _ = parse_host_port_and_name(link)
    return ob is not None and h == host and p == port


def check_clash_yaml_to_links():
    links = foreign_yaml_to_links(_CLASH_YAML)
    # ssr не поддержан, остальные три должны конвертироваться
    assert len(links) == 3, links
    reality = [l for l in links if "145.223.68.58" in l][0]
    assert "security=reality" in reality and "pbk=qc2DcqT9zPPZr6ePZ7ukxACW" in reality
    assert "sid=0f4a1b2c" in reality and "fp=firefox" in reality
    assert _parses(reality, "145.223.68.58", 443)

    vm = [l for l in links if l.startswith("vmess://")][0]
    payload = json.loads(base64.b64decode(vm[len("vmess://"):]))
    assert payload["net"] == "ws" and payload["path"] == "/vmpath"
    assert payload["host"] == "vmhost.com" and payload["tls"] == "tls"
    assert _parses(vm, "vm.example.com", 443)

    hy2 = [l for l in links if l.startswith("hysteria2://")][0]
    assert "obfs=salamander" in hy2 and "obfs-password=salpass" in hy2
    assert "insecure=1" in hy2
    assert _parses(hy2, "hy.example.net", 443)


def check_singbox_json_to_links():
    links = singbox_json_to_links(_SINGBOX_JSON)
    # direct пропущен, vless+ss сконвертированы
    assert len(links) == 2, links
    vless = [l for l in links if l.startswith("vless://")][0]
    assert "security=reality" in vless and "pbk=pbk1" in vless and "sid=sid1" in vless
    assert "type=ws" in vless and "host=sbhost.com" in vless
    assert _parses(vless, "1.2.3.4", 443)

    ss = [l for l in links if l.startswith("ss://")][0]
    assert "plugin=obfs-local%3Bobfs%3Dhttp" in ss
    assert _parses(ss, "5.6.7.8", 8388)


def check_unsupported_skipped():
    # незнакомый ss-плагин не должен превращаться в битую ссылку
    link = clash_proxy_to_link({
        "name": "x", "type": "ss", "server": "1.2.3.4", "port": 443,
        "cipher": "aes-128-gcm", "password": "p",
        "plugin": "shadow-tls", "plugin-opts": {"version": 3},
    })
    assert link is None
    # quic-транспорт sing-box нашим диалектом не выражается
    link = singbox_outbound_to_link({
        "type": "vless", "server": "1.2.3.4", "server_port": 443, "uuid": "u",
        "transport": {"type": "quic"},
    })
    assert link is None
