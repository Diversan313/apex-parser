"""Проверки разбора ссылок: host/port/SNI, IPv6, port hopping, кривые ссылки."""
from apex.parse import (
    parse_host_port,
    parse_host_port_and_name,
    extract_sni_from_link,
)


def check_simple_host_port():
    host, port = parse_host_port("1.2.3.4:443")
    assert (host, port) == ("1.2.3.4", 443)
    # domain c параметрами и хвостом
    host, port = parse_host_port("a.b.com:2053/path?q=1")
    assert (host, port) == ("a.b.com", 2053)


def check_ipv6():
    host, port = parse_host_port("[2001:db8::1]:8443")
    assert host == "[2001:db8::1]" and port == 8443


def check_port_range():
    # port hopping: берём первый порт диапазона
    host, port = parse_host_port("1.2.3.4:443,5000-6000")
    assert port == 443
    _, port = parse_host_port("1.2.3.4:5000-6000")
    assert port == 5000


def check_name_and_sni():
    host, port, name = parse_host_port_and_name(
        "vless://u@1.2.3.4:443?sni=x.com&security=tls#%F0%9F%87%B3%20name"
    )
    assert host == "1.2.3.4" and port == 443
    assert "name" in name
    assert extract_sni_from_link("vless://u@1.2.3.4:443?sni=abc.com&type=tcp") == "abc.com"


def check_garbage():
    for junk in ("", "not a link", "vless://", "vmess://###"):
        host, port, name = parse_host_port_and_name(junk)
        assert not host and not port, junk
