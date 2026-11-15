"""Проверки расширенных белых источников: twl-список, ASN-порог, гейт WL."""
import ipaddress
import json
import os
import tempfile

from apex import config as cfg
from apex import white_extra
from apex.classify import classify_config


class _StubReader:
    """Заглушка maxminddb-ридера: фиксированная таблица «ip → ASN»."""

    def __init__(self, table):
        self._table = table

    def get(self, ip):
        return self._table.get(str(ip))


def check_twl_load_and_membership():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    saved = (
        cfg.TWL_WHITE_FILE,
        cfg.TWL_WHITE_ENABLED,
        white_extra._TWL_IPS,
        white_extra._TWL_NETS,
    )
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [{"cidr": "203.0.113.0/24", "ips": ["203.0.113.5", "203.0.113.6"]}],
                f,
            )
        cfg.TWL_WHITE_FILE = path
        cfg.TWL_WHITE_ENABLED = 1
        white_extra._TWL_IPS = set()
        white_extra._TWL_NETS = []
        white_extra._load_twl()
        assert white_extra.ip_in_twl("203.0.113.5")
        assert not white_extra.ip_in_twl("198.51.100.1")
        assert len(white_extra._TWL_NETS) == 1
    finally:
        (
            cfg.TWL_WHITE_FILE,
            cfg.TWL_WHITE_ENABLED,
            white_extra._TWL_IPS,
            white_extra._TWL_NETS,
        ) = saved


def check_asn_threshold():
    nets = [
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("203.0.114.0/24"),
        ipaddress.ip_network("203.0.115.0/24"),
    ]
    table = {
        "203.0.113.0": {"autonomous_system_number": 64496},
        "203.0.114.0": {"autonomous_system_number": 64496},
        "203.0.115.0": {"autonomous_system_number": 64496},
        "203.0.116.0": {"autonomous_system_number": 64497},
    }
    assert white_extra._count_trusted(_StubReader(table), nets, 3) == {64496}
    assert white_extra._count_trusted(_StubReader(table), nets[:2], 3) == set()


def check_is_asn_white():
    saved = (white_extra._ASN_READER, white_extra._TRUSTED_ASN)
    try:
        white_extra._ASN_READER = _StubReader(
            {"203.0.113.5": {"autonomous_system_number": 64496}}
        )
        white_extra._TRUSTED_ASN = {64496}
        assert white_extra.is_asn_white("203.0.113.5")
        assert not white_extra.is_asn_white("198.51.100.1")
    finally:
        white_extra._ASN_READER, white_extra._TRUSTED_ASN = saved


def check_white_gate_classification():
    saved_twl = white_extra._TWL_IPS
    saved_gate = cfg.WL_ONLY_WHITE_IP
    empty = set()
    try:
        white_extra._TWL_IPS = {int(ipaddress.ip_address("1.2.3.4"))}
        cfg.WL_ONLY_WHITE_IP = 1
        # twl-вход литеральным IP -> WL даже без ключевых слов
        assert classify_config("vless://u@1.2.3.4:443?type=tcp", empty, 0.0) == "WL"
        # домен в twl/ASN-слое не проверяется (только литеральный IP) -> BL
        assert (
            classify_config("vless://u@twl.example.com:443?type=tcp", empty, 0.0)
            == "BL"
        )
        # ключевые слова без белого входа гейтит в BL
        assert (
            classify_config(
                "vless://u@9.9.9.9:443?type=tcp#белый список lte", empty, 0.0
            )
            == "BL"
        )
        # без гейта ключевые слова дают WL как раньше
        cfg.WL_ONLY_WHITE_IP = 0
        assert (
            classify_config(
                "vless://u@9.9.9.9:443?type=tcp#белый список lte", empty, 0.0
            )
            == "WL"
        )
    finally:
        white_extra._TWL_IPS = saved_twl
        cfg.WL_ONLY_WHITE_IP = saved_gate
