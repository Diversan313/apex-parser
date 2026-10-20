"""Проверки white_ip.txt: смешанный формат (IP + CIDR + домены), защита от стирания."""
import os
import tempfile

import apex.incoming as incoming


def check_white_line_valid():
    assert incoming._white_line_valid("1.2.3.4")
    assert incoming._white_line_valid("1.2.3.0/24")
    assert incoming._white_line_valid("2a00:1450:4001::/48")
    assert incoming._white_line_valid("example.com")
    assert not incoming._white_line_valid("")
    assert not incoming._white_line_valid("# комментарий")
    assert not incoming._white_line_valid("404: Not Found")
    assert not incoming._white_line_valid("1.2.3.4:443")


def _tmp_white_file(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def check_load_white_mixed():
    # смесь IP и CIDR: подсети должны сохраниться строками, а не резолвиться
    path = _tmp_white_file("9.9.9.9\n1.2.3.0/24\n\n# комментарий\n8.8.8.8\n")
    orig = incoming.WHITE_IP_FILE
    incoming.WHITE_IP_FILE = path
    try:
        ips, networks = incoming.load_white_ips()
        assert ips == {"9.9.9.9", "8.8.8.8"}, ips
        assert networks == ["1.2.3.0/24"], networks
    finally:
        incoming.WHITE_IP_FILE = orig
        os.remove(path)


def check_save_white_guard_and_roundtrip():
    path = _tmp_white_file("9.9.9.9\n")
    orig = incoming.WHITE_IP_FILE
    incoming.WHITE_IP_FILE = path
    try:
        # пустая база не стирает файл: сбой скачивания/чтения не должен
        # уничтожить базу, на которую опирается следующий прогон
        incoming.save_white_ips(set(), [])
        with open(path, "r", encoding="utf-8") as f:
            assert f.read().strip() == "9.9.9.9"

        # непустая база: подсети + IP, roundtrip не теряет содержимое
        incoming.save_white_ips({"8.8.8.8", "9.9.9.9"}, ["1.2.3.0/24"])
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        assert lines == ["1.2.3.0/24", "8.8.8.8", "9.9.9.9"], lines
    finally:
        incoming.WHITE_IP_FILE = orig
        os.remove(path)
