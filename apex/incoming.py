"""White IP, локальные/remote sources helpers, прошлые alive."""
from __future__ import annotations

import ipaddress
import os
import urllib.request
from typing import List, Set, Tuple

from .config import (
    WHITE_IP_FILE,
    WHITE_IP_URL,
    SECURE_SOURCES_GITHUB,
    SPLIT_SOURCES,
    SOURCES_DIR,
    SUPPORTED_PROTOCOLS,
    KEEP_PREV_ALIVES,
    HEADERS,
    SSL_CONTEXT,
    DOMAIN_REGEX,
)
from . import config as cfg
from .utils import safe_b64decode, sanitize_v2rayng_link
from .parse import parse_ip_or_resolve


def resolve_source_files() -> Tuple[str, str]:
    """
    Возвращает (wl_path, bl_path).

    SECURE_SOURCES_GITHUB=True  → файлы в корне (workflow скачал из private)
    SECURE_SOURCES_GITHUB=False → apex/sources/
    SPLIT_SOURCES=True  → sources_wl.txt + sources_bl.txt
    SPLIT_SOURCES=False → один sources.txt для обоих
    """
    base = "" if SECURE_SOURCES_GITHUB else SOURCES_DIR

    if SPLIT_SOURCES:
        wl = os.path.join(base, "sources_wl.txt") if base else "sources_wl.txt"
        bl = os.path.join(base, "sources_bl.txt") if base else "sources_bl.txt"
        # fallback старых имён
        if not os.path.exists(wl) and os.path.exists(
            os.path.join(base, "source_wl.txt") if base else "source_wl.txt"
        ):
            wl = os.path.join(base, "source_wl.txt") if base else "source_wl.txt"
        if not os.path.exists(bl) and os.path.exists(
            os.path.join(base, "source_bl.txt") if base else "source_bl.txt"
        ):
            bl = os.path.join(base, "source_bl.txt") if base else "source_bl.txt"
        # парных файлов нет, но лежит общий sources.txt - работаем по нему
        single = os.path.join(base, "sources.txt") if base else "sources.txt"
        if not os.path.exists(wl) and not os.path.exists(bl) and os.path.exists(single):
            return single, single
        return wl, bl

    single = os.path.join(base, "sources.txt") if base else "sources.txt"
    return single, single


def _white_line_valid(line: str) -> bool:
    """Строка white_ip.txt — отдельный IP, CIDR-подсеть или домен?"""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    try:
        ipaddress.ip_address(line)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(line, strict=False)
        return True
    except ValueError:
        pass
    return bool(DOMAIN_REGEX.match(line))


def download_white_ip() -> None:
    """
    Если WHITE_IP_URL задан — скачивает и перезаписывает локальный white_ip.txt.
    Если URL пустой — ничего не делает (остаётся локальный файл).

    Тело с ошибкой («404: Not Found» и т.п.) или без единой валидной
    строки не перезаписывает базу: этот файл — основа WL-классификации,
    один кривой ответ не должен её стирать.
    """
    url = (WHITE_IP_URL or "").strip()
    if not url:
        print("📂 WHITE_IP_URL пуст — используем только локальный white_ip.txt")
        return

    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30, context=SSL_CONTEXT) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        if not data.strip():
            print("⚠️ Remote white_ip пуст — локальный файл не трогаем")
            return
        lines = [
            ln.strip()
            for ln in data.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        valid = [ln for ln in lines if _white_line_valid(ln)]
        if not valid:
            print("⚠️ Remote white_ip без единого валидного IP/подсети — локальный файл не трогаем")
            return
        with open(WHITE_IP_FILE, "w", encoding="utf-8") as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")
        print(f"📥 White IP скачан с remote: {len(valid)} валидных строк → {WHITE_IP_FILE}")
    except Exception as e:
        print(f"⚠️ Не удалось скачать white_ip: {e} — используем локальный файл")


def load_white_ips() -> Tuple[Set[str], List[str]]:
    """
    Читает локальный white_ip.txt: отдельные IP (+ резолв доменов)
    и CIDR-подсети.

    Файл может содержать смесь «1.2.3.4», «1.2.3.0/24» и доменов.
    Подсети храним исходными строками: save должен вернуть в файл то же
    содержимое, а не только резолвнутые адреса.
    """
    white_ips: Set[str] = set()
    white_networks: List[str] = []
    if not os.path.exists(WHITE_IP_FILE):
        return white_ips, white_networks
    try:
        with open(WHITE_IP_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" in line:
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        continue
                    net_str = str(net)
                    if net_str not in white_networks:
                        white_networks.append(net_str)
                    continue
                white_ips.update(parse_ip_or_resolve(line))
    except Exception as e:
        print(f"⚠️ Ошибка чтения {WHITE_IP_FILE}: {e}")
    return white_ips, white_networks


def save_white_ips(white_ips: Set[str], white_networks: List[str] = None) -> None:
    """Пишет отсортированный white_ip.txt: подсети + отдельные IP.

    Пустую базу не записываем: сбой при скачивании или чтении не должен
    стирать файл, на который опирается следующий прогон.
    """
    white_networks = list(white_networks or [])
    if not white_ips and not white_networks:
        print("⚠️ White IP база пуста — файл не перезаписываем")
        return

    def net_sort_key(net):
        try:
            return (0, ipaddress.ip_network(net, strict=False))
        except ValueError:
            return (1, net)

    def ip_sort_key(ip):
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    with open(WHITE_IP_FILE, "w", encoding="utf-8") as f:
        for net in sorted(set(white_networks), key=net_sort_key):
            f.write(net + "\n")
        for ip in sorted(set(white_ips), key=ip_sort_key):
            f.write(ip + "\n")


# ============================================================
# PREVIOUS ALIVES
# ============================================================

def load_previous_alives():

    prev_wl = []
    prev_bl = []

    if not KEEP_PREV_ALIVES:
        print(
            "📂 KEEP_PREV_ALIVES=False — "
            "прошлые alive не загружаем"
        )
        return (
            prev_wl,
            prev_bl,
        )

    if os.path.exists(
        "subs/main/alive_bs.txt"
    ):

        try:

            with open(
                "subs/main/alive_bs.txt",
                "r",
                encoding="utf-8",
            ) as f:

                decoded = (
                    safe_b64decode(
                        f.read()
                    )
                )

            prev_wl = [
                sanitize_v2rayng_link(
                    l.strip()
                )
                for l in decoded.splitlines()
                if l.strip().startswith(
                    SUPPORTED_PROTOCOLS
                )
            ]

        except Exception:
            pass

    if os.path.exists(
        "subs/main/alive_bl.txt"
    ):

        try:

            with open(
                "subs/main/alive_bl.txt",
                "r",
                encoding="utf-8",
            ) as f:

                decoded = (
                    safe_b64decode(
                        f.read()
                    )
                )

            prev_bl = [
                sanitize_v2rayng_link(
                    l.strip()
                )
                for l in decoded.splitlines()
                if l.strip().startswith(
                    SUPPORTED_PROTOCOLS
                )
            ]

        except Exception:
            pass

    print(
        f"📂 Загружено из прошлых файлов: "
        f"WL={len(prev_wl)}, "
        f"BL={len(prev_bl)}"
    )

    return (
        prev_wl,
        prev_bl,
    )
