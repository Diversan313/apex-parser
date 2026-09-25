"""White IP, локальные/remote sources helpers, прошлые alive."""
from __future__ import annotations

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
        return wl, bl

    single = os.path.join(base, "sources.txt") if base else "sources.txt"
    return single, single


def download_white_ip() -> None:
    """
    Если WHITE_IP_URL задан — скачивает и перезаписывает локальный white_ip.txt.
    Если URL пустой — ничего не делает (остаётся локальный файл).
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
        with open(WHITE_IP_FILE, "w", encoding="utf-8") as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")
        lines = [
            ln.strip()
            for ln in data.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        print(f"📥 White IP скачан с remote: {len(lines)} строк → {WHITE_IP_FILE}")
    except Exception as e:
        print(f"⚠️ Не удалось скачать white_ip: {e} — используем локальный файл")


def load_white_ips() -> set:
    """Читает локальный white_ip.txt в set IP-строк."""
    white_ips: set = set()
    if not os.path.exists(WHITE_IP_FILE):
        return white_ips
    try:
        with open(WHITE_IP_FILE, "r", encoding="utf-8") as f:
            for line in f:
                white_ips.update(parse_ip_or_resolve(line))
    except Exception as e:
        print(f"⚠️ Ошибка чтения {WHITE_IP_FILE}: {e}")
    return white_ips


def save_white_ips(white_ips: set) -> None:
    """Пишет отсортированный white_ip.txt."""
    import ipaddress

    def ip_sort_key(ip):
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    with open(WHITE_IP_FILE, "w", encoding="utf-8") as f:
        for ip in sorted(list(white_ips), key=ip_sort_key):
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
