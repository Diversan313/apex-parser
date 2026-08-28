"""Очередь incoming / white_ip и загрузка предыдущих alive."""
from __future__ import annotations

import os
from typing import List, Set, Tuple

from .config import (
    WHITE_IP_FILE,
    INCOMING_FILE,
    MAX_QUEUE_LIMIT,
    SUPPORTED_PROTOCOLS,
)
from .utils import safe_b64decode, sanitize_v2rayng_link
from .parse import parse_ip_or_resolve

def process_incoming_queue():

    incoming_proxies = []
    incoming_raw_ips = []

    if not os.path.exists(
        INCOMING_FILE
    ):
        return (
            incoming_proxies,
            incoming_raw_ips,
        )

    try:

        with open(
            INCOMING_FILE,
            "r",
            encoding="utf-8",
        ) as f:

            lines = [
                line.strip()
                for line in f
                if (
                    line.strip()
                    and not line.strip().startswith(
                        "#"
                    )
                )
            ]

        unique_lines = list(
            dict.fromkeys(
                lines
            )
        )[
            :MAX_QUEUE_LIMIT
        ]

        for item in unique_lines:

            if item.startswith(
                SUPPORTED_PROTOCOLS
            ):

                incoming_proxies.append(
                    sanitize_v2rayng_link(
                        item
                    )
                )

            else:

                incoming_raw_ips.extend(
                    parse_ip_or_resolve(
                        item
                    )
                )

        print(
            f"📥 Из очереди забрано: "
            f"{len(incoming_proxies)} "
            f"прокси-ссылок и "
            f"{len(incoming_raw_ips)} "
            f"чистых IP."
        )

    except Exception as e:

        print(
            f"⚠️ Ошибка чтения очереди: "
            f"{e}"
        )

    return (
        incoming_proxies,
        incoming_raw_ips,
    )


# ============================================================
# PREVIOUS ALIVES
# ============================================================

def load_previous_alives():

    prev_wl = []
    prev_bl = []

    if os.path.exists(
        "alive_bs.txt"
    ):

        try:

            with open(
                "alive_bs.txt",
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
        "alive_bl.txt"
    ):

        try:

            with open(
                "alive_bl.txt",
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

