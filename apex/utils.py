"""Мелкие утилиты: base64, флаги, sanitize ссылок."""
from __future__ import annotations

import base64
import json
import re
import urllib.parse

from .config import FLAG_REGEX

def safe_b64decode(s: str) -> str:
    s = s.strip()
    s = re.sub(r"\s+", "", s)
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)

    return base64.b64decode(
        s
    ).decode(
        "utf-8",
        errors="ignore",
    )


def safe_b64encode(s: str) -> str:
    return base64.b64encode(
        s.encode("utf-8")
    ).decode("utf-8")


def fmt_bytes(n: int) -> str:
    try:
        n = int(n or 0)
    except Exception:
        n = 0
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}B"


# ============================================================
# FLAGS
# ============================================================

def cc_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🌐"

    return "".join(
        chr(127397 + ord(c))
        for c in cc.upper()
    )


def extract_clean_flag(text: str) -> str:
    if not text:
        return "🌐"

    flags = FLAG_REGEX.findall(text)

    return (
        flags[0]
        if flags
        else "🌐"
    )


# ============================================================
# SANITIZE
# ============================================================

def sanitize_v2rayng_link(link: str) -> str:
    """
    Только минимальная нормализация.

    extra XHTTP НЕ УДАЛЯЕМ.
    """

    link = link.strip()

    try:

        if link.startswith("vmess://"):

            b64_data = (
                link
                .replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

            if str(
                data.get(
                    "net",
                    "",
                )
            ).lower() in (
                "auto",
                "none",
                "",
            ):
                data["net"] = "tcp"

            if (
                str(
                    data.get(
                        "tls",
                        "",
                    )
                ).lower()
                == "auto"
            ):
                data["tls"] = ""

            if (
                str(
                    data.get(
                        "type",
                        "",
                    )
                ).lower()
                == "auto"
            ):
                data["type"] = "none"

            encoded = safe_b64encode(
                json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )

            return (
                "vmess://"
                + encoded
            )

        main_part = link
        name_part = ""

        if "#" in link:
            main_part, name_part = (
                link.split(
                    "#",
                    1,
                )
            )

        if "?" not in main_part:
            return link

        base, query_part = (
            main_part.split(
                "?",
                1,
            )
        )

        params = urllib.parse.parse_qs(
            query_part,
            keep_blank_values=True,
        )

        changed = False

        if base.startswith("vless://"):

            encryption = str(
                params.get(
                    "encryption",
                    [""],
                )[0]
            ).lower()

            if encryption in (
                "",
                "auto",
            ):
                params["encryption"] = [
                    "none"
                ]

                changed = True

        if (
            "type" in params
            and str(
                params["type"][0]
            ).lower()
            == "auto"
        ):
            params["type"] = [
                "tcp"
            ]
            changed = True

        if (
            "net" in params
            and str(
                params["net"][0]
            ).lower()
            == "auto"
        ):
            params["net"] = [
                "tcp"
            ]
            changed = True

        if (
            "security" in params
            and str(
                params["security"][0]
            ).lower()
            == "auto"
        ):
            del params["security"]
            changed = True

        if not changed:
            return link

        new_query = urllib.parse.urlencode(
            params,
            doseq=True,
        ).replace(
            "+",
            "%20",
        )

        new_link = (
            base
            + "?"
            + new_query
        )

        if name_part:
            new_link += (
                "#"
                + name_part
            )

        return new_link

    except Exception:
        return link

