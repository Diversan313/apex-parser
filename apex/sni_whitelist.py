"""SNI mobile whitelist (скачивание, загрузка, проверка)."""
from __future__ import annotations

import os
import urllib.request
import urllib.parse

from .config import (
    SNI_WHITELIST_PATH,
    SNI_WHITELIST_URL,
    HEADERS,
    SSL_CONTEXT,
)
from .parse import extract_sni_from_link

# Множество доменов из официального списка БС.
SNI_WHITELIST_SET: set = set()

def update_sni_whitelist_file():
    """
    Скачивает whitelist SNI с GitHub в arch/lists/whitelist.txt.
    Обновляет файл только если содержимое изменилось.
    """

    os.makedirs(
        os.path.dirname(SNI_WHITELIST_PATH) or ".",
        exist_ok=True,
    )

    try:
        req = urllib.request.Request(
            SNI_WHITELIST_URL,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=30,
            context=SSL_CONTEXT,
        ) as response:
            remote_data = response.read()

        # Нормализуем переводы строк
        try:
            remote_text = remote_data.decode(
                "utf-8",
                errors="ignore",
            )
        except Exception:
            remote_text = remote_data.decode(
                "latin-1",
                errors="ignore",
            )

        remote_text = remote_text.replace("\r\n", "\n").replace(
            "\r", "\n"
        )
        if remote_text and not remote_text.endswith("\n"):
            remote_text += "\n"

        local_text = None
        if os.path.exists(SNI_WHITELIST_PATH):
            try:
                with open(
                    SNI_WHITELIST_PATH,
                    "r",
                    encoding="utf-8",
                ) as f:
                    local_text = f.read().replace(
                        "\r\n", "\n"
                    ).replace("\r", "\n")
            except Exception:
                local_text = None

        if local_text is not None and local_text == remote_text:
            print(
                f"✅ SNI whitelist актуален: "
                f"{SNI_WHITELIST_PATH}"
            )
            return True

        with open(
            SNI_WHITELIST_PATH,
            "w",
            encoding="utf-8",
        ) as f:
            f.write(remote_text)

        lines = [
            ln.strip()
            for ln in remote_text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]

        print(
            f"📥 SNI whitelist обновлён: "
            f"{SNI_WHITELIST_PATH} "
            f"({len(lines)} доменов)"
        )
        return True

    except Exception as e:
        if os.path.exists(SNI_WHITELIST_PATH):
            print(
                f"⚠️ Не удалось обновить SNI whitelist: {e}. "
                f"Используем локальный файл."
            )
            return True

        print(
            f"⚠️ SNI whitelist недоступен: {e}"
        )
        return False


def load_sni_whitelist():
    """Читает arch/lists/whitelist.txt в SNI_WHITELIST_SET."""

    global SNI_WHITELIST_SET
    SNI_WHITELIST_SET = set()

    if not os.path.exists(SNI_WHITELIST_PATH):
        print(
            f"⚠️ Файл {SNI_WHITELIST_PATH} не найден"
        )
        return

    try:
        with open(
            SNI_WHITELIST_PATH,
            "r",
            encoding="utf-8",
        ) as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                # убираем возможные схемы/пути
                if "://" in line:
                    try:
                        line = urllib.parse.urlparse(
                            line
                        ).netloc or line
                    except Exception:
                        pass
                line = (
                    line.split("/")[0]
                    .split("?")[0]
                    .split("#")[0]
                    .strip("[]")
                    .lower()
                )
                if line:
                    SNI_WHITELIST_SET.add(line)

        print(
            f"📋 SNI whitelist загружен: "
            f"{len(SNI_WHITELIST_SET)} доменов"
        )

    except Exception as e:
        print(
            f"⚠️ Ошибка чтения SNI whitelist: {e}"
        )
        SNI_WHITELIST_SET = set()


def init_sni_whitelist():
    update_sni_whitelist_file()
    load_sni_whitelist()


def is_sni_in_mobile_whitelist(sni: str) -> bool:
    """
    Точное совпадение или subdomain для домена из списка.
    Пример: list имеет vk.com → m.vk.com тоже матчится.
    """

    if not sni or not SNI_WHITELIST_SET:
        return False

    sni = sni.strip().lower().rstrip(".")

    if not sni:
        return False

    if sni in SNI_WHITELIST_SET:
        return True

    # subdomain: foo.bar.vk.com при vk.com в списке
    parts = sni.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in SNI_WHITELIST_SET:
            return True

    return False


def link_has_whitelisted_sni(link: str) -> bool:
    sni = extract_sni_from_link(link)
    if sni and is_sni_in_mobile_whitelist(sni):
        return True
    return False

