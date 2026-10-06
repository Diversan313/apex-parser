"""Загрузка подписок, извлечение конфигов, expired-проверка."""
from __future__ import annotations

import os
import re
import ssl
import json
import time
import base64
import socket
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from .config import (
    HEADERS,
    SSL_CONTEXT,
    SSL_VERIFY_SOURCES,
    KAMELEON_ENABLED,
    SOURCE_FETCH_WORKERS,
    SOURCE_FETCH_TIMEOUT,
    SOURCE_FETCH_RETRIES,
    MAX_WORKERS,
    EXPIRED_MARKERS_REGEX,
    SUPPORTED_PROTOCOLS,
    DECRYPT_HAPP,
)
from .utils import (
    safe_b64decode,
    safe_b64encode,
    sanitize_v2rayng_link,
    fmt_bytes,
)
from .parse import parse_host_port
from .xray import xray_outbound_to_link
from .utils import happ
from .utils.kameleon import fetch_kameleon
from . import config as _cfg

def extract_configs_from_json_text(content: str) -> list:
    """Достаёт share-ссылки из JSON-подписки / Xray config (без двойного счёта)."""
    content = content.strip()
    if not content:
        return []
    try:
        data = json.loads(content)
    except Exception:
        return []

    found = []
    seen_keys = set()

    def link_key(link: str) -> str:
        # без #имени — одно и то же соединение не дублируем
        return link.split("#", 1)[0]

    def add_link(link: str):
        if not link or not link.startswith(SUPPORTED_PROTOCOLS):
            return
        link = sanitize_v2rayng_link(link)
        k = link_key(link)
        if k in seen_keys:
            return
        seen_keys.add(k)
        found.append(link)

    def walk(obj, root_remarks=None):
        if isinstance(obj, str):
            s = obj.strip()
            if s.startswith(SUPPORTED_PROTOCOLS):
                add_link(s)
            return
        if isinstance(obj, list):
            for item in obj:
                walk(item, root_remarks)
            return
        if not isinstance(obj, dict):
            return

        remarks = obj.get("remarks") or root_remarks

        # Полный Xray config: берём только outbounds, внутрь settings не лезем повторно
        if isinstance(obj.get("outbounds"), list):
            for ob in obj["outbounds"]:
                link = xray_outbound_to_link(ob)
                if not link:
                    continue
                if remarks and "#" in link:
                    base, _ = link.split("#", 1)
                    link = base + "#" + urllib.parse.quote(str(remarks))
                add_link(link)
            for k, v in obj.items():
                if k == "outbounds":
                    continue
                walk(v, remarks)
            return

        # Одиночный outbound
        if "protocol" in obj and "settings" in obj:
            link = xray_outbound_to_link(obj)
            if link:
                if remarks and "#" in link:
                    base, _ = link.split("#", 1)
                    link = base + "#" + urllib.parse.quote(str(remarks))
                add_link(link)
            return

        # vmess JSON object
        if obj.get("add") and obj.get("id") and obj.get("port"):
            try:
                add_link(
                    "vmess://"
                    + safe_b64encode(
                        json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
                    )
                )
            except Exception:
                pass
            return

        for v in obj.values():
            walk(v, remarks)

    walk(data)
    return found


def content_looks_expired(content: str, configs: list) -> bool:
    """
    Помечать источник Expired только если подписка реально
    «мертвая», а не из‑за одного случайного конфига в сборнике.

    Правила:
    - 0.0.0.0 / localhost НЕ учитываем (отфильтруются позже).
    - Маркеры в теле подписки смотрим БЕЗ share-ссылок
      (баннер «подписка истекла» на уровне файла).
    - Если конфигов много — нужен высокий % конфигов с маркером
      (≥70%), один «expired» в имени не роняет всю подписку.
    - Если конфигов ≤3 — expired только когда помечены все.
    - Пустая подписка + баннер в тексте → Expired.
    """
    configs = list(configs or [])
    body = content or ""

    # убираем сами ссылки, чтобы не ловить expired внутри имени ноды
    body_no_links = re.sub(
        r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://\S+",
        " ",
        body,
    )
    for c in configs:
        if c:
            body_no_links = body_no_links.replace(c, " ")

    sub_level = bool(EXPIRED_MARKERS_REGEX.search(body_no_links))

    expired_cfg = 0
    for c in configs:
        if c and EXPIRED_MARKERS_REGEX.search(c):
            expired_cfg += 1

    n = len(configs)

    if n == 0:
        return sub_level

    # Баннер «недействительна/истекла» в теле + мало конфигов → Expired
    if sub_level and n <= 5:
        return True

    if n <= 3:
        # мало конфигов — если все (или единственный) с маркером в имени
        return expired_cfg == n

    ratio = expired_cfg / float(n)
    # много рабочих + один мусорный «expired» → НЕ expired
    if ratio >= 0.70:
        return True
    if sub_level and ratio >= 0.50:
        return True

    return False


def fix_github_url(url: str) -> str:
    """
    raw.githubusercontent.com/.../commit/<sha>/file → ветка main/master.

    Ссылка на файл в конкретном коммите умирает, когда SHA выпадает из
    истории (rebase, squash, очистка). Заменяем на живую ветку, чтобы
    источник не умирал сам по себе.
    """
    m = re.match(
        r"^(https://raw\.githubusercontent\.com/[^/]+/[^/]+)/"
        r"(?:commit/[0-9a-fA-F]{40}|[0-9a-fA-F]{40})/(.+)$",
        url.strip(),
    )
    if not m:
        return url
    return f"{m.group(1)}/main/{m.group(2)}"


# Верифицированный контекст для источников (SSL_VERIFY_SOURCES)
_VERIFIED_SSL = ssl.create_default_context()

# Коды, при которых стоит повторить: rate-limit, таймаут-шлюз, перегрузка
_TRANSIENT_HTTP_CODES = frozenset({
    403, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 529, 530,
})


def _is_transient_error(e: Exception) -> bool:
    """
    Транзиентная ли ошибка (стоит ли ретрай)?
    Перманентные (404/400/401 и т.п.) фейлятся сразу, без траты попыток.
    """
    if isinstance(e, urllib.error.HTTPError):
        return e.code in _TRANSIENT_HTTP_CODES

    if isinstance(
        e,
        (
            socket.timeout,
            TimeoutError,
            ConnectionError,
            ConnectionResetError,
            ConnectionAbortedError,
            ConnectionRefusedError,
        ),
    ):
        return True

    if isinstance(e, urllib.error.URLError):
        reason = e.reason
        if isinstance(reason, (OSError, socket.timeout, TimeoutError)):
            return True
        text = str(reason).lower()
        return any(
            w in text
            for w in ("timed out", "timeout", "connection", "reset", "unreachable", "refused")
        )

    if isinstance(e, ssl.SSLError):
        return True

    # http.client.RemoteDisconnected и пр. наследуют ConnectionError — покрыто выше.
    return False


def _extract_subscription_configs(content: str, info: dict, _depth: int = 0) -> list:
    """
    Вытаскивает конфиги из текста подписки всеми способами:
    plain / base64 / JSON / base64-JSON / happ://crypt*.
    Заполняет флаги формата в info, возвращает список конфигов.
    """
    stripped = content.strip()
    valid_configs = []

    # 1) plain share links
    raw_lines = [l.strip() for l in content.splitlines() if l.strip()]
    info["total_lines"] = len(raw_lines)
    for line in raw_lines:
        if line.startswith(SUPPORTED_PROTOCOLS):
            valid_configs.append(sanitize_v2rayng_link(line))

    # 2) base64 subscription
    if not valid_configs:
        try:
            decoded = safe_b64decode(stripped)
            if any(p in decoded for p in SUPPORTED_PROTOCOLS):
                content = decoded
                info["is_base64"] = True
                raw_lines = [l.strip() for l in content.splitlines() if l.strip()]
                info["total_lines"] = len(raw_lines)
                for line in raw_lines:
                    if line.startswith(SUPPORTED_PROTOCOLS):
                        valid_configs.append(sanitize_v2rayng_link(line))
        except Exception:
            pass

    # 3) JSON (array of links / Xray full config / vmess objects)
    if not valid_configs:
        json_configs = extract_configs_from_json_text(stripped)
        if json_configs:
            valid_configs = json_configs
            info["is_json"] = True
        else:
            # maybe base64-wrapped JSON
            try:
                decoded = safe_b64decode(stripped)
                json_configs = extract_configs_from_json_text(decoded)
                if json_configs:
                    valid_configs = json_configs
                    info["is_json"] = True
                    info["is_base64"] = True
            except Exception:
                pass
    elif stripped.startswith("{") or stripped.startswith("["):
        # links found but also JSON — mark if JSON parse works
        extra = extract_configs_from_json_text(stripped)
        if extra:
            info["is_json"] = True
            for c in extra:
                if c not in valid_configs:
                    valid_configs.append(c)

    # 4) happ://crypt* — зашифрованные ссылки на подписки:
    #    расшифровываем → URL подписки → качаем её как вложенный источник.
    if DECRYPT_HAPP and "happ://" in content and _depth == 0:
        for h_link in happ.extract_happ_links(content):
            sub_url = happ.happ_link_to_subscription_url(h_link)
            if not sub_url:
                continue
            nested = fetch_single_url_with_details(
                sub_url, retries=1, _depth=_depth + 1
            )
            info["happ_decrypted"] += 1
            for c in nested.get("configs") or []:
                if c not in valid_configs:
                    valid_configs.append(c)

    return valid_configs


def fetch_single_url_with_details(
    url: str,
    retries: int = 1,
    _depth: int = 0,
    _content_override: str = None,
) -> dict:

    url_clean = url.strip().replace(" ", "%20")

    info = {
        "url": url,
        "http_status": None,
        "size_bytes": 0,
        "is_base64": False,
        "is_json": False,
        "is_expired": False,
        "happ_decrypted": 0,
        "kameleon": False,
        "total_lines": 0,
        "configs": [],
        "error": None,
        "network_error": False,
    }

    # Kameleon: контент уже скачан с маскировкой — парсим без загрузки
    if _content_override is not None:
        info["http_status"] = 200
        content = _content_override
    else:
        last_err = None
        use_verified = SSL_VERIFY_SOURCES
        attempt = 0
        while attempt <= retries:
            attempt += 1
            try:
                req = urllib.request.Request(
                    fix_github_url(url_clean), headers=HEADERS
                )
                # SSL_VERIFY_SOURCES: сначала с проверкой сертификата;
                # при битом серте — одноразовый fallback на контекст без проверки
                with urllib.request.urlopen(
                    req, timeout=SOURCE_FETCH_TIMEOUT,
                    context=_VERIFIED_SSL if use_verified else SSL_CONTEXT,
                ) as response:
                    info["http_status"] = response.status
                    raw_data = response.read()
                    info["size_bytes"] = len(raw_data)
                    content = raw_data.decode("utf-8", errors="ignore")
                    info["network_error"] = False
                    info["error"] = None  # успех после fallback'а — ошибка не актуальна
                    last_err = None
                    break
            except Exception as e:
                last_err = e
                info["error"] = f"{type(e).__name__}: {e}"
                if isinstance(e, urllib.error.HTTPError):
                    info["http_status"] = e.code  # для Kameleon-триггера на 401/403

                # urllib заворачивает ошибку серта в URLError(reason=SSLCertVerificationError)
                cert_err = isinstance(e, ssl.SSLCertVerificationError) or (
                    isinstance(e, urllib.error.URLError)
                    and isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError)
                )

                if cert_err:
                    if use_verified:
                        use_verified = False
                        attempt -= 1  # fallback не тратит попытку
                        continue
                    info["network_error"] = False  # серт бит навсегда — ретраи не помогут
                    content = None
                    break

                # ретраи ТОЛЬКО для транзиентных ошибок:
                # 404/400/401 и прочий перманент фейлится сразу
                transient = _is_transient_error(e)
                info["network_error"] = transient
                if transient and attempt <= retries:
                    time.sleep(0.5 * attempt)
                    continue
                content = None
                break
        else:
            content = None

        # Kameleon на отказ источника: панели режут "чужой" UA кодом 401/403 —
        # маскируемся и пробуем снова (на 404 бессмысленно — объекта нет).
        if (
            content is None
            and _cfg.KAMELEON_ENABLED
            and _depth == 0
            and info.get("http_status") in (401, 403)
        ):
            kcontent = fetch_kameleon(url_clean)
            if kcontent:
                content = kcontent
                info["kameleon"] = True
                info["http_status"] = 200
                info["error"] = None
                info["network_error"] = False
            else:
                return info

    if content is None:
        return info

    try:
        valid_configs = _extract_subscription_configs(content, info, _depth)

        # Kameleon: источник скачался, но конфигов не отдал (пустышка/мусор)
        # - маскируемся под клиентов, пока какая-то личность не вытащит подписку.
        if _cfg.KAMELEON_ENABLED and not valid_configs and _depth == 0:
            kcontent = fetch_kameleon(url_clean)
            if kcontent:
                # сбрасываем флаги формата - парсим свежий контент с нуля
                info["is_base64"] = False
                info["is_json"] = False
                info["total_lines"] = 0
                kconfigs = _extract_subscription_configs(kcontent, info, _depth + 1)
                if kconfigs:
                    valid_configs = kconfigs
                    info["kameleon"] = True

        info["configs"] = list(dict.fromkeys(valid_configs))
        info["is_expired"] = content_looks_expired(content, info["configs"])

    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"

    return info


def fetch_links_parallel_with_source(
    url_file: str,
) -> list:

    links_with_source = []

    if not os.path.exists(
        url_file
    ):

        print(
            f"⚠️ Файл источников "
            f"{url_file} не найден!"
        )

        return links_with_source

    try:

        with open(
            url_file,
            "r",
            encoding="utf-8",
        ) as f:

            urls = [
                line.strip()
                for line in f
                if (
                    line.strip()
                    and not line.strip().startswith(
                        "#"
                    )
                )
            ]

        print(
            f"\n📡 [{url_file}] "
            f"Скачивание источников "
            f"({len(urls)} шт.)..."
        )

        successful_sources = 0
        results_by_idx = {}
        done_count = 0

        with ThreadPoolExecutor(
            max_workers=SOURCE_FETCH_WORKERS
        ) as executor:

            futures = {
                executor.submit(
                    fetch_single_url_with_details,
                    url,
                ): idx
                for idx, url in enumerate(
                    urls,
                    1,
                )
            }

            for future in as_completed(futures):
                idx = futures[future]
                try:
                    res = future.result()
                    results_by_idx[idx] = ("ok", res)
                except Exception as e:
                    results_by_idx[idx] = ("err", str(e))
                done_count += 1
                # прогресс адаптивный: маленький список - каждая строка,
                # огромный - каждые ~5%, чтобы не топить лог
                if done_count == 1 or done_count == len(urls) or done_count % max(1, len(urls) // 20) == 0:
                    got = sum(
                        1 for kind, payload in results_by_idx.values()
                        if kind == "ok" and payload.get("configs")
                    )
                    print(f"   📡 скачано {done_count}/{len(urls)} источников, с конфигами: {got}")

        # Повтор только для сетевых сбоев (не для пустых/битых подписок)
        retry_idxs = []
        for idx, (kind, payload) in results_by_idx.items():
            if kind == "err":
                retry_idxs.append(idx)
            elif (
                isinstance(payload, dict)
                and payload.get("network_error")
                and not payload.get("configs")
            ):
                retry_idxs.append(idx)

        if retry_idxs:
            print(
                f"  ↺ Повтор сети для "
                f"{len(retry_idxs)} источник(ов)..."
            )
            with ThreadPoolExecutor(
                max_workers=MAX_WORKERS
            ) as executor:
                futures2 = {
                    executor.submit(
                        fetch_single_url_with_details,
                        urls[idx - 1],
                        2,
                    ): idx
                    for idx in retry_idxs
                }
                for future in as_completed(futures2):
                    idx = futures2[future]
                    try:
                        res = future.result()
                        results_by_idx[idx] = ("ok", res)
                    except Exception as e:
                        results_by_idx[idx] = ("err", str(e))

        # Печать строго по номеру источника (без URL)
        special_lines = []   # ошибки и источники с пометками - в конец отчёта

        for idx in range(1, len(urls) + 1):
            kind, payload = results_by_idx.get(
                idx, ("err", "нет ответа")
            )

            res = payload if kind == "ok" else None
            configs = (res or {}).get("configs") or []

            if res.get("http_status") in (200, 204) or configs:
                successful_sources += 1

            # строка источника
            status_str = (
                f"HTTP {res.get('http_status')}"
                if res.get("http_status")
                else "ОШИБКА"
            )
            fmt_parts = []
            if res.get("is_base64"):
                fmt_parts.append("Base64")
            if res.get("is_json"):
                fmt_parts.append("JSON")
            if res.get("happ_decrypted"):
                fmt_parts.append(f"Happ:{res['happ_decrypted']}")
            if res.get("kameleon"):
                fmt_parts.append("Kameleon")
            if res.get("is_expired"):
                fmt_parts.append("Expired")
            fmt_str = f" [{'/'.join(fmt_parts)}]" if fmt_parts else ""
            err_str = (
                f" (Ошибка: {res.get('error')})"
                if res.get("error") and not configs
                else ""
            )
            line = (
                f"  ├─ {'❌' if kind == 'err' or not configs else '🔗'} Источник #{idx:<3} | "
                f"Статус: {status_str:<10} | "
                f"Размер: {fmt_bytes(res.get('size_bytes', 0)) if res else '0B'} | "
                f"Конфигов: {len(configs)}"
                f"{fmt_str}{err_str}"
                if kind == "ok"
                else f"  ├─ ❌ Источник #{idx:<3} | ОШИБКА | {payload}"
            )

            # проблемные/особые - буферизуем, обычные печатаем сразу
            if kind == "err" or not configs or fmt_parts:
                special_lines.append(line)
            else:
                print(line)

            if res:
                for cfg_ in configs:
                    links_with_source.append(
                        (cfg_, f"src#{idx}")
                    )

        for line in special_lines:
            print(line)

        print(
            f"✅ Получено "
            f"{len(links_with_source)} "
            f"конфигов из "
            f"{successful_sources}/"
            f"{len(urls)} источников."
        )

    except Exception as e:

        print(
            f"⚠️ Ошибка чтения "
            f"{url_file}: {e}"
        )

    return links_with_source


