"""Загрузка подписок, извлечение конфигов, expired-проверка."""
from __future__ import annotations

import os
import re
import ssl
import json
import time
import base64
import socket
import threading
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
    SOCKET_DEFAULT_TIMEOUT,
    SOURCE_FETCH_RETRIES,
    FETCH_HEARTBEAT_SEC,
    SOURCE_FETCH_DEADLINE,
    WRITE_SOURCES_REPORT,
    EXPIRED_MARKERS_REGEX,
    SUPPORTED_PROTOCOLS,
    DECRYPT_HAPP,
)
from .utils import (
    safe_b64decode,
    safe_b64encode,
    sanitize_v2rayng_link,
    fmt_bytes,
    fmt_duration,
)
from .parse import parse_host_port
from .xray import xray_outbound_to_link
from .utils import happ
from .utils.kameleon import fetch_kameleon
from .utils.prox import prox_fetch, happ_decrypt_fallback
from .utils.netlimit import install_network_limits, read_bounded
from .utils.converters import foreign_yaml_to_links, singbox_outbound_to_link

# Дефолт для сокетов, которым не задан явный таймаут.
# DNS это НЕ ограничивает: getaddrinfo — системный вызов, его потолок
# ставит install_network_limits() патчем из netlimit.
socket.setdefaulttimeout(SOCKET_DEFAULT_TIMEOUT)
install_network_limits()
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

        # Полный Xray config: берём только outbounds, внутрь settings не лезем повторно.
        # Подмешиваем и sing-box outbounds (type+server) — Xray-конвертер их
        # не узнаёт, а реальные подписки в sing-box JSON приходят часто.
        if isinstance(obj.get("outbounds"), list):
            for ob in obj["outbounds"]:
                link = xray_outbound_to_link(ob) or singbox_outbound_to_link(ob)
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


def _prox_eligible(info: dict) -> bool:
    """Prox включаем только для гео-блоков: панель отдала отказ
    (401/403/406/451), заглушку с 200 без конфигов или оборвала
    соединение. Таймауты и 404 — мимо: чужой IP их не лечит."""
    if not _cfg.PROX_ENABLED:
        return False
    if info.get("conn_blocked"):
        return True
    status = info.get("http_status")
    if status in (401, 403, 406, 451):
        return True
    if status in (200, 204) and not info.get("configs"):
        return True
    return False


def _try_prox(url_clean: str, info: dict, _deadline: float):
    """Третий уровень цепочки: контент с чужого IP.

    Вызывается после провала прямых попыток и Kameleon. Не влезает в
    остаток бюджета источника — Prox пропускается, источник падает
    как без него.
    """
    if not _prox_eligible(info):
        return None
    remaining = _deadline - time.monotonic()
    if remaining <= 1.0:
        return None
    pcontent = prox_fetch(url_clean, timeout=remaining)
    if pcontent:
        info["prox"] = True
        info["http_status"] = 200
        info["error"] = None
        info["network_error"] = False
    return pcontent


def _extract_subscription_configs(
    content: str, info: dict, _depth: int = 0, _deadline: float = None
) -> list:
    """
    Вытаскивает конфиги из текста подписки всеми способами:
    plain / base64 / JSON / base64-JSON / happ://crypt*.
    Заполняет флаги формата в info, возвращает список конфигов.

    _deadline — общий с родительским источником бюджет на happ-вложенности.
    Без параметра ветка ниже обращалась к несуществующему имени и
    молча теряла все конфиги источника, в котором есть happ-ссылки.
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

    # 3b) Clash/Mihomo YAML (proxies:) и sing-box в YAML-обёртке (outbounds:)
    # — конвертация в share-ссылки. Дешёлая проверка маркера не даёт
    # гонять YAML-парсер по обычным plain/base64 подпискам.
    if not valid_configs and ("proxies:" in content or "outbounds:" in content):
        yaml_configs = foreign_yaml_to_links(content)
        if yaml_configs:
            valid_configs = yaml_configs
            info["is_yaml"] = True

    # 4) happ://crypt* — зашифрованные ссылки на подписки:
    #    расшифровываем → URL подписки → качаем её как вложенный источник.
    #    Дедлайн общий с родителем: десяток happ-ссылок не должен
    #    умножать бюджет источника.
    if DECRYPT_HAPP and "happ://" in content and _depth == 0:
        # самостоятельные вызовы (тесты) идут со стандартным бюджетом источника
        if _deadline is None:
            _deadline = time.monotonic() + SOURCE_FETCH_DEADLINE
        for h_link in happ.extract_happ_links(content):
            sub_url = happ.happ_link_to_subscription_url(h_link)
            if not sub_url:
                # локальные ключи отстают от новых маркеров — внешний
                # декрипт как fallback; недоступен тихо пропускаем
                sub_url = happ_decrypt_fallback(h_link)
            if not sub_url:
                continue
            if time.monotonic() >= _deadline:
                break
            nested = fetch_single_url_with_details(
                sub_url, retries=1, _depth=_depth + 1, _deadline=_deadline
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
    _deadline: float = None,
) -> dict:

    url_clean = url.strip().replace(" ", "%20")

    # Стенка на весь источник: попытки, redirect'ы, Kameleon и happ-вложенности
    # суммарно. Без неё timeout urlopen не ограничивает запрос целиком —
    # он действует на каждую сокетную операцию отдельно.
    if _deadline is None:
        _deadline = time.monotonic() + SOURCE_FETCH_DEADLINE

    info = {
        "url": url,
        "http_status": None,
        "size_bytes": 0,
        "is_base64": False,
        "is_json": False,
        "is_yaml": False,
        "is_expired": False,
        "happ_decrypted": 0,
        "kameleon": False,
        "prox": False,
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
            remaining = _deadline - time.monotonic()
            if remaining <= 0:
                info["error"] = f"превышен бюджет источника {SOURCE_FETCH_DEADLINE}с"
                info["network_error"] = True
                content = None
                break
            attempt += 1
            try:
                req = urllib.request.Request(
                    fix_github_url(url_clean), headers=HEADERS
                )
                # SSL_VERIFY_SOURCES: сначала с проверкой сертификата;
                # при битом серте — одноразовый fallback на контекст без проверки
                with urllib.request.urlopen(
                    req,
                    timeout=min(SOURCE_FETCH_TIMEOUT, remaining),
                    context=_VERIFIED_SSL if use_verified else SSL_CONTEXT,
                ) as response:
                    info["http_status"] = response.status
                    raw_data = read_bounded(response, _deadline)
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
                # обрыв соединения — признак гео-фильтра; таймаут им не считается
                if isinstance(e, (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError)):
                    info["conn_blocked"] = True
                if transient and attempt <= retries:
                    time.sleep(min(0.5 * attempt, max(0.0, _deadline - time.monotonic())))
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
            kameleon_budget = max(2, int(_deadline - time.monotonic()))
            kcontent = fetch_kameleon(
                url_clean, timeout=min(12, kameleon_budget), deadline=_deadline
            )
            if kcontent:
                content = kcontent
                info["kameleon"] = True
                info["http_status"] = 200
                info["error"] = None
                info["network_error"] = False
            else:
                # Kameleon не вытащил — последняя надежда: чужой IP
                content = _try_prox(url_clean, info, _deadline)
                if content is None:
                    return info

    if content is None:
        # сюда попадают conn_blocked-источники и 401/403 при выключенном
        # Kameleon — обе категории лечатся чужим IP
        content = _try_prox(url_clean, info, _deadline)

    if content is None:
        return info

    try:
        valid_configs = _extract_subscription_configs(content, info, _depth, _deadline)

        # Kameleon: источник скачался, но конфигов не отдал (пустышка/мусор)
        # - маскируемся под клиентов, пока какая-то личность не вытащит подписку.
        if _cfg.KAMELEON_ENABLED and not valid_configs and _depth == 0:
            kameleon_budget = max(2, int(_deadline - time.monotonic()))
            kcontent = fetch_kameleon(
                url_clean, timeout=min(12, kameleon_budget), deadline=_deadline
            )
            if kcontent:
                # сбрасываем флаги формата - парсим свежий контент с нуля
                info["is_base64"] = False
                info["is_json"] = False
                info["total_lines"] = 0
                kconfigs = _extract_subscription_configs(kcontent, info, _depth + 1, _deadline)
                if kconfigs:
                    valid_configs = kconfigs
                    info["kameleon"] = True

        # Prox: контент с чужого IP (гео-заглушка с 200 без конфигов)
        if not valid_configs and _depth == 0:
            pcontent = _try_prox(url_clean, info, _deadline)
            if pcontent:
                info["is_base64"] = False
                info["is_json"] = False
                info["total_lines"] = 0
                valid_configs = _extract_subscription_configs(
                    pcontent, info, _depth + 1, _deadline
                )
                # expired-проверка ниже должна видеть реальное тело
                content = pcontent

        info["configs"] = list(dict.fromkeys(valid_configs))
        info["is_expired"] = content_looks_expired(content, info["configs"])

    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"

    return info


def _fetch_source_bounded(url: str, retries: int = 1) -> dict:
    """Жёсткая гарантия завершения одного источника.

    Внутренний дедлайн ограничивает все явные операции, но urlopen может
    застрять на уровне C: TLS handshake и чтение заголовков идут теми же
    recv с per-op таймаутом, и «капающий» сервер растягивает их неограниченно.
    Поэтому вызов выполняем в daemon-потоке: после исчерпания бюджета поток
    бросаем и возвращаем помеченный timeout'ом результат. Брошенный поток
    завершится сам по своему дедлайну и не держит выход процесса
    (в отличие от потоков ThreadPoolExecutor, которые джойнятся при exit).
    """
    box = {}

    def _run():
        box["res"] = fetch_single_url_with_details(url, retries=retries)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    # бюджет + запас на одну финальную сокетную операцию
    t.join(SOURCE_FETCH_DEADLINE + SOURCE_FETCH_TIMEOUT + 5)
    if "res" in box:
        return box["res"]
    return {
        "url": url,
        "http_status": None,
        "size_bytes": 0,
        "is_base64": False,
        "is_json": False,
        "is_expired": False,
        "happ_decrypted": 0,
        "kameleon": False,
        "prox": False,
        "total_lines": 0,
        "configs": [],
        "error": f"источник не уложился в {SOURCE_FETCH_DEADLINE}с (hard deadline)",
        "network_error": True,
    }


def fetch_links_parallel_with_source(
    url_file: str,
) -> list:

    links_with_source = []

    if not os.path.exists(
        url_file
    ):

        print(
            f"error: файл источников не найден: {url_file}"
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

        t0 = time.monotonic()

        print(f"fetch: {url_file}, {len(urls)} источников")

        results_by_idx = {}
        done_count = 0
        next_heartbeat = t0 + FETCH_HEARTBEAT_SEC

        with ThreadPoolExecutor(
            max_workers=SOURCE_FETCH_WORKERS
        ) as executor:

            futures = {
                executor.submit(
                    _fetch_source_bounded,
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
                # heartbeat по времени: объём вывода не зависит от числа источников
                if time.monotonic() >= next_heartbeat:
                    print(f"fetch: {done_count}/{len(urls)}")
                    next_heartbeat = time.monotonic() + FETCH_HEARTBEAT_SEC

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
            print(f"fetch: повтор для {len(retry_idxs)} источников с сетевыми ошибками")
            # повтор идёт с полной шириной первого прохода: медленный retry
            # растягивал хвост прогона на десятки минут
            with ThreadPoolExecutor(
                max_workers=SOURCE_FETCH_WORKERS
            ) as executor:
                futures2 = {
                    executor.submit(
                        _fetch_source_bounded,
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

        # Полный отчёт — в файл: построчный дамп всех источников топит
        # лог Actions. Консоль получает только сводку по фазе.
        special_lines = []   # ошибки и источники с пометками - в конец отчёта
        report_lines = []
        stats = {
            "with_configs": 0,
            "empty_200": 0,
            "expired": 0,
            "deadline": 0,
            "http_err": 0,
            "net_err": 0,
            "yaml": 0,
            "kameleon": 0,
            "prox": 0,
        }
        err_types = {}

        for idx in range(1, len(urls) + 1):
            kind, payload = results_by_idx.get(
                idx, ("err", "нет ответа")
            )

            # упавший поток задачи не должен обрывать отчёт:
            # у такого результата нет полей, конфиги остальных источников терять нельзя
            if kind != "ok" or not isinstance(payload, dict):
                special_lines.append(
                    f"  ├─ ❌ Источник #{idx:<3} | ОШИБКА | {payload}"
                )
                etype = str(payload).split(":", 1)[0][:24]
                err_types[etype] = err_types.get(etype, 0) + 1
                continue

            res = payload
            configs = res.get("configs") or []
            err_text = res.get("error") or ""

            # Порядок проверок важен: у expired и дедлайнных источников
            # HTTP-статус бывает 200, в общие категории они не попадают.
            if configs:
                stats["with_configs"] += 1
            elif res.get("is_expired"):
                stats["expired"] += 1
            elif "hard deadline" in err_text or "превышен бюджет" in err_text:
                stats["deadline"] += 1
            elif res.get("http_status") in (200, 204):
                stats["empty_200"] += 1
            elif res.get("http_status") is None:
                stats["net_err"] += 1
            else:
                stats["http_err"] += 1
            if res.get("is_yaml"):
                stats["yaml"] += 1
            if res.get("kameleon"):
                stats["kameleon"] += 1
            if res.get("prox"):
                stats["prox"] += 1
            if err_text and not configs:
                etype = err_text.split(":", 1)[0][:24]
                err_types[etype] = err_types.get(etype, 0) + 1

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
            if res.get("is_yaml"):
                fmt_parts.append("YAML")
            if res.get("happ_decrypted"):
                fmt_parts.append(f"Happ:{res['happ_decrypted']}")
            if res.get("kameleon"):
                fmt_parts.append("Kameleon")
            if res.get("prox"):
                fmt_parts.append("Prox")
            if res.get("is_expired"):
                fmt_parts.append("Expired")
            fmt_str = f" [{'/'.join(fmt_parts)}]" if fmt_parts else ""
            err_str = (
                f" (Ошибка: {err_text})"
                if err_text and not configs
                else ""
            )
            line = (
                f"  ├─ {'❌' if not configs else '🔗'} Источник #{idx:<3} | "
                f"Статус: {status_str:<10} | "
                f"Размер: {fmt_bytes(res.get('size_bytes', 0))} | "
                f"Конфигов: {len(configs)}"
                f"{fmt_str}{err_str}"
            )

            # проблемные/особые - в конец отчёта, обычные - по порядку
            if not configs or fmt_parts:
                special_lines.append(line)
            else:
                report_lines.append(line)

            for cfg_ in configs:
                links_with_source.append(
                    (cfg_, f"src#{idx}")
                )

        top_errs = sorted(
            err_types.items(),
            key=lambda kv: -kv[1],
        )[:5]

        # разрез по категориям — в шапку отчёта, консоль получает короткую строку
        breakdown = (
            f"конфигов {len(links_with_source)} у {stats['with_configs']}, "
            f"пустые {stats['empty_200']}, expired {stats['expired']}, "
            f"yaml {stats['yaml']}, kameleon {stats['kameleon']}, prox {stats['prox']}, "
            f"HTTP-ошибки {stats['http_err']}, сетевые {stats['net_err']}, "
            f"дедлайны {stats['deadline']}"
        )
        if top_errs:
            breakdown += "\n# топ ошибок: " + ", ".join(
                f"{k} {v}" for k, v in top_errs
            )

        report_hint = ""
        if WRITE_SOURCES_REPORT:
            # имя по файлу источников: sources.txt -> sources_report.txt,
            # sources_wl.txt -> sources_wl_report.txt (раздельный режим)
            base = os.path.splitext(
                os.path.basename(url_file)
            )[0]
            name = (
                "sources_report.txt"
                if base == "sources"
                else f"{base}_report.txt"
            )
            report_path = os.path.join("stats", name)
            try:
                os.makedirs("stats", exist_ok=True)
                with open(
                    report_path,
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(
                        f"# Источники: {url_file} "
                        f"({len(urls)} шт.)\n#{breakdown}\n"
                    )
                    for line in report_lines + special_lines:
                        f.write(line + "\n")
                report_hint = f", отчёт {report_path}"
            except Exception as e:
                print(f"warn: отчёт источников не записан: {e}")

        failed_sources = sum(err_types.values())
        print(
            f"fetch: за {fmt_duration(time.monotonic() - t0)}, "
            f"конфигов {len(links_with_source)}, "
            f"ошибки {failed_sources}"
            f"{report_hint}"
        )

    except Exception as e:

        print(
            f"warn: чтение {url_file}: {e}"
        )

    return links_with_source


