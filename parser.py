import os
import urllib.request
import urllib.parse
import re
import base64
import socket
import json
import ipaddress
import subprocess
import time
import random
import threading
import ssl
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# НАСТРОЙКИ И ФАЙЛЫ
# ============================================================

WHITE_IP_FILE = "white_ip.txt"
INCOMING_FILE = "incoming_sources.txt"

MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = (
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/"
    "GeoLite2-Country.mmdb"
)

MAX_QUEUE_LIMIT = 1000
MAX_WORKERS = 15

# ============================================================
# BL - ОСТАВЛЯЕМ ТВОЮ ЛОГИКУ
# ============================================================

MAX_CONFIGS_PER_IP_BL = 2
MAX_CONFIGS_PER_SUBNET_BL = 5

# ============================================================
# WL
#
# ВАЖНО:
# До Xray WL НЕ РЕЖЕМ.
# После проверки применяется максимум 30/IP.
# ============================================================

MAX_CONFIGS_PER_IP_WL = 30

# ============================================================
# Xray tests
# ============================================================

WL_MIN_SUCCESS_COUNT = 1
BL_MIN_SUCCESS_COUNT = 2

# Твоя логика RU SNI:
# часть таких конфигов попадает в WL,
# остальные остаются BL.
RU_SNI_RATIO = 0.30

# Таймауты
XRAY_START_TIMEOUT = 1.2
XRAY_TEST_TIMEOUT = 6.0


# ============================================================
# SSL
# ============================================================

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}


# ============================================================
# CACHE
# ============================================================

DNS_CACHE = {}
DNS_LOCK = threading.Lock()

GEO_ONLINE_CACHE = {}
GEO_LOCK = threading.Lock()


# ============================================================
# REGEX
# ============================================================

WL_KEYWORDS_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(бс|обход|глусилк(?:а|и|ок|ам|ах)?|"
    r"глушилк(?:а|и|ок|ам|ах)?|whitelist|lte|"
    r"бел(?:ый|ые|ых)\s*списк(?:и|а|ов|ам|ах)?)"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)

FLAG_REGEX = re.compile(
    r"[\U0001F1E6-\U0001F1FF]{2}"
)

SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
)


# ============================================================
# MAXMIND
# ============================================================

try:
    import maxminddb
except ImportError:
    maxminddb = None

GEO_READER = None


# ============================================================
# CLOUDFLARE
#
# НЕ МЕНЯЮ ТВОЙ ФИЛЬТР.
# ============================================================

CF_CIDRS = [
    "103.4.160.0/22",
    "103.5.72.0/22",
    "103.7.4.0/22",
    "103.8.4.0/22",
    "103.8.84.0/22",
    "103.16.0.0/12",
    "103.24.124.0/22",
    "103.27.248.0/22",
    "103.44.96.0/22",
    "103.252.104.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "8.39.124.0/22",
    "8.41.8.0/22",
    "8.42.120.0/22",
    "8.44.0.0/22",
    "8.46.0.0/22",
    "8.48.0.0/22",
    "8.50.0.0/22",
    "8.52.0.0/22",
]

CF_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in CF_CIDRS
]


# ============================================================
# GEOIP
# ============================================================

def download_geoip_db():
    if os.path.exists(MMDB_PATH):
        return

    print("📥 Скачиваю оффлайн базу GeoIP...")

    try:
        req = urllib.request.Request(
            MMDB_URL,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=30,
            context=SSL_CONTEXT,
        ) as response:
            data = response.read()

        with open(MMDB_PATH, "wb") as f:
            f.write(data)

        print("✅ База GeoIP успешно загружена!")

    except Exception as e:
        print(f"⚠️ Ошибка загрузки базы GeoIP: {e}")


def init_geoip():
    global GEO_READER

    download_geoip_db()

    if maxminddb and os.path.exists(MMDB_PATH):
        try:
            GEO_READER = maxminddb.open_database(
                MMDB_PATH
            )
        except Exception:
            GEO_READER = None


# ============================================================
# BASE64
# ============================================================

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


# ============================================================
# HOST VALIDATION
# ============================================================

def is_valid_public_host(host: str) -> bool:
    if not host:
        return False

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if (
        not clean_host
        or clean_host.isdigit()
    ):
        return False

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return False

        return True

    except ValueError:
        pass

    if (
        "." not in clean_host
        or clean_host.startswith(".")
        or clean_host.endswith(".")
    ):
        return False

    if not DOMAIN_REGEX.match(
        clean_host
    ):
        return False

    if clean_host.endswith(
        (
            ".local",
            ".localhost",
            ".internal",
            ".lan",
            ".home",
            ".arpa",
            ".invalid",
            ".test",
        )
    ):
        return False

    return True


# ============================================================
# DNS
# ============================================================

def resolve_host_cached(clean_host: str):
    clean_host = clean_host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not is_valid_public_host(
        clean_host
    ):
        return None

    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[
                clean_host
            ]

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if ip_obj.is_global:

            with DNS_LOCK:
                DNS_CACHE[
                    clean_host
                ] = clean_host

            return clean_host

    except ValueError:
        pass

    try:
        socket.setdefaulttimeout(
            2.0
        )

        ip = socket.gethostbyname(
            clean_host
        )

        ip_obj = ipaddress.ip_address(
            ip
        )

        resolved_ip = (
            ip
            if ip_obj.is_global
            else None
        )

    except Exception:
        resolved_ip = None

    with DNS_LOCK:
        DNS_CACHE[
            clean_host
        ] = resolved_ip

    return resolved_ip


# ============================================================
# GEO
# ============================================================

def fetch_country_from_ip(
    ip_str: str,
):
    if not ip_str:
        return None

    if not is_valid_public_host(
        ip_str
    ):
        return None

    if GEO_READER:

        try:
            record = GEO_READER.get(
                ip_str
            )

            if (
                record
                and "country" in record
                and "iso_code"
                in record["country"]
            ):
                return (
                    record["country"]
                    ["iso_code"]
                )

        except Exception:
            pass

    with GEO_LOCK:

        if ip_str in GEO_ONLINE_CACHE:
            return GEO_ONLINE_CACHE[
                ip_str
            ]

    try:
        url = (
            "http://ip-api.com/json/"
            + ip_str
            + "?fields=status,countryCode"
        )

        req = urllib.request.Request(
            url,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=2.0,
            context=SSL_CONTEXT,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

        if (
            data.get("status")
            == "success"
            and data.get(
                "countryCode"
            )
        ):

            cc = data[
                "countryCode"
            ].upper()

            with GEO_LOCK:
                GEO_ONLINE_CACHE[
                    ip_str
                ] = cc

            return cc

    except Exception:
        pass

    return None


# ============================================================
# CLOUDFLARE
# ============================================================

def is_cloudflare_or_warp(
    host: str,
) -> bool:

    try:

        clean_host = host.strip(
            '[] \t\r\n\'"'
        ).lower()

        if not is_valid_public_host(
            clean_host
        ):
            return True

        if any(
            bad in clean_host
            for bad in (
                "localhost",
                "127.0.0.1",
                ".ir",
                ".cn",
                ".cf",
                ".ga",
                ".gq",
                ".ml",
                ".tk",
            )
        ):
            return True

        ip_str = resolve_host_cached(
            clean_host
        )

        if not ip_str:
            return True

        ip_obj = ipaddress.ip_address(
            ip_str
        )

        if not ip_obj.is_global:
            return True

        if ip_obj.version == 4:

            for network in CF_NETWORKS:

                if ip_obj in network:
                    return True

        elif ip_obj.version == 6:

            if str(
                ip_obj
            ).startswith(
                (
                    "2400:cb00:",
                    "2606:4700:",
                    "2803:f800:",
                    "2405:b500:",
                    "2405:8100:",
                    "2a06:98c0:",
                    "2c0f:f248:",
                )
            ):
                return True

    except Exception:
        return True

    return False


# ============================================================
# PARSE HOST PORT
# ============================================================

def parse_host_port(
    server_part: str,
):
    if not server_part:
        return None, None

    server_part = server_part.rstrip(
        "/"
    )

    try:

        if server_part.startswith(
            "["
        ):

            if "]" not in server_part:
                return None, None

            host_b, rest = (
                server_part.split(
                    "]",
                    1,
                )
            )

            host = host_b + "]"

            port_str = (
                rest
                .lstrip(":")
                .split("/")[0]
                .split("?")[0]
            )

            return (
                host,
                int(port_str),
            )

        if ":" in server_part:

            host, port_str = (
                server_part.rsplit(
                    ":",
                    1,
                )
            )

            port_str = (
                port_str
                .split("/")[0]
                .split("?")[0]
            )

            return (
                host,
                int(port_str),
            )

    except Exception:
        pass

    return None, None


# ============================================================
# PARSE LINK
# ============================================================

def parse_host_port_and_name(
    link: str,
):
    try:

        orig_name = ""

        if "#" in link:

            orig_name = (
                urllib.parse.unquote(
                    link.split(
                        "#",
                        1,
                    )[1]
                )
            )

        clean_link = link.split(
            "#",
            1,
        )[0]

        if clean_link.startswith(
            (
                "vless://",
                "trojan://",
                "ss://",
                "hysteria2://",
                "hy2://",
            )
        ):

            protocol, rest = (
                clean_link.split(
                    "://",
                    1,
                )
            )

            rest = rest.split(
                "?",
                1,
            )[0]

            if protocol == "ss":

                if "@" not in rest:

                    try:
                        decoded = safe_b64decode(
                            rest
                        )

                        if "@" in decoded:

                            _, host_port = (
                                decoded.rsplit(
                                    "@",
                                    1,
                                )
                            )

                            host, port = (
                                parse_host_port(
                                    host_port
                                )
                            )

                            return (
                                host,
                                port,
                                orig_name,
                            )

                    except Exception:
                        pass

                else:

                    _, host_port = (
                        rest.rsplit(
                            "@",
                            1,
                        )
                    )

                    host, port = (
                        parse_host_port(
                            host_port
                        )
                    )

                    return (
                        host,
                        port,
                        orig_name,
                    )

            else:

                if "@" in rest:
                    rest = (
                        rest.rsplit(
                            "@",
                            1,
                        )[1]
                    )

                host, port = (
                    parse_host_port(
                        rest
                    )
                )

                return (
                    host,
                    port,
                    orig_name,
                )

        elif clean_link.startswith(
            "vmess://"
        ):

            b64_data = (
                clean_link
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

            data = json.loads(
                decoded
            )

            return (
                data.get(
                    "add"
                ),
                int(
                    data.get(
                        "port"
                    )
                ),
                data.get(
                    "ps",
                    "",
                ),
            )

    except Exception:
        pass

    return None, None, ""


# ============================================================
# SNI
# ============================================================

def extract_sni_from_link(
    link: str,
) -> str:

    try:

        if "?" in link:

            query_part = (
                link.split(
                    "?",
                    1,
                )[1]
                .split(
                    "#",
                    1,
                )[0]
            )

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            sni = (
                params.get(
                    "sni",
                    [""],
                )[0]
                or params.get(
                    "host",
                    [""],
                )[0]
            )

            if sni:
                return (
                    urllib.parse.unquote(
                        sni
                    )
                    .lower()
                    .strip()
                )

        if link.startswith(
            "vmess://"
        ):

            b64_data = (
                link.replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            return (
                data.get(
                    "sni"
                )
                or data.get(
                    "host"
                )
                or ""
            ).lower().strip()

    except Exception:
        pass

    return ""


# ============================================================
# ALL HOSTS / IPS
# ============================================================

def extract_all_hosts_and_ips_from_link(
    link: str,
) -> list:

    hosts = set()

    main_host, _, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if main_host:

        hosts.add(
            main_host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    sni = extract_sni_from_link(
        link
    )

    if sni:

        hosts.add(
            sni.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    if "?" in link:

        try:

            query_part = (
                link.split(
                    "?",
                    1,
                )[1]
                .split(
                    "#",
                    1,
                )[0]
            )

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            h_param = params.get(
                "host",
                [""],
            )[0]

            if h_param:

                hosts.add(
                    urllib.parse.unquote(
                        h_param
                    )
                    .strip(
                        '[] \t\r\n\'"'
                    )
                    .lower()
                )

        except Exception:
            pass

    ip_matches = re.findall(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        link,
    )

    for ip_cand in ip_matches:

        try:

            ip_obj = ipaddress.ip_address(
                ip_cand
            )

            if ip_obj.is_global:
                hosts.add(
                    ip_cand
                )

        except ValueError:
            pass

    return list(hosts)


# ============================================================
# WHITE IP
# ============================================================

def parse_ip_or_resolve(
    item: str,
) -> set:

    if not item:
        return set()

    item = item.strip()

    if (
        not item
        or item.startswith("#")
    ):
        return set()

    if "://" in item:

        try:

            parsed = urllib.parse.urlparse(
                item
            )

            item = (
                parsed.netloc
                or item.split(
                    "://",
                    1,
                )[1]
            )

        except Exception:
            pass

    item = (
        item.split("/")[0]
        .split("?")[0]
        .split("#")[0]
        .strip()
    )

    host, _ = parse_host_port(
        item
    )

    if not host:
        host = item

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not is_valid_public_host(
        clean_host
    ):
        return set()

    try:

        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if ip_obj.is_global:
            return {
                str(ip_obj)
            }

    except ValueError:
        pass

    resolved_ip = (
        resolve_host_cached(
            clean_host
        )
    )

    if resolved_ip:
        try:

            ip_obj = ipaddress.ip_address(
                resolved_ip
            )

            if ip_obj.is_global:
                return {
                    resolved_ip
                }

        except ValueError:
            pass

    return set()


def find_matched_ip_for_link(
    link: str,
    white_ips: set,
):

    if not white_ips:
        return None

    hosts = (
        extract_all_hosts_and_ips_from_link(
            link
        )
    )

    for host in hosts:

        if not host:
            continue

        clean_host = host.strip(
            '[] \t\r\n\'"'
        ).lower()

        if not is_valid_public_host(
            clean_host
        ):
            continue

        if clean_host in white_ips:
            return clean_host

        resolved_ip = (
            resolve_host_cached(
                clean_host
            )
        )

        if (
            resolved_ip
            and resolved_ip in white_ips
        ):
            return resolved_ip

    return None


# ============================================================
# WL CLASSIFICATION
# ============================================================

def is_wl_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:

    full_text = (
        f"{link} {orig_name}"
    )

    try:
        full_text = (
            urllib.parse.unquote(
                full_text
            )
        )
    except Exception:
        pass

    return bool(
        WL_KEYWORDS_REGEX.search(
            full_text
        )
    )


RU_SNI_LIST = [
    "www.vk.com",
    "vk.com",
    "m.vk.com",
    "m1.vk.ru",
    "st.vk.ru",
    "id.vk.com",
    "sun1-93.userapi.com",
    "yandex.ru",
    "api-maps.yandex.ru",
    "wap.yandex.ru",
    "360.yandex.ru",
    "smartcaptcha.yandexcloud.net",
    "max.ru",
    "web.max.ru",
    "rutube.ru",
    "storage.yandex.net",
    "ads.x5.ru",
    "5post-gate.x5.ru",
    "28.img.avito.st",
    "cdn.tracker.yandex.net",
    "id.pervye.ru",
    "ya.ru",
    "rzd.ru",
    "live.ok.ru",
    "id.ok.ru",
    "qq.utiltools.ru",
    "ru.muzgrape.space",
    "flypobeda.ru",
    "shopping-api-gateway.cdek.shopping",
    "api.acquisition-gwe.plus.yandex.ru",
]


def is_ru_sni(
    link: str,
) -> bool:

    sni = extract_sni_from_link(
        link
    )

    if sni:

        if sni.endswith(
            (
                ".ru",
                ".su",
            )
        ):
            return True

        if any(
            sni == x
            or sni.endswith(
                "." + x
            )
            for x in RU_SNI_LIST
        ):
            return True

    link_low = link.lower()

    if re.search(
        r"sni=[^&]*\.(ru|su)(?:&|$)",
        link_low,
    ):
        return True

    return False


def classify_config(
    link: str,
    white_ips: set,
    ru_sni_ratio: float = RU_SNI_RATIO,
) -> str:

    # 1. Реальный WL по IP
    if find_matched_ip_for_link(
        link,
        white_ips,
    ):
        return "WL"

    host, _, orig_name = (
        parse_host_port_and_name(
            link
        )
    )

    if (
        not host
        or not is_valid_public_host(
            host
        )
    ):
        return "BL"

    # 2. WL по словам
    if is_wl_by_keywords(
        link,
        orig_name,
    ):
        return "WL"

    # 3. WL по стране endpoint
    clean_ip = (
        resolve_host_cached(
            host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )
    )

    if clean_ip:

        cc = fetch_country_from_ip(
            clean_ip
        )

        if (
            cc
            and cc.upper() == "RU"
        ):
            return "WL"

    # 4. RU SNI → твоя вероятность 30%
    if is_ru_sni(
        link
    ):

        return (
            "WL"
            if random.random()
            < ru_sni_ratio
            else "BL"
        )

    return "BL"


# ============================================================
# XHTTP EXTRA
# ============================================================

def parse_xhttp_extra(
    query_params: dict,
) -> dict:
    """
    В источнике extra — URL-encoded JSON.

    Например:

      extra={
        "host": "",
        "path": "",
        "mode": "",
        "headers": {...},
        "xPaddingBytes": "...",
        "sessionIDPlacement": "...",
        "seqPlacement": "...",
        "xmux": {...},
        ...
      }

    Эти поля должны попасть НЕ внутрь
    xhttpSettings["extra"], а непосредственно
    в xhttpSettings.
    """

    raw = query_params.get(
        "extra",
        [""],
    )[0]

    if not raw:
        return {}

    try:

        decoded = urllib.parse.unquote(
            raw
        )

        data = json.loads(
            decoded
        )

        if isinstance(
            data,
            dict,
        ):
            return data

    except Exception:
        pass

    return {}


def first_param(
    params: dict,
    name: str,
    default: str = "",
) -> str:

    values = params.get(
        name
    )

    if not values:
        return default

    return str(
        values[0]
    )


def parse_bool_param(
    params: dict,
    *names,
    default=False,
) -> bool:

    for name in names:

        if name not in params:
            continue

        value = str(
            params[name][0]
        ).strip().lower()

        return value in (
            "1",
            "true",
            "yes",
            "on",
        )

    return default


# ============================================================
# LINK -> XRAY OUTBOUND
# ============================================================

def link_to_xray_outbound(
    link: str,
):
    try:

        main_part = link.split(
            "#",
            1,
        )[0]

        if "://" not in main_part:
            return None

        protocol, rest = (
            main_part.split(
                "://",
                1,
            )
        )

        protocol = protocol.lower()

        # В этой проверке Hysteria2 по-прежнему
        # не запускаем через Xray HTTP-inbound.
        if protocol in (
            "hysteria2",
            "hy2",
        ):
            return None

        query_params = {}

        if "?" in rest:

            rest, query_part = (
                rest.split(
                    "?",
                    1,
                )
            )

            query_params = (
                urllib.parse.parse_qs(
                    query_part,
                    keep_blank_values=True,
                )
            )

        outbound = {
            "streamSettings": {}
        }

        # ====================================================
        # SHADOWSOCKS
        # ====================================================

        if protocol == "ss":

            if "@" not in rest:

                decoded = (
                    safe_b64decode(
                        rest
                    )
                )

                if "@" not in decoded:
                    return None

                user_info, host_port = (
                    decoded.rsplit(
                        "@",
                        1,
                    )
                )

            else:

                user_info, host_port = (
                    rest.rsplit(
                        "@",
                        1,
                    )
                )

                if ":" not in user_info:

                    try:
                        user_info = (
                            safe_b64decode(
                                user_info
                            )
                        )

                    except Exception:
                        pass

            if ":" not in user_info:
                return None

            method, password = (
                user_info.split(
                    ":",
                    1,
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": host,
                                "port": port,
                                "method": method,
                                "password": password,
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # VLESS
        # ====================================================

        elif protocol == "vless":

            if "@" not in rest:
                return None

            user_info, host_port = (
                rest.rsplit(
                    "@",
                    1,
                )
            )

            user_info = (
                urllib.parse.unquote(
                    user_info
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if (
                not host
                or not port
                or not user_info
            ):
                return None

            flow = first_param(
                query_params,
                "flow",
                "",
            )

            user = {
                "id": user_info,
                "encryption": first_param(
                    query_params,
                    "encryption",
                    "none",
                ) or "none",
            }

            if flow:
                user[
                    "flow"
                ] = flow

            outbound.update(
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": port,
                                "users": [
                                    user
                                ],
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # TROJAN
        # ====================================================

        elif protocol == "trojan":

            if "@" not in rest:
                return None

            user_info, host_port = (
                rest.rsplit(
                    "@",
                    1,
                )
            )

            host, port = (
                parse_host_port(
                    host_port
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": host,
                                "port": port,
                                "password": (
                                    urllib.parse.unquote(
                                        user_info
                                    )
                                ),
                            }
                        ]
                    },
                }
            )

        # ====================================================
        # VMESS
        # ====================================================

        elif protocol == "vmess":

            decoded = safe_b64decode(
                rest
            )

            data = json.loads(
                decoded
            )

            host = data.get(
                "add"
            )

            port = int(
                data.get(
                    "port"
                )
            )

            if not host or not port:
                return None

            outbound.update(
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": port,
                                "users": [
                                    {
                                        "id": data.get(
                                            "id"
                                        ),
                                        "alterId": int(
                                            data.get(
                                                "aid",
                                                0,
                                            )
                                        ),
                                        "security": (
                                            data.get(
                                                "scy",
                                                "auto",
                                            )
                                            or "auto"
                                        ),
                                    }
                                ],
                            }
                        ]
                    },
                }
            )

            query_params = {
                "security": [
                    data.get(
                        "tls",
                        "",
                    )
                ],
                "sni": [
                    data.get(
                        "sni",
                        "",
                    )
                    or data.get(
                        "host",
                        "",
                    )
                ],
                "type": [
                    data.get(
                        "net",
                        "",
                    )
                ],
                "path": [
                    data.get(
                        "path",
                        "/",
                    )
                ],
                "host": [
                    data.get(
                        "host",
                        "",
                    )
                ],
                "alpn": [
                    data.get(
                        "alpn",
                        "",
                    )
                ],
                "fp": [
                    data.get(
                        "fp",
                        "",
                    )
                ],
            }

        else:
            return None

        # ====================================================
        # SECURITY
        # ====================================================

        security = first_param(
            query_params,
            "security",
            "",
        ).lower()

        if (
            protocol == "trojan"
            and not security
        ):
            security = "tls"

        if security in (
            "tls",
            "reality",
        ):

            outbound[
                "streamSettings"
            ]["security"] = security

            sni = (
                first_param(
                    query_params,
                    "sni",
                    "",
                )
                or first_param(
                    query_params,
                    "host",
                    "",
                )
            )

            fp = first_param(
                query_params,
                "fp",
                "",
            )

            alpn_raw = first_param(
                query_params,
                "alpn",
                "",
            )

            alpn_list = [
                x.strip()
                for x in alpn_raw.split(",")
                if x.strip()
            ]

            allow_insecure = (
                parse_bool_param(
                    query_params,
                    "allowInsecure",
                    "insecure",
                    default=False,
                )
            )

            if security == "tls":

                tls_settings = {
                    "serverName": sni,
                    "allowInsecure": (
                        allow_insecure
                    ),
                }

                if fp:
                    tls_settings[
                        "fingerprint"
                    ] = fp

                if alpn_list:
                    tls_settings[
                        "alpn"
                    ] = alpn_list

                outbound[
                    "streamSettings"
                ]["tlsSettings"] = (
                    tls_settings
                )

            else:

                # IMPORTANT:
                # current Xray uses "password" for
                # the REALITY public key.
                reality_settings = {
                    "serverName": sni,
                    "password": first_param(
                        query_params,
                        "pbk",
                        "",
                    ),
                    "shortId": first_param(
                        query_params,
                        "sid",
                        "",
                    ),
                    "fingerprint": (
                        fp
                        or "chrome"
                    ),
                }

                spx = first_param(
                    query_params,
                    "spx",
                    "",
                )

                if spx:
                    reality_settings[
                        "spiderX"
                    ] = spx

                # В некоторых старых ссылках поле
                # publicKey могло встречаться вместо pbk.
                if not reality_settings[
                    "password"
                ]:
                    reality_settings[
                        "password"
                    ] = first_param(
                        query_params,
                        "publicKey",
                        "",
                    )

                outbound[
                    "streamSettings"
                ]["realitySettings"] = (
                    reality_settings
                )

        # ====================================================
        # TRANSPORT
        #
        # CURRENT XRAY:
        # streamSettings.method
        # ====================================================

        net = (
            first_param(
                query_params,
                "type",
                "",
            )
            or first_param(
                query_params,
                "net",
                "",
            )
        ).lower()

        if not net:
            net = "raw"

        outbound[
            "streamSettings"
        ]["method"] = net

        path_val = urllib.parse.unquote(
            first_param(
                query_params,
                "path",
                "/",
            )
            or "/"
        )

        host_val = first_param(
            query_params,
            "host",
            "",
        )

        header_type = first_param(
            query_params,
            "headerType",
            "none",
        )

        # ====================================================
        # XHTTP
        # ====================================================

        if net in (
            "xhttp",
            "splithttp",
        ):

            # У текущего Xray transport method называется xhttp.
            outbound[
                "streamSettings"
            ]["method"] = "xhttp"

            extra_data = parse_xhttp_extra(
                query_params
            )

            xhttp_settings = dict(
                extra_data
            )

            # query-параметры имеют приоритет
            # только когда они реально заданы.

            if host_val:
                xhttp_settings[
                    "host"
                ] = host_val

            if path_val:
                xhttp_settings[
                    "path"
                ] = path_val

            mode_val = first_param(
                query_params,
                "mode",
                "",
            )

            if mode_val:
                xhttp_settings[
                    "mode"
                ] = mode_val

            xhttp_settings.setdefault(
                "host",
                "",
            )

            xhttp_settings.setdefault(
                "path",
                "/",
            )

            xhttp_settings.setdefault(
                "mode",
                "auto",
            )

            outbound[
                "streamSettings"
            ]["xhttpSettings"] = (
                xhttp_settings
            )

        # ====================================================
        # WEB SOCKET
        # ====================================================

        elif net == "ws":

            ws_settings = {
                "path": path_val,
            }

            if host_val:
                ws_settings[
                    "headers"
                ] = {
                    "Host": host_val
                }

            else:
                ws_settings[
                    "headers"
                ] = {}

            outbound[
                "streamSettings"
            ]["wsSettings"] = (
                ws_settings
            )

        # ====================================================
        # GRPC
        # ====================================================

        elif net == "grpc":

            grpc_settings = {
                "serviceName": (
                    first_param(
                        query_params,
                        "serviceName",
                        "",
                    )
                    or path_val.lstrip("/")
                )
            }

            authority = first_param(
                query_params,
                "authority",
                "",
            )

            if authority:
                grpc_settings[
                    "authority"
                ] = authority

            outbound[
                "streamSettings"
            ]["grpcSettings"] = (
                grpc_settings
            )

        # ====================================================
        # HTTP UPGRADE
        # ====================================================

        elif net == "httpupgrade":

            outbound[
                "streamSettings"
            ]["httpupgradeSettings"] = {
                "path": path_val,
                "host": host_val,
            }

        # ====================================================
        # HTTP / H2
        # ====================================================

        elif net in (
            "http",
            "h2",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "http"

            outbound[
                "streamSettings"
            ]["httpSettings"] = {
                "path": path_val,
                "host": (
                    [host_val]
                    if host_val
                    else []
                ),
            }

        # ====================================================
        # mKCP
        # ====================================================

        elif net in (
            "kcp",
            "mkcp",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "mkcp"

            outbound[
                "streamSettings"
            ]["kcpSettings"] = {
                "header": {
                    "type": header_type
                }
            }

        # ====================================================
        # RAW
        # ====================================================

        elif net in (
            "tcp",
            "raw",
        ):

            outbound[
                "streamSettings"
            ]["method"] = "raw"

            header_type = first_param(
                query_params,
                "headerType",
                "",
            )

            if header_type:
                outbound[
                    "streamSettings"
                ]["rawSettings"] = {
                    "header": {
                        "type": header_type
                    }
                }

        return outbound

    except Exception:
        return None


# ============================================================
# XRAY VERSION / COMMAND
# ============================================================

def get_xray_executable():
    if os.name == "nt":
        candidates = [
            "./xray.exe",
            "xray.exe",
            "xray",
        ]
    else:
        candidates = [
            "./xray",
            "xray",
        ]

    for exe in candidates:

        if "/" in exe or "\\" in exe:

            if os.path.exists(exe):
                return exe

        else:
            return exe

    return (
        "xray.exe"
        if os.name == "nt"
        else "xray"
    )


def print_xray_version():

    exe = get_xray_executable()

    try:

        result = subprocess.run(
            [
                exe,
                "version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        version_text = (
            result.stdout.strip()
            or result.stderr.strip()
        )

        print(
            "🧩 Xray version:"
        )

        print(
            version_text[:1000]
        )

    except Exception as e:

        print(
            f"⚠️ Не удалось узнать "
            f"версию Xray: {e}"
        )


def get_xray_cmd() -> list:
    return [
        get_xray_executable(),
        "run",
        "-c",
        "stdin:",
    ]


# ============================================================
# XRAY CHECK
# ============================================================

def get_free_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as s:

        s.bind(
            (
                "127.0.0.1",
                0,
            )
        )

        return s.getsockname()[1]


def wait_for_port(
    port: int,
    timeout: float = XRAY_START_TIMEOUT,
) -> bool:

    start = time.time()

    while (
        time.time() - start
        < timeout
    ):

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    port,
                ),
                timeout=0.05,
            ):
                return True

        except (
            OSError,
            ConnectionRefusedError,
        ):
            time.sleep(0.01)

    return False


def get_exit_country_via_proxy(
    opener,
    timeout,
):
    results = []

    try:

        req = urllib.request.Request(
            "http://ip-api.com/json?fields=status,countryCode",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            if (
                data.get("status")
                == "success"
                and data.get(
                    "countryCode"
                )
            ):

                results.append(
                    (
                        "ip-api",
                        data[
                            "countryCode"
                        ].upper(),
                    )
                )

    except Exception:
        pass

    try:

        req = urllib.request.Request(
            "https://api.ip2location.io/",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            if data.get(
                "country_code"
            ):

                results.append(
                    (
                        "ip2location",
                        data[
                            "country_code"
                        ].upper(),
                    )
                )

    except Exception:
        pass

    try:

        req = urllib.request.Request(
            "https://api.ip.sb/geoip",
            headers=HEADERS,
        )

        with opener.open(
            req,
            timeout=timeout,
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    "utf-8"
                )
            )

            cc = (
                data.get(
                    "country_code"
                )
                or data.get(
                    "country"
                )
            )

            if cc:

                results.append(
                    (
                        "ip.sb",
                        cc.upper(),
                    )
                )

    except Exception:
        pass

    if not results:
        return None

    counts = {}

    for _, cc in results:

        counts[cc] = (
            counts.get(
                cc,
                0,
            )
            + 1
        )

    for cc, count in (
        counts.items()
    ):

        if count >= 2:
            return cc

    for name, cc in results:

        if name == "ip-api":
            return cc

    return results[0][1]


def check_via_xray_detailed(
    outbound_obj: dict,
    timeout: float = XRAY_TEST_TIMEOUT,
    min_success_count: int = 2,
):

    port = get_free_port()

    config = {
        "log": {
            "loglevel": "none"
        },
        "inbounds": [
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {
                    "auth": "noauth"
                },
            }
        ],
        "outbounds": [
            outbound_obj
        ],
    }

    proc = None

    try:

        cmd = get_xray_cmd()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        payload = json.dumps(
            config,
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )

        proc.stdin.write(
            payload
        )

        proc.stdin.flush()
        proc.stdin.close()

        if not wait_for_port(
            port,
            XRAY_START_TIMEOUT,
        ):
            return (
                False,
                None,
                "Локальный Xray не запустился",
            )

        proxy_handler = (
            urllib.request.ProxyHandler(
                {
                    "http": (
                        "http://127.0.0.1:"
                        f"{port}"
                    ),
                    "https": (
                        "http://127.0.0.1:"
                        f"{port}"
                    ),
                }
            )
        )

        opener = (
            urllib.request.build_opener(
                proxy_handler
            )
        )

        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.microsoft.com/connecttest.txt",
        ]

        success_count = 0

        for url in test_urls:

            try:

                req = urllib.request.Request(
                    url,
                    headers=HEADERS,
                )

                with opener.open(
                    req,
                    timeout=timeout,
                ) as resp:

                    if resp.status in (
                        200,
                        204,
                    ):
                        success_count += 1

            except Exception:
                pass

        if (
            success_count
            >= min_success_count
        ):

            cc = (
                get_exit_country_via_proxy(
                    opener,
                    timeout,
                )
            )

            return (
                True,
                cc,
                f"OK ({success_count}/3)",
            )

        return (
            False,
            None,
            f"Тест провален "
            f"({success_count}/3)",
        )

    except Exception as e:

        return (
            False,
            None,
            f"Ошибка: "
            f"{type(e).__name__}: {e}",
        )

    finally:

        if proc:

            try:

                proc.terminate()
                proc.wait(
                    timeout=0.5
                )

            except Exception:

                try:
                    proc.kill()
                except Exception:
                    pass


def check_proxy_alive_detailed(
    link: str,
    min_success_count: int = 2,
):

    host, port, orig_name = (
        parse_host_port_and_name(
            link
        )
    )

    if (
        not host
        or not port
        or not is_valid_public_host(
            host
        )
    ):
        return (
            False,
            None,
            "Некорректный формат "
            "хоста/порта",
            None,
        )

    if is_cloudflare_or_warp(
        host
    ):
        return (
            False,
            None,
            "Отфильтрован "
            "(Cloudflare/WARP)",
            None,
        )

    if link.startswith(
        (
            "hysteria2://",
            "hy2://",
        )
    ):
        return (
            False,
            None,
            "Hysteria2 не поддерживается "
            "этим Xray-check",
            None,
        )

    outbound = (
        link_to_xray_outbound(
            link
        )
    )

    if not outbound:
        return (
            False,
            None,
            "Ошибка генерации "
            "JSON для Xray",
            None,
        )

    is_ok, cc, reason = (
        check_via_xray_detailed(
            outbound,
            timeout=XRAY_TEST_TIMEOUT,
            min_success_count=min_success_count,
        )
    )

    if is_ok:

        final_flag = (
            cc_to_flag(cc)
            if cc
            else extract_clean_flag(
                orig_name
            )
        )

        return (
            True,
            (
                link,
                final_flag,
            ),
            reason,
            cc,
        )

    return (
        False,
        None,
        reason,
        None,
    )


# ============================================================
# FETCH SOURCE
# ============================================================

def fetch_single_url_with_details(
    url: str,
) -> dict:

    url_clean = (
        url.strip()
        .replace(
            " ",
            "%20",
        )
    )

    info = {
        "url": url,
        "http_status": None,
        "size_bytes": 0,
        "is_base64": False,
        "total_lines": 0,
        "configs": [],
        "error": None,
    }

    try:

        req = urllib.request.Request(
            url_clean,
            headers=HEADERS,
        )

        with urllib.request.urlopen(
            req,
            timeout=12,
            context=SSL_CONTEXT,
        ) as response:

            info[
                "http_status"
            ] = response.status

            raw_data = (
                response.read()
            )

            info[
                "size_bytes"
            ] = len(
                raw_data
            )

            content = raw_data.decode(
                "utf-8",
                errors="ignore",
            )

            if not any(
                p in content
                for p in SUPPORTED_PROTOCOLS
            ):

                try:

                    decoded = (
                        safe_b64decode(
                            content
                        )
                    )

                    if any(
                        p in decoded
                        for p in SUPPORTED_PROTOCOLS
                    ):
                        content = decoded
                        info[
                            "is_base64"
                        ] = True

                except Exception:
                    pass

            raw_lines = [
                l.strip()
                for l in content.splitlines()
                if l.strip()
            ]

            info[
                "total_lines"
            ] = len(
                raw_lines
            )

            valid_configs = []

            for line in raw_lines:

                if line.startswith(
                    SUPPORTED_PROTOCOLS
                ):

                    valid_configs.append(
                        sanitize_v2rayng_link(
                            line
                        )
                    )

            info[
                "configs"
            ] = valid_configs

    except Exception as e:

        info["error"] = (
            f"{type(e).__name__}: {e}"
        )

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

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
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

            for future in as_completed(
                futures
            ):

                idx = futures[
                    future
                ]

                try:
                    res = (
                        future.result()
                    )

                except Exception as e:

                    print(
                        f"  ├─ ❌ Источник "
                        f"#{idx}: {e}"
                    )

                    continue

                configs = res[
                    "configs"
                ]

                status_str = (
                    f"HTTP "
                    f"{res['http_status']}"
                    if res[
                        "http_status"
                    ]
                    else "ОШИБКА"
                )

                b64_str = (
                    " [Base64]"
                    if res[
                        "is_base64"
                    ]
                    else ""
                )

                err_str = (
                    " (Ошибка: "
                    f"{res['error']})"
                    if res["error"]
                    else ""
                )

                if (
                    res[
                        "http_status"
                    ] in (
                        200,
                        204,
                    )
                    or configs
                ):
                    successful_sources += 1

                print(
                    f"  ├─ 🔗 Источник "
                    f"#{idx:<3} | "
                    f"Статус: "
                    f"{status_str:<10} | "
                    f"Размер: "
                    f"{res['size_bytes']}B | "
                    f"Конфигов: "
                    f"{len(configs)}"
                    f"{b64_str}"
                    f"{err_str}"
                )

                for cfg in configs:

                    links_with_source.append(
                        (
                            cfg,
                            res["url"],
                        )
                    )

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


# ============================================================
# INCOMING
# ============================================================

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


# ============================================================
# DEDUP KEYS
# ============================================================

def get_config_dedup_key(
    link: str,
):
    """
    До теста:
    удаляем только логически абсолютно одинаковые
    конфиги.

    SNI, UUID, path, flow, pbk, sid, fp,
    serviceName и mode входят в ключ.
    """

    host, port, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if not host or not port:
        return None

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    clean_ip = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    protocol = (
        link.split(
            "://",
            1,
        )[0].lower()
        if "://" in link
        else ""
    )

    sni = extract_sni_from_link(
        link
    )

    net = ""
    path = ""
    pbk = ""
    uuid = ""
    security = ""
    flow = ""
    sid = ""
    mode = ""
    fp = ""
    service_name = ""
    authority = ""
    extra_signature = ""

    try:

        if link.startswith(
            "vmess://"
        ):

            b64_data = (
                link.replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = (
                safe_b64decode(
                    b64_data
                )
            )

            data = json.loads(
                decoded
            )

            uuid = str(
                data.get(
                    "id",
                    "",
                )
            )

            net = str(
                data.get(
                    "net",
                    "raw",
                )
            ).lower()

            path = str(
                data.get(
                    "path",
                    "",
                )
            )

            security = str(
                data.get(
                    "tls",
                    "",
                )
            ).lower()

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            uuid = (
                parsed.username
                or ""
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            net = (
                query_params.get(
                    "type",
                    query_params.get(
                        "net",
                        ["raw"],
                    ),
                )[0].lower()
            )

            path = query_params.get(
                "path",
                [""],
            )[0]

            pbk = query_params.get(
                "pbk",
                [""],
            )[0]

            security = (
                query_params.get(
                    "security",
                    [""],
                )[0].lower()
            )

            flow = (
                query_params.get(
                    "flow",
                    [""],
                )[0].lower()
            )

            sid = query_params.get(
                "sid",
                [""],
            )[0]

            mode = (
                query_params.get(
                    "mode",
                    [""],
                )[0].lower()
            )

            fp = (
                query_params.get(
                    "fp",
                    [""],
                )[0].lower()
            )

            service_name = (
                query_params.get(
                    "serviceName",
                    [""],
                )[0]
            )

            authority = (
                query_params.get(
                    "authority",
                    [""],
                )[0]
            )

            # XHTTP extra должен влиять на уникальность.
            extra = (
                parse_xhttp_extra(
                    query_params
                )
            )

            if extra:

                extra_signature = (
                    json.dumps(
                        extra,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )

    except Exception:
        pass

    path = (
        urllib.parse.unquote(
            path
        )
        or "/"
    )

    return (
        protocol,
        clean_ip,
        str(port),
        sni,
        net,
        path,
        pbk,
        uuid,
        security,
        flow,
        sid,
        mode,
        fp,
        service_name,
        authority,
        extra_signature,
    )


def get_final_dedup_key(
    link: str,
):
    """
    После теста.

    Немного более грубый ключ:
    одинаковый endpoint / SNI / transport / path /
    security считается дублем.
    """

    host, port, _ = (
        parse_host_port_and_name(
            link
        )
    )

    if not host or not port:
        return None

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    clean_ip = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    protocol = (
        link.split(
            "://",
            1,
        )[0].lower()
        if "://" in link
        else ""
    )

    sni = extract_sni_from_link(
        link
    )

    net = ""
    path = "/"
    security = ""
    fp = ""

    try:

        if link.startswith(
            "vmess://"
        ):

            b64_data = (
                link.replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = (
                safe_b64decode(
                    b64_data
                )
            )

            data = json.loads(
                decoded
            )

            net = str(
                data.get(
                    "net",
                    "raw",
                )
            ).lower()

            path = (
                str(
                    data.get(
                        "path",
                        "",
                    )
                )
                or "/"
            )

            security = str(
                data.get(
                    "tls",
                    "",
                )
            ).lower()

            fp = str(
                data.get(
                    "fp",
                    "",
                )
            ).lower()

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            net = (
                query_params.get(
                    "type",
                    query_params.get(
                        "net",
                        ["raw"],
                    ),
                )[0].lower()
            )

            path = (
                query_params.get(
                    "path",
                    [""],
                )[0]
                or "/"
            )

            security = (
                query_params.get(
                    "security",
                    [""],
                )[0].lower()
            )

            fp = (
                query_params.get(
                    "fp",
                    [""],
                )[0].lower()
            )

    except Exception:
        pass

    path = (
        urllib.parse.unquote(
            path
        )
        or "/"
    )

    return (
        protocol,
        clean_ip,
        str(port),
        sni,
        net,
        path,
        security,
        fp,
    )


# ============================================================
# PRE-PING DEDUP
# ============================================================

def clean_and_dedup(
    tagged_items: list,
) -> list:

    seen_strings = set()
    seen_keys = set()
    result = []

    for link, source in tagged_items:

        link = link.strip()

        if not link.startswith(
            SUPPORTED_PROTOCOLS
        ):
            continue

        # Полный текстовый дубль
        if link in seen_strings:
            continue

        seen_strings.add(link)

        # Логический дубль
        key = get_config_dedup_key(
            link
        )

        if not key:
            continue

        if key in seen_keys:
            continue

        seen_keys.add(key)

        result.append(
            (
                link,
                source,
            )
        )

    print(
        f"🧹 Дедуп ДО пинга: "
        f"было {len(tagged_items)}, "
        f"осталось {len(result)}."
    )

    return result


# ============================================================
# BL LIMIT
# ============================================================

def limit_bl_configs_per_ip(
    items_list: list,
) -> list:
    """
    Лимиты применяются ТОЛЬКО к BL.

    Это важно:
    WL по словам / RU IP / RU SNI не должен попасть
    под BL-лимит только потому, что его IP нет в white_ips.
    """

    ip_counter = defaultdict(int)
    subnet_counter = defaultdict(int)

    grouped = defaultdict(list)

    for item in items_list:

        link = item[0]

        host, _, _ = (
            parse_host_port_and_name(
                link
            )
        )

        if not host:
            continue

        clean_host = (
            host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

        ip_str = (
            resolve_host_cached(
                clean_host
            )
            or clean_host
        )

        grouped[
            ip_str
        ].append(
            item
        )

    result = []

    for ip_str, items in grouped.items():

        for item in items:

            if (
                ip_counter[ip_str]
                >= MAX_CONFIGS_PER_IP_BL
            ):
                break

            try:

                ip_obj = ipaddress.ip_address(
                    ip_str
                )

                if ip_obj.version == 4:

                    subnet_key = str(
                        ipaddress.ip_network(
                            f"{ip_str}/24",
                            strict=False,
                        )
                    )

                else:

                    subnet_key = str(
                        ipaddress.ip_network(
                            f"{ip_str}/64",
                            strict=False,
                        )
                    )

                if (
                    subnet_counter[
                        subnet_key
                    ]
                    >= MAX_CONFIGS_PER_SUBNET_BL
                ):
                    continue

                subnet_counter[
                    subnet_key
                ] += 1

            except Exception:
                pass

            ip_counter[
                ip_str
            ] += 1

            result.append(
                item
            )

    print(
        f"✂️ BL лимиты ДО пинга: "
        f"было {len(items_list)}, "
        f"осталось {len(result)} | "
        f"IP={MAX_CONFIGS_PER_IP_BL}, "
        f"/24={MAX_CONFIGS_PER_SUBNET_BL}"
    )

    return result


# ============================================================
# WL DIVERSITY
# ============================================================

def get_wl_item_info(
    item,
):
    link = item[0]

    host, port, orig_name = (
        parse_host_port_and_name(
            link
        )
    )

    clean_host = (
        host.strip(
            '[] \t\r\n\'"'
        ).lower()
        if host
        else ""
    )

    ip_str = (
        resolve_host_cached(
            clean_host
        )
        or clean_host
    )

    flag = (
        item[1]
        if len(item) > 1
        else extract_clean_flag(
            orig_name
        )
    )

    sni = extract_sni_from_link(
        link
    )

    path = "/"

    try:

        if link.startswith(
            "vmess://"
        ):

            decoded = (
                safe_b64decode(
                    link
                    .replace(
                        "vmess://",
                        "",
                        1,
                    )
                    .strip()
                )
            )

            data = json.loads(
                decoded
            )

            sni = (
                data.get("sni")
                or data.get("host")
                or sni
                or ""
            )

            path = (
                str(
                    data.get(
                        "path",
                        "/",
                    )
                )
                or "/"
            )

        else:

            parsed = (
                urllib.parse.urlparse(
                    link
                )
            )

            query_params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            path = (
                query_params.get(
                    "path",
                    ["/"],
                )[0]
                or "/"
            )

    except Exception:
        pass

    return {
        "link": link,
        "ip": ip_str,
        "flag": flag,
        "sni": (
            sni or ""
        ).lower(),
        "path": urllib.parse.unquote(
            path
        ),
        "source": (
            item[2]
            if len(item) > 2
            else ""
        ),
    }


def select_wl_diverse(
    alive_items: list,
) -> list:
    """
    WL отбирается ПОСЛЕ проверки.

    Не уничтожаем сотни SNI ДО теста.

    Приоритет:
      1. разные IP;
      2. новые SNI;
      3. новые флаги;
      4. новый path;
      5. новые SNI+path.

    На один IP максимум MAX_CONFIGS_PER_IP_WL.
    """

    if not alive_items:
        return []

    grouped = defaultdict(list)

    for item in alive_items:
        info = get_wl_item_info(
            item
        )

        grouped[
            info["ip"]
        ].append(
            (
                item,
                info,
            )
        )

    result = []

    for ip_str, entries in grouped.items():

        selected = []

        used_sni = set()
        used_flags = set()
        used_paths = set()
        used_pairs = set()

        # Новые SNI из PREV_* не считаем
        # новыми предпочтительными.
        old_snis = set()

        for item, info in entries:

            if str(
                info["source"]
            ).startswith(
                "PREV_"
            ):

                if info["sni"]:
                    old_snis.add(
                        info["sni"]
                    )

        def score(
            entry,
        ):
            item, info = entry

            s = 0

            # Новый SNI
            if (
                info["sni"]
                and info["sni"]
                not in used_sni
            ):
                s += 1000

            # SNI, которого не было в старом списке
            if (
                info["sni"]
                and info["sni"]
                not in old_snis
                and not str(
                    info["source"]
                ).startswith(
                    "PREV_"
                )
            ):
                s += 700

            # Новый флаг
            if (
                info["flag"]
                not in used_flags
            ):
                s += 500

            # Новый SNI + path
            pair = (
                info["sni"],
                info["path"],
            )

            if pair not in used_pairs:
                s += 300

            # Новый path
            if (
                info["path"]
                not in used_paths
            ):
                s += 100

            # Новые конфиги чуть выше старых
            if not str(
                info["source"]
            ).startswith(
                "PREV_"
            ):
                s += 10

            return s

        remaining = list(
            entries
        )

        while (
            remaining
            and len(selected)
            < MAX_CONFIGS_PER_IP_WL
        ):

            remaining.sort(
                key=score,
                reverse=True,
            )

            item, info = (
                remaining.pop(0)
            )

            selected.append(
                item
            )

            if info["sni"]:
                used_sni.add(
                    info["sni"]
                )

            used_flags.add(
                info["flag"]
            )

            used_paths.add(
                info["path"]
            )

            used_pairs.add(
                (
                    info["sni"],
                    info["path"],
                )
            )

        result.extend(
            selected
        )

    print(
        f"🎨 WL diversity: "
        f"до={len(alive_items)}, "
        f"после={len(result)}"
    )

    return result


# ============================================================
# BL PROTOCOL FILTER
#
# НЕ МЕНЯЮ.
# ============================================================

def filter_protocols_bl(
    alive_configs,
    minority_ratio=0.10,
):

    priority = []
    minority = []

    for item in alive_configs:

        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        proto = (
            link
            .split(
                "://",
                1,
            )[0]
            .lower()
        )

        if proto in (
            "vless",
            "hysteria2",
            "hy2",
        ):

            priority.append(
                item
            )

        else:

            minority.append(
                item
            )

    max_minority = max(
        10,
        int(
            len(priority)
            * (
                minority_ratio
                / (
                    1
                    - minority_ratio
                )
            )
        ),
    )

    if len(minority) > max_minority:

        minority = minority[
            :max_minority
        ]

    print(
        f"🎯 Фильтр BL протоколов: "
        f"VLESS/Hy2: "
        f"{len(priority)} шт. | "
        f"Старые: "
        f"{len(minority)} шт. "
        f"(лимит "
        f"{minority_ratio * 100:.0f}%)"
    )

    return (
        priority
        + minority
    )


# ============================================================
# RENAME
# ============================================================

def rename_config(
    link: str,
    index: int,
    tag: str,
    detected_flag: str,
) -> str:

    new_name = (
        f"{detected_flag} "
        f"{tag} Сервер {index}"
    )

    if link.startswith(
        "vmess://"
    ):

        try:

            b64_data = (
                link
                .replace(
                    "vmess://",
                    "",
                    1,
                )
                .strip()
            )

            decoded = (
                safe_b64decode(
                    b64_data
                )
            )

            data = json.loads(
                decoded
            )

            data["ps"] = (
                new_name
            )

            encoded = (
                base64.b64encode(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                    ).encode(
                        "utf-8"
                    )
                )
                .decode(
                    "utf-8"
                )
            )

            return (
                "vmess://"
                + encoded
            )

        except Exception:
            pass

    if "://" in link:

        main_part = link.split(
            "#",
            1,
        )[0]

        return (
            main_part
            + "#"
            + urllib.parse.quote(
                new_name
            )
        )

    return link


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "🚀 Старт продвинутого Xray-парсера..."
    )

    print(
        "⚙️ WL: тест 1/3"
    )

    print(
        "⚙️ BL: тест 2/3"
    )

    print(
        "⚙️ WL: IP/keywords/RU IP/RU SNI сохраняются"
    )

    print(
        "⚙️ Старые alive-конфиги используются"
    )

    print(
        "⚙️ BL /24 и протокольный фильтр сохраняются"
    )

    print_xray_version()

    wl_file = (
        "sources_wl.txt"
        if os.path.exists(
            "sources_wl.txt"
        )
        else "source_wl.txt"
    )

    bl_file = (
        "sources_bl.txt"
        if os.path.exists(
            "sources_bl.txt"
        )
        else "source_bl.txt"
    )

    # ========================================================
    # 1. SOURCES
    # ========================================================

    wl_fetched = (
        fetch_links_parallel_with_source(
            wl_file
        )
    )

    bl_fetched = (
        fetch_links_parallel_with_source(
            bl_file
        )
    )

    incoming_proxies, incoming_raw_ips = (
        process_incoming_queue()
    )

    # ========================================================
    # 2. WHITE IP
    # ========================================================

    white_ips = set()

    if os.path.exists(
        WHITE_IP_FILE
    ):

        try:

            with open(
                WHITE_IP_FILE,
                "r",
                encoding="utf-8",
            ) as f:

                for line in f:

                    white_ips.update(
                        parse_ip_or_resolve(
                            line
                        )
                    )

        except Exception as e:

            print(
                f"⚠️ Ошибка чтения "
                f"{WHITE_IP_FILE}: {e}"
            )

    for item in incoming_raw_ips:

        white_ips.update(
            parse_ip_or_resolve(
                item
            )
        )

    def ip_sort_key(ip):

        try:
            return (
                0,
                ipaddress.ip_address(
                    ip
                )
            )

        except ValueError:

            return (
                1,
                ip,
            )

    with open(
        WHITE_IP_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        for ip in sorted(
            list(
                white_ips
            ),
            key=ip_sort_key,
        ):

            f.write(
                ip
                + "\n"
            )

    print(
        f"💾 White IP база: "
        f"{len(white_ips)} IP"
    )

    # ========================================================
    # 3. OLD ALIVE
    # ========================================================

    prev_wl_links, prev_bl_links = (
        load_previous_alives()
    )

    # ========================================================
    # 4. ALL CANDIDATES
    # ========================================================

    tagged_items = []

    # NEW WL source
    for link, src in wl_fetched:

        tagged_items.append(
            (
                link,
                src,
            )
        )

    # NEW BL source
    for link, src in bl_fetched:

        tagged_items.append(
            (
                link,
                src,
            )
        )

    # Telegram
    for link in incoming_proxies:

        tagged_items.append(
            (
                link,
                "INCOMING_TELEGRAM",
            )
        )

    # PREVIOUS WL
    for link in prev_wl_links:

        tagged_items.append(
            (
                link,
                "PREV_WL",
            )
        )

    # PREVIOUS BL
    for link in prev_bl_links:

        tagged_items.append(
            (
                link,
                "PREV_BL",
            )
        )

    print(
        f"\n📦 Всего кандидатов "
        f"до дедупликации: "
        f"{len(tagged_items)}"
    )

    # ========================================================
    # 5. EXACT/LOGICAL DEDUP
    # ========================================================

    clean_items = (
        clean_and_dedup(
            tagged_items
        )
    )

    # ========================================================
    # 6. CLASSIFY FIRST
    #
    # КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ:
    #
    # Раньше BL limit применялся к ВСЕМ конфигам
    # ДО classify_config().
    #
    # Поэтому WL по keyword/RU-IP/RU-SNI мог
    # быть ошибочно ограничен как BL.
    #
    # Теперь сначала классифицируем.
    # ========================================================

    pre_ping_wl = []
    pre_ping_bl = []

    for link, src in clean_items:

        host, port, orig_name = (
            parse_host_port_and_name(
                link
            )
        )

        if (
            not host
            or not port
            or not is_valid_public_host(
                host
            )
        ):
            continue

        category = classify_config(
            link,
            white_ips,
            RU_SNI_RATIO,
        )

        if category == "WL":

            pre_ping_wl.append(
                (
                    link,
                    src,
                )
            )

        else:

            pre_ping_bl.append(
                (
                    link,
                    src,
                )
            )

    print(
        f"\n🧠 Классификация ДО пинга:"
        f"\n   WL: {len(pre_ping_wl)}"
        f"\n   BL: {len(pre_ping_bl)}"
    )

    # ========================================================
    # 7. ONLY BL LIMIT
    #
    # WL не режем здесь вообще.
    # ========================================================

    pre_ping_bl = (
        limit_bl_configs_per_ip(
            pre_ping_bl
        )
    )

    print(
        f"\n📡 После BL-предлимита:"
        f"\n   WL: {len(pre_ping_wl)}"
        f"\n   BL: {len(pre_ping_bl)}"
    )

    # ========================================================
    # 8. PING WL
    #
    # ВСЕ WL-кандидаты проходят тест 1/3.
    # ========================================================

    ping_wl = []
    seen_wl = set()

    for link, src in pre_ping_wl:

        if link in seen_wl:
            continue

        seen_wl.add(
            link
        )

        ping_wl.append(
            (
                link,
                src,
            )
        )

    # ========================================================
    # 9. PING BL
    #
    # BL тест 2/3.
    # ========================================================

    ping_bl = []
    seen_bl = set()

    for link, src in pre_ping_bl:

        if link in seen_bl:
            continue

        seen_bl.add(
            link
        )

        ping_bl.append(
            (
                link,
                src,
            )
        )

    print(
        f"\n📡 Xray очередь:"
        f"\n   WL: {len(ping_wl)}"
        f"\n   BL: {len(ping_bl)}"
    )

    # ========================================================
    # 10. TEST WL + BL
    # ========================================================

    alive_wl_data = []
    alive_bl_data = []

    wl_ok = 0
    wl_fail = 0

    bl_ok = 0
    bl_fail = 0

    bl_ru_to_wl = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        # ----------------------------------------------------
        # WL 1/3
        # ----------------------------------------------------

        wl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                WL_MIN_SUCCESS_COUNT,
            ): (
                link,
                src,
            )
            for link, src in ping_wl
        }

        for future in as_completed(
            wl_futures
        ):

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception:
                continue

            if is_ok:

                alive_wl_data.append(
                    res
                )

                wl_ok += 1

            else:

                wl_fail += 1

        print(
            f"\n🟢 WL тест завершён: "
            f"OK={wl_ok}, "
            f"FAIL={wl_fail}"
        )

        # ----------------------------------------------------
        # BL 2/3
        # ----------------------------------------------------

        bl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                BL_MIN_SUCCESS_COUNT,
            ): (
                link,
                src,
            )
            for link, src in ping_bl
        }

        for future in as_completed(
            bl_futures
        ):

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception:
                continue

            if not is_ok:

                bl_fail += 1
                continue

            bl_ok += 1

            # Живой BL с RU exit -> WL.
            if (
                cc
                and cc.upper()
                == "RU"
            ):

                alive_wl_data.append(
                    res
                )

                bl_ru_to_wl += 1

            else:

                alive_bl_data.append(
                    res
                )

    print(
        f"\n🔴 BL тест завершён: "
        f"OK={bl_ok}, "
        f"FAIL={bl_fail}, "
        f"RU→WL={bl_ru_to_wl}"
    )

    # ========================================================
    # 11. WL DEDUP AFTER TEST
    # ========================================================

    alive_wl_data = (
        dedup_advanced(
            alive_wl_data,
            "WL после Xray",
        )
    )

    # ========================================================
    # 12. WL DIVERSITY AFTER TEST
    #
    # Только сейчас применяем 30/IP.
    # ========================================================

    alive_wl_clean = (
        select_wl_diverse(
            alive_wl_data
        )
    )

    alive_wl_clean = (
        dedup_advanced(
            alive_wl_clean,
            "WL после diversity",
        )
    )

    # ========================================================
    # 13. BL DEDUP
    # ========================================================

    alive_bl_data = (
        dedup_advanced(
            alive_bl_data,
            "BL после Xray",
        )
    )

    # ========================================================
    # 14. BL LIMIT AFTER TEST
    #
    # Сохраняем:
    # IP = 2
    # /24 = 5
    # ========================================================

    alive_bl_limited = (
        limit_bl_configs_per_ip(
            alive_bl_data
        )
    )

    # ========================================================
    # 15. BL PROTOCOL FILTER
    #
    # НЕ МЕНЯЕМ.
    # ========================================================

    alive_bl_clean = (
        filter_protocols_bl(
            alive_bl_limited,
            minority_ratio=0.10,
        )
    )

    # ========================================================
    # 16. FULL
    # ========================================================

    alive_full_raw = (
        alive_wl_clean
        + alive_bl_clean
    )

    alive_full_clean = (
        dedup_advanced(
            alive_full_raw,
            "FULL",
        )
    )

    # --------------------------------------------------------
    # Для FULL не применяем BL-ограничение к WL.
    # --------------------------------------------------------

    wl_keys = set()

    for item in alive_wl_clean:

        key = get_final_dedup_key(
            item[0]
        )

        if key:
            wl_keys.add(
                key
            )

    full_wl = []
    full_bl = []

    for item in alive_full_clean:

        key = get_final_dedup_key(
            item[0]
        )

        if key in wl_keys:
            full_wl.append(
                item
            )
        else:
            full_bl.append(
                item
            )

    # BL ограничиваем ещё раз для FULL.
    full_bl = limit_bl_configs_per_ip(
        full_bl
    )

    alive_full_clean = (
        full_wl
        + full_bl
    )

    # ========================================================
    # 17. RENAME
    # ========================================================

    final_wl = [
        rename_config(
            item[0],
            idx,
            "[WL]",
            item[1],
        )
        for idx, item in enumerate(
            alive_wl_clean,
            1,
        )
    ]

    final_bl = [
        rename_config(
            item[0],
            idx,
            "[BL]",
            item[1],
        )
        for idx, item in enumerate(
            alive_bl_clean,
            1,
        )
    ]

    final_full = []

    for idx, item in enumerate(
        alive_full_clean,
        1,
    ):

        key = get_final_dedup_key(
            item[0]
        )

        tag = (
            "[WL]"
            if key in wl_keys
            else "[BL]"
        )

        final_full.append(
            rename_config(
                item[0],
                idx,
                tag,
                item[1],
            )
        )

    # ========================================================
    # 18. SAVE
    # ========================================================

    with open(
        "alive_bs.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_wl
                )
            )
        )

    with open(
        "alive_bl.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_bl
                )
            )
        )

    with open(
        "alive_full.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            safe_b64encode(
                "\n".join(
                    final_full
                )
            )
        )

    # ========================================================
    # CLOSE GEO
    # ========================================================

    if GEO_READER:

        try:
            GEO_READER.close()
        except Exception:
            pass

    # ========================================================
    # FINAL STATS
    # ========================================================

    print()
    print("=" * 70)
    print("📊 ФИНАЛЬНАЯ СТАТИСТИКА")
    print("=" * 70)

    print(
        f"WL кандидатов:       {len(ping_wl)}"
    )

    print(
        f"WL живых:             {wl_ok}"
    )

    print(
        f"WL после diversity:   {len(final_wl)}"
    )

    print(
        f"BL кандидатов:        {len(ping_bl)}"
    )

    print(
        f"BL живых:             {bl_ok}"
    )

    print(
        f"BL финал:             {len(final_bl)}"
    )

    print(
        f"BL RU → WL:           {bl_ru_to_wl}"
    )

    print(
        f"FULL:                 {len(final_full)}"
    )

    print(
        f"White IP:             {len(white_ips)}"
    )

    print("=" * 70)

    print(
        "✨ Готово!"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    init_geoip()

    main()