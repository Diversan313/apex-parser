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
# НАСТРОЙКИ
# ============================================================

WHITE_IP_FILE = "white_ip.txt"
INCOMING_FILE = "incoming_sources.txt"

MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

MAX_QUEUE_LIMIT = 1000
MAX_WORKERS = 15

# WL не режем по количеству конфигов на IP.
MAX_CONFIGS_PER_IP_WL = 100000

# BL:
# оставляем исходную логику:
# несколько конфигов с одного IP + ограничение по /24.
MAX_CONFIGS_PER_IP_BL = 2
MAX_CONFIGS_PER_SUBNET_BL = 5

# BL: VLESS / Hysteria имеют приоритет,
# старые протоколы максимум около 10%.
BL_MINORITY_RATIO = 0.10

# WL проверяем по 1 успешному тесту из 3.
WL_MIN_SUCCESS_COUNT = 1

# BL проверяем по 2 из 3.
BL_MIN_SUCCESS_COUNT = 2

# Для старого поведения RU SNI.
RU_SNI_RATIO = 0.30


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
    r"глушилк(?:а|и|ок|ам|ах)?|"
    r"whitelist|lte|"
    r"бел(?:ый|ые|ых)\s*списк(?:и|а|ов|ам|ах)?)"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)

FLAG_REGEX = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


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


# ============================================================
# CLOUDFLARE
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

        with open(MMDB_PATH, "wb") as out_file:
            out_file.write(data)

        print("✅ База GeoIP успешно загружена!")

    except Exception as e:
        print(f"⚠️ Ошибка загрузки базы GeoIP: {e}")


download_geoip_db()


GEO_READER = None

if maxminddb and os.path.exists(MMDB_PATH):
    try:
        GEO_READER = maxminddb.open_database(MMDB_PATH)
    except Exception:
        GEO_READER = None


# ============================================================
# BASE64
# ============================================================

def safe_b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)

    return base64.b64decode(
        s
    ).decode(
        "utf-8",
        errors="ignore",
    )


# ============================================================
# SANITIZE
# ============================================================

def sanitize_v2rayng_link(link: str) -> str:
    """
    Исправляет только явно проблемные auto-параметры.

    ВАЖНО:
    extra XHTTP здесь НЕ удаляем.
    """

    try:
        if link.startswith("vmess://"):
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)

            if str(data.get("net", "")).lower() in (
                "auto",
                "none",
                "",
            ):
                data["net"] = "tcp"

            if str(data.get("tls", "")).lower() == "auto":
                data["tls"] = ""

            if str(data.get("type", "")).lower() == "auto":
                data["type"] = "none"

            encoded = base64.b64encode(
                json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("utf-8")

            return f"vmess://{encoded}"

        main_part = link
        name_part = ""

        if "#" in link:
            main_part, name_part = link.split(
                "#",
                1,
            )

        base = main_part
        query_part = ""

        if "?" in main_part:
            base, query_part = main_part.split(
                "?",
                1,
            )

        if query_part:
            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            changed = False

            if base.startswith("vless://"):
                if (
                    "encryption" not in params
                    or params["encryption"][0].lower()
                    in ("auto", "")
                ):
                    params["encryption"] = ["none"]
                    changed = True

            if (
                "type" in params
                and params["type"][0].lower() == "auto"
            ):
                params["type"] = ["tcp"]
                changed = True

            if (
                "net" in params
                and params["net"][0].lower() == "auto"
            ):
                params["net"] = ["tcp"]
                changed = True

            if (
                "security" in params
                and params["security"][0].lower() == "auto"
            ):
                del params["security"]
                changed = True

            if changed:
                new_query = urllib.parse.urlencode(
                    params,
                    doseq=True,
                )

                new_query = new_query.replace(
                    "+",
                    "%20",
                )

                new_link = (
                    f"{base}?{new_query}"
                )

                if name_part:
                    new_link += f"#{name_part}"

                return new_link

    except Exception:
        pass

    return link


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

    return flags[0] if flags else "🌐"


# ============================================================
# HOST VALIDATION
# ============================================================

def is_valid_public_host(host: str) -> bool:
    if not host:
        return False

    clean_host = host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not clean_host or clean_host.isdigit():
        return False

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        if (
            ip_obj.version == 4
            and "." not in clean_host
        ):
            return False

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

    if not DOMAIN_REGEX.match(clean_host):
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

    if not is_valid_public_host(clean_host):
        return None

    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[clean_host]

    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        with DNS_LOCK:
            DNS_CACHE[clean_host] = clean_host

        return clean_host

    except ValueError:
        pass

    try:
        socket.setdefaulttimeout(2.0)

        ip = socket.gethostbyname(
            clean_host
        )

        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            resolved_ip = None
        else:
            resolved_ip = ip

    except Exception:
        resolved_ip = None

    with DNS_LOCK:
        DNS_CACHE[clean_host] = resolved_ip

    return resolved_ip


# ============================================================
# GEO
# ============================================================

def fetch_country_from_ip(ip_str: str) -> str:
    if not ip_str:
        return None

    if not is_valid_public_host(ip_str):
        return None

    if GEO_READER:
        try:
            record = GEO_READER.get(ip_str)

            if (
                record
                and "country" in record
                and "iso_code" in record["country"]
            ):
                return record["country"]["iso_code"]

        except Exception:
            pass

    with GEO_LOCK:
        if ip_str in GEO_ONLINE_CACHE:
            return GEO_ONLINE_CACHE[ip_str]

    try:
        url = (
            f"http://ip-api.com/json/"
            f"{ip_str}?fields=status,countryCode"
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
                    "utf-8",
                    errors="ignore",
                )
            )

        if (
            data.get("status") == "success"
            and data.get("countryCode")
        ):
            cc = data["countryCode"]

            with GEO_LOCK:
                GEO_ONLINE_CACHE[ip_str] = cc

            return cc

    except Exception:
        pass

    return None


# ============================================================
# CLOUDFLARE / WARP
# ============================================================

def is_cloudflare_or_warp(host: str) -> bool:
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

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        ):
            return True

        if ip_obj.version == 4:
            for network in CF_NETWORKS:
                if ip_obj in network:
                    return True

        elif ip_obj.version == 6:
            if str(ip_obj).startswith(
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
# HOST / PORT
# ============================================================

def parse_host_port(server_part: str):
    if not server_part:
        return None, None

    server_part = server_part.rstrip("/")

    try:
        if server_part.startswith("["):
            if "]" in server_part:
                host_b, rest = server_part.split(
                    "]",
                    1,
                )

                host = host_b + "]"

                port_str = (
                    rest
                    .lstrip(":")
                    .split("/")[0]
                    .split("?")[0]
                )

                return host, int(port_str)

        if ":" in server_part:
            host, port_str = server_part.rsplit(
                ":",
                1,
            )

            port_str = (
                port_str
                .split("/")[0]
                .split("?")[0]
            )

            return host, int(port_str)

    except Exception:
        pass

    return None, None


# ============================================================
# PARSE LINK
# ============================================================

def parse_host_port_and_name(link: str):
    try:
        orig_name = ""

        if "#" in link:
            orig_name = urllib.parse.unquote(
                link.split("#", 1)[1]
            )

        clean_link = link.split("#")[0]

        if clean_link.startswith(
            (
                "vless://",
                "trojan://",
                "ss://",
                "hysteria2://",
                "hy2://",
            )
        ):
            protocol, rest = clean_link.split(
                "://",
                1,
            )

            # Не отрезаем query до парсинга ss.
            rest_without_query = rest.split(
                "?",
                1,
            )[0]

            if protocol == "ss":
                if "@" not in rest_without_query:
                    try:
                        decoded = safe_b64decode(
                            rest_without_query
                        )

                        if "@" in decoded:
                            _, host_port = decoded.rsplit(
                                "@",
                                1,
                            )

                            host, port = parse_host_port(
                                host_port
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
                        rest_without_query.rsplit(
                            "@",
                            1,
                        )
                    )

                    host, port = parse_host_port(
                        host_port
                    )

                    return (
                        host,
                        port,
                        orig_name,
                    )

            else:
                rest_without_query = rest_without_query

                if "@" in rest_without_query:
                    rest_without_query = (
                        rest_without_query.rsplit(
                            "@",
                            1,
                        )[1]
                    )

                host, port = parse_host_port(
                    rest_without_query
                )

                return (
                    host,
                    port,
                    orig_name,
                )

        elif clean_link.startswith("vmess://"):
            b64_data = clean_link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

            return (
                data.get("add"),
                int(data.get("port")),
                data.get("ps", ""),
            )

    except Exception:
        pass

    return None, None, ""


# ============================================================
# SNI
# ============================================================

def extract_sni_from_link(link: str) -> str:
    try:
        if "?" in link:
            query_part = (
                link
                .split("?", 1)[1]
                .split("#")[0]
            )

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

            sni = (
                params.get("sni", [""])[0]
                or params.get("host", [""])[0]
            )

            if sni:
                return sni.lower().strip()

        if link.startswith("vmess://"):
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

            return (
                data.get("sni")
                or data.get("host")
                or ""
            ).lower().strip()

    except Exception:
        pass

    return ""


# ============================================================
# ALL HOSTS
# ============================================================

def extract_all_hosts_and_ips_from_link(link: str) -> list:
    hosts = set()

    main_host, _, _ = (
        parse_host_port_and_name(link)
    )

    if main_host:
        hosts.add(
            main_host.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    sni = extract_sni_from_link(link)

    if sni:
        hosts.add(
            sni.strip(
                '[] \t\r\n\'"'
            ).lower()
        )

    if "?" in link:
        try:
            query_part = (
                link
                .split("?", 1)[1]
                .split("#")[0]
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
                    h_param.strip(
                        '[] \t\r\n\'"'
                    ).lower()
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

            if not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
            ):
                hosts.add(ip_cand)

        except ValueError:
            pass

    return list(hosts)


# ============================================================
# IP PARSER
# ============================================================

def parse_ip_or_resolve(item: str) -> set:
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
        item
        .split("/")[0]
        .split("?")[0]
        .split("#")[0]
        .strip()
    )

    host, _ = parse_host_port(item)

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

        if not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return {str(ip_obj)}

    except ValueError:
        pass

    resolved_ip = resolve_host_cached(
        clean_host
    )

    if resolved_ip:
        try:
            ip_obj = ipaddress.ip_address(
                resolved_ip
            )

            if not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
            ):
                return {resolved_ip}

        except ValueError:
            pass

    return set()


# ============================================================
# WHITE IP MATCH
# ============================================================

def find_matched_ip_for_link(
    link: str,
    white_ips: set,
):
    if not white_ips:
        return None

    all_hosts = (
        extract_all_hosts_and_ips_from_link(
            link
        )
    )

    for host in all_hosts:
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

        resolved_ip = resolve_host_cached(
            clean_host
        )

        if (
            resolved_ip
            and resolved_ip in white_ips
        ):
            return resolved_ip

    return None


# ============================================================
# CLASSIFICATION
# ============================================================

def is_wl_by_keywords(
    link: str,
    orig_name: str = "",
) -> bool:
    full_text = f"{link} {orig_name}"

    try:
        full_text = urllib.parse.unquote(
            full_text
        )
    except Exception:
        pass

    return bool(
        WL_KEYWORDS_REGEX.search(
            full_text
        )
    )


def is_ru_sni(link: str) -> bool:
    link_low = link.lower()

    if re.search(
        r"sni=[^&]*\.(ru|su)(?:&|$)",
        link_low,
    ):
        return True

    if link.startswith("vmess://"):
        try:
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

            values = [
                data.get("sni", ""),
                data.get("host", ""),
                data.get("add", ""),
            ]

            for value in values:
                if not value:
                    continue

                value = str(value).lower()

                if (
                    value.endswith(".ru")
                    or value.endswith(".su")
                    or ".ru:" in value
                ):
                    return True

        except Exception:
            pass

    else:
        host, _, _ = (
            parse_host_port_and_name(link)
        )

        if host:
            host_low = host.lower()

            if (
                host_low.endswith(".ru")
                or host_low.endswith(".su")
                or ".ru]" in host_low
            ):
                return True

    return False


def classify_config(
    link: str,
    white_ips: set,
    ru_sni_ratio: float = RU_SNI_RATIO,
) -> str:

    # 1. Белый IP — WL
    matched_ip = find_matched_ip_for_link(
        link,
        white_ips,
    )

    if matched_ip:
        return "WL"

    host, _, orig_name = (
        parse_host_port_and_name(link)
    )

    if (
        not host
        or not is_valid_public_host(host)
    ):
        return "BL"

    # 2. Ключевые слова — WL
    if is_wl_by_keywords(
        link,
        orig_name,
    ):
        return "WL"

    # 3. Российский IP — WL
    clean_ip = resolve_host_cached(
        host.strip(
            '[] \t\r\n\'"'
        ).lower()
    )

    if clean_ip:
        cc = fetch_country_from_ip(
            clean_ip
        )

        if cc and cc.upper() == "RU":
            return "WL"

    # 4. RU/SU SNI — вероятностный WL
    if is_ru_sni(link):
        if random.random() < ru_sni_ratio:
            return "WL"

    return "BL"


# ============================================================
# XHTTP EXTRA
# ============================================================

def parse_xhttp_extra(query_params):
    """
    Берёт extra из ссылки и превращает URL-encoded JSON
    в обычный dict.

    Важнейшее исправление относительно старой версии:
    extra НЕ выбрасывается.
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

        obj = json.loads(decoded)

        if isinstance(obj, dict):
            return obj

    except Exception:
        pass

    return {}


def normalize_xhttp_settings(
    query_params,
):
    """
    Формирует xhttpSettings.

    Query-параметры являются основой:
      host
      path
      mode

    extra сохраняется целиком.

    При этом пустые значения из extra не затирают
    рабочие query-параметры.
    """

    extra = parse_xhttp_extra(
        query_params
    )

    path = query_params.get(
        "path",
        [""],
    )[0]

    host = query_params.get(
        "host",
        [""],
    )[0]

    mode = query_params.get(
        "mode",
        [""],
    )[0]

    if not path:
        path = extra.get(
            "path",
            "/",
        ) or "/"

    if not host:
        host = extra.get(
            "host",
            "",
        ) or ""

    if not mode:
        mode = extra.get(
            "mode",
            "auto",
        ) or "auto"

    xhttp = {
        "path": urllib.parse.unquote(
            path
        ) or "/",
        "host": host,
        "mode": mode,
    }

    if extra:
        xhttp["extra"] = extra

    return xhttp


# ============================================================
# LINK -> XRAY
# ============================================================

def link_to_xray_outbound(link: str):
    try:
        main_part = link.split(
            "#",
            1,
        )[0]

        if "://" not in main_part:
            return None

        protocol, rest = main_part.split(
            "://",
            1,
        )

        protocol = protocol.lower()

        # Hysteria2 пока не проверяем через этот Xray HTTP
        # inbound, как и в старой версии.
        if protocol in (
            "hysteria2",
            "hy2",
        ):
            return None

        query_params = {}

        if "?" in rest:
            rest, query_part = rest.split(
                "?",
                1,
            )

            query_params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True,
            )

        outbound = {
            "streamSettings": {}
        }

        # ----------------------------------------------------
        # Shadowsocks
        # ----------------------------------------------------

        if protocol == "ss":
            if "@" not in rest:
                decoded = safe_b64decode(
                    rest
                )

                if "@" in decoded:
                    user_info, host_port = (
                        decoded.rsplit(
                            "@",
                            1,
                        )
                    )
                else:
                    return None

            else:
                user_info, host_port = (
                    rest.rsplit(
                        "@",
                        1,
                    )
                )

                if ":" not in user_info:
                    try:
                        user_info = safe_b64decode(
                            user_info
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

            host, port = parse_host_port(
                host_port
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

        # ----------------------------------------------------
        # VLESS / Trojan
        # ----------------------------------------------------

        elif protocol in (
            "vless",
            "trojan",
        ):
            if "@" in rest:
                user_info, host_port = (
                    rest.rsplit(
                        "@",
                        1,
                    )
                )
            else:
                user_info = ""
                host_port = rest

            host, port = parse_host_port(
                host_port
            )

            if not host or not port:
                return None

            if protocol == "vless":
                flow = query_params.get(
                    "flow",
                    [""],
                )[0]

                outbound.update(
                    {
                        "protocol": "vless",
                        "settings": {
                            "vnext": [
                                {
                                    "address": host,
                                    "port": port,
                                    "users": [
                                        {
                                            "id": user_info,
                                            "encryption": "none",
                                            "flow": flow,
                                        }
                                    ],
                                }
                            ]
                        },
                    }
                )

            else:
                outbound.update(
                    {
                        "protocol": "trojan",
                        "settings": {
                            "servers": [
                                {
                                    "address": host,
                                    "port": port,
                                    "password": user_info,
                                }
                            ]
                        },
                    }
                )

        # ----------------------------------------------------
        # VMess
        # ----------------------------------------------------

        elif protocol == "vmess":
            decoded = safe_b64decode(
                rest
            )

            data = json.loads(decoded)

            host = data.get("add")
            port = int(data.get("port"))

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
                                        "id": data.get("id"),
                                        "alterId": int(
                                            data.get(
                                                "aid",
                                                0,
                                            )
                                        ),
                                        "security": "auto",
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
            }

        else:
            return None

        # ----------------------------------------------------
        # SECURITY
        # ----------------------------------------------------

        security = query_params.get(
            "security",
            [""],
        )[0].lower()

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
                query_params.get(
                    "sni",
                    [""],
                )[0]
                or query_params.get(
                    "host",
                    [""],
                )[0]
            )

            alpn_raw = query_params.get(
                "alpn",
                [""],
            )[0]

            alpn_list = [
                a.strip()
                for a in alpn_raw.split(",")
                if a.strip()
            ]

            if security == "tls":
                tls_obj = {
                    "serverName": sni
                }

                if alpn_list:
                    tls_obj["alpn"] = alpn_list

                outbound[
                    "streamSettings"
                ]["tlsSettings"] = tls_obj

            else:
                reality_obj = {
                    "serverName": sni,
                    "publicKey": query_params.get(
                        "pbk",
                        [""],
                    )[0],
                    "shortId": query_params.get(
                        "sid",
                        [""],
                    )[0],
                    "fingerprint": query_params.get(
                        "fp",
                        ["chrome"],
                    )[0],
                }

                spx = query_params.get(
                    "spx",
                    [""],
                )[0]

                if spx:
                    reality_obj[
                        "spiderX"
                    ] = spx

                outbound[
                    "streamSettings"
                ]["realitySettings"] = reality_obj

        # ----------------------------------------------------
        # NETWORK
        # ----------------------------------------------------

        net = (
            query_params.get(
                "type",
                [""],
            )[0]
            or query_params.get(
                "net",
                [""],
            )[0]
        )

        if net:
            net = net.lower()

            outbound[
                "streamSettings"
            ]["network"] = net

            path_val = query_params.get(
                "path",
                ["/"],
            )[0] or "/"

            host_val = query_params.get(
                "host",
                [""],
            )[0]

            path_val = urllib.parse.unquote(
                path_val
            )

            header_type = query_params.get(
                "headerType",
                ["none"],
            )[0]

            # ------------------------------------------------
            # WS
            # ------------------------------------------------

            if net == "ws":
                outbound[
                    "streamSettings"
                ]["wsSettings"] = {
                    "path": path_val,
                    "headers": (
                        {"Host": host_val}
                        if host_val
                        else {}
                    ),
                }

            # ------------------------------------------------
            # GRPC
            # ------------------------------------------------

            elif net == "grpc":
                outbound[
                    "streamSettings"
                ]["grpcSettings"] = {
                    "serviceName": (
                        query_params.get(
                            "serviceName",
                            [""],
                        )[0]
                        or path_val.lstrip("/")
                    )
                }

            # ------------------------------------------------
            # XHTTP
            # ------------------------------------------------

            elif net in (
                "xhttp",
                "splithttp",
            ):
                xhttp_settings = (
                    normalize_xhttp_settings(
                        query_params
                    )
                )

                outbound[
                    "streamSettings"
                ]["xhttpSettings"] = (
                    xhttp_settings
                )

            # ------------------------------------------------
            # HTTP Upgrade
            # ------------------------------------------------

            elif net == "httpupgrade":
                outbound[
                    "streamSettings"
                ]["httpupgradeSettings"] = {
                    "path": path_val,
                    "host": host_val,
                }

            # ------------------------------------------------
            # HTTP / H2
            # ------------------------------------------------

            elif net in (
                "http",
                "h2",
            ):
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

            # ------------------------------------------------
            # KCP
            # ------------------------------------------------

            elif net in (
                "kcp",
                "mkcp",
            ):
                outbound[
                    "streamSettings"
                ]["kcpSettings"] = {
                    "header": {
                        "type": header_type
                    }
                }

        return outbound

    except Exception:
        return None


# ============================================================
# LOCAL PORT
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
    timeout: float = 1.5,
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


# ============================================================
# XRAY
# ============================================================

def get_xray_cmd() -> list:
    candidates = []

    if os.name == "nt":
        candidates.extend(
            [
                "xray.exe",
                "./xray.exe",
                "xray",
            ]
        )
    else:
        candidates.extend(
            [
                "./xray",
                "xray",
            ]
        )

    for exe in candidates:
        if (
            os.path.exists(exe)
            or exe == "xray"
            or exe == "xray.exe"
        ):
            return [
                exe,
                "run",
                "-c",
                "stdin:",
            ]

    return [
        "xray",
        "run",
        "-c",
        "stdin:",
    ]


# ============================================================
# EXIT COUNTRY
# ============================================================

def get_exit_country_via_proxy(
    opener,
    timeout,
):
    results = []

    # --------------------------------------------------------
    # ip-api
    # --------------------------------------------------------

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
                    "utf-8",
                    errors="ignore",
                )
            )

            if (
                data.get("status")
                == "success"
                and data.get("countryCode")
            ):
                results.append(
                    (
                        "ip-api",
                        data["countryCode"].upper(),
                    )
                )

    except Exception:
        pass

    # --------------------------------------------------------
    # ip2location
    # --------------------------------------------------------

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
                    "utf-8",
                    errors="ignore",
                )
            )

            if data.get("country_code"):
                results.append(
                    (
                        "ip2location",
                        data["country_code"].upper(),
                    )
                )

    except Exception:
        pass

    # --------------------------------------------------------
    # ip.sb
    # --------------------------------------------------------

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
                    "utf-8",
                    errors="ignore",
                )
            )

            cc = (
                data.get("country_code")
                or data.get("country")
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
            counts.get(cc, 0)
            + 1
        )

    for cc, count in counts.items():
        if count >= 2:
            return cc

    for name, cc in results:
        if name == "ip-api":
            return cc

    return results[0][1]


# ============================================================
# XRAY CHECK
# ============================================================

def check_via_xray_detailed(
    outbound_obj: dict,
    timeout: float = 6.0,
    min_success_count: int = 2,
):
    port = get_free_port()

    config = {
        "log": {
            "loglevel": "warning"
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
            stderr=subprocess.PIPE,
        )

        raw_config = json.dumps(
            config,
            ensure_ascii=False,
        ).encode("utf-8")

        proc.stdin.write(
            raw_config
        )

        proc.stdin.flush()
        proc.stdin.close()

        if not wait_for_port(
            port,
            timeout=1.5,
        ):
            stderr_text = ""

            try:
                stderr_text = (
                    proc.stderr.read()
                    .decode(
                        "utf-8",
                        errors="ignore",
                    )[-1000:]
                )
            except Exception:
                pass

            return (
                False,
                None,
                "Локальный Xray не запустился"
                + (
                    f": {stderr_text}"
                    if stderr_text
                    else ""
                ),
            )

        proxy_handler = (
            urllib.request.ProxyHandler(
                {
                    "http": (
                        f"http://127.0.0.1:{port}"
                    ),
                    "https": (
                        f"http://127.0.0.1:{port}"
                    ),
                }
            )
        )

        opener = urllib.request.build_opener(
            proxy_handler
        )

        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.microsoft.com/connecttest.txt",
        ]

        success_count = 0
        errors = []

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

                    else:
                        errors.append(
                            f"{url}: HTTP {resp.status}"
                        )

            except Exception as e:
                errors.append(
                    f"{url}: {type(e).__name__}: {e}"
                )

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
            f"({success_count}/3)"
            + (
                " | "
                + " ; ".join(errors[:2])
                if errors
                else ""
            ),
        )

    except Exception as e:
        return (
            False,
            None,
            f"Ошибка Xray: "
            f"{type(e).__name__}: {e}",
        )

    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)

            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# ============================================================
# PROXY CHECK
# ============================================================

def check_proxy_alive_detailed(
    link: str,
    min_success_count: int = 2,
):
    host, port, orig_name = (
        parse_host_port_and_name(link)
    )

    if (
        not host
        or not port
        or not is_valid_public_host(host)
    ):
        return (
            False,
            None,
            "Некорректный формат хоста/порта",
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
            "Hysteria2 не поддерживается Xray-check",
            None,
        )

    outbound = link_to_xray_outbound(
        link
    )

    if not outbound:
        return (
            False,
            None,
            "Ошибка генерации JSON для Xray",
            None,
        )

    is_ok, cc, reason = (
        check_via_xray_detailed(
            outbound,
            timeout=6.0,
            min_success_count=min_success_count,
        )
    )

    if is_ok:
        if cc:
            final_flag = cc_to_flag(cc)
        else:
            final_flag = extract_clean_flag(
                orig_name
            )

        return (
            True,
            (link, final_flag),
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
# DOWNLOAD SOURCE
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

            info["http_status"] = (
                response.status
            )

            raw_data = response.read()

            info["size_bytes"] = len(
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
                    decoded = safe_b64decode(
                        content
                    )

                    if any(
                        p in decoded
                        for p in SUPPORTED_PROTOCOLS
                    ):
                        content = decoded
                        info["is_base64"] = True

                except Exception:
                    pass

            raw_lines = [
                line.strip()
                for line in content.splitlines()
                if line.strip()
            ]

            info["total_lines"] = len(
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

            info["configs"] = (
                valid_configs
            )

    except Exception as e:
        info["error"] = str(e)

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
                if line.strip()
                and not line.strip().startswith("#")
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
                idx = futures[future]

                try:
                    res = future.result()
                except Exception as e:
                    print(
                        f"  ├─ ❌ Источник #{idx}: "
                        f"{e}"
                    )
                    continue

                configs = res["configs"]

                status_str = (
                    f"HTTP {res['http_status']}"
                    if res["http_status"]
                    else "ОШИБКА"
                )

                b64_str = (
                    " [Base64]"
                    if res["is_base64"]
                    else ""
                )

                err_str = (
                    f" (Ошибка: {res['error']})"
                    if res["error"]
                    else ""
                )

                if (
                    res["http_status"]
                    in (200, 204)
                    or configs
                ):
                    successful_sources += 1

                print(
                    f"  ├─ 🔗 Источник #{idx:<3} | "
                    f"Статус: {status_str:<10} | "
                    f"Размер: {res['size_bytes']}B | "
                    f"Найдено конфигов: "
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
            f"✅ Успешно получено "
            f"{len(links_with_source)} конфигов "
            f"из {successful_sources}/"
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

    if os.path.exists(
        INCOMING_FILE
    ):
        try:
            with open(
                INCOMING_FILE,
                "r",
                encoding="utf-8",
            ) as f:
                lines = [
                    line.strip()
                    for line in f
                    if line.strip()
                    and not line.strip().startswith("#")
                ]

            unique_lines = list(
                dict.fromkeys(lines)
            )[:MAX_QUEUE_LIMIT]

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
                    extracted = (
                        parse_ip_or_resolve(
                            item
                        )
                    )

                    for ip in extracted:
                        incoming_raw_ips.append(
                            ip
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
                f"⚠️ Ошибка чтения очереди "
                f"{INCOMING_FILE}: {e}"
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
                decoded = safe_b64decode(
                    f.read()
                )

            prev_wl = [
                sanitize_v2rayng_link(
                    line.strip()
                )
                for line in decoded.splitlines()
                if line.strip().startswith(
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
                decoded = safe_b64decode(
                    f.read()
                )

            prev_bl = [
                sanitize_v2rayng_link(
                    line.strip()
                )
                for line in decoded.splitlines()
                if line.strip().startswith(
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

    return prev_wl, prev_bl


# ============================================================
# DEDUP KEY
# ============================================================

def get_config_dedup_key(
    link: str,
) -> tuple:

    host, port, _ = (
        parse_host_port_and_name(link)
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
            "://"
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

    try:
        if link.startswith(
            "vmess://"
        ):
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

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
            )

        else:
            parsed = urllib.parse.urlparse(
                link
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
                )[0]
                .lower()
            )

            path = query_params.get(
                "path",
                [""],
            )[0]

            pbk = query_params.get(
                "pbk",
                [""],
            )[0]

            security = query_params.get(
                "security",
                [""],
            )[0].lower()

            flow = query_params.get(
                "flow",
                [""],
            )[0].lower()

            sid = query_params.get(
                "sid",
                [""],
            )[0]

            mode = query_params.get(
                "mode",
                [""],
            )[0].lower()

    except Exception:
        pass

    path = (
        urllib.parse.unquote(path)
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
    )


# ============================================================
# FINAL DEDUP KEY
# ============================================================

def get_final_dedup_key(
    link: str,
) -> tuple:

    host, port, _ = (
        parse_host_port_and_name(link)
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
            "://"
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

    try:
        if link.startswith(
            "vmess://"
        ):
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

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

        else:
            parsed = urllib.parse.urlparse(
                link
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
                )[0]
                .lower()
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
                )[0]
                .lower()
            )

    except Exception:
        pass

    path = (
        urllib.parse.unquote(path)
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
    )


# ============================================================
# INPUT DEDUP
# ============================================================

def clean_and_dedup(
    tagged_items: list,
) -> list:
    """
    ВАЖНО:

    Здесь теперь удаляется только абсолютно одинаковая
    строка.

    Никакого get_config_dedup_key до проверки.

    Это специально сделано потому, что один IP может иметь:
      - разные SNI;
      - разные path;
      - разные UUID;
      - разные XHTTP extra;
      - разные страны в названии.

    Все они должны сначала попасть на реальный тест.
    """

    seen_strings = set()
    valid_items = []

    for link, source_tag in tagged_items:
        link = link.strip()

        if not link.startswith(
            SUPPORTED_PROTOCOLS
        ):
            continue

        if link in seen_strings:
            continue

        seen_strings.add(link)

        valid_items.append(
            (
                link,
                source_tag,
            )
        )

    print(
        f"🧹 Предварительная очистка: "
        f"было {len(tagged_items)}, "
        f"осталось {len(valid_items)} "
        f"(удалены только точные дубликаты)."
    )

    return valid_items


# ============================================================
# LIMIT PER IP / SUBNET
# ============================================================

def limit_configs_per_ip(
    items_list: list,
    white_ips: set,
    max_per_ip_bl: int = MAX_CONFIGS_PER_IP_BL,
    max_per_ip_wl: int = MAX_CONFIGS_PER_IP_WL,
    max_per_subnet_bl: int = MAX_CONFIGS_PER_SUBNET_BL,
) -> list:

    ip_counter = defaultdict(int)
    subnet_counter = defaultdict(int)

    filtered = []

    grouped_by_ip = defaultdict(list)

    for item in items_list:
        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        host, _, _ = (
            parse_host_port_and_name(link)
        )

        if not host:
            continue

        clean_host = host.strip(
            '[] \t\r\n\'"'
        ).lower()

        ip_str = (
            resolve_host_cached(
                clean_host
            )
            or clean_host
        )

        grouped_by_ip[ip_str].append(
            item
        )

    for ip_str, items in (
        grouped_by_ip.items()
    ):
        is_wl = (
            ip_str in white_ips
        )

        limit = (
            max_per_ip_wl
            if is_wl
            else max_per_ip_bl
        )

        if is_wl:
            # WL до теста не должен
            # уничтожать разные SNI/path.
            #
            # Просто отдаём всё.
            for item in items:
                filtered.append(item)

            continue

        # BL — старая логика.
        for item in items:
            if (
                ip_counter[ip_str]
                >= limit
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
                    subnet_counter[subnet_key]
                    >= max_per_subnet_bl
                ):
                    continue

                subnet_counter[
                    subnet_key
                ] += 1

            except Exception:
                pass

            ip_counter[ip_str] += 1
            filtered.append(item)

    print(
        f"✂️ Ограничение BL: "
        f"было {len(items_list)}, "
        f"осталось {len(filtered)}. "
        f"BL/IP={max_per_ip_bl}, "
        f"BL/subnet={max_per_subnet_bl}. "
        f"WL/IP не ограничивается."
    )

    return filtered


# ============================================================
# DIVERSITY DEDUP AFTER TEST
# ============================================================

def get_diversity_info(
    link: str,
):
    host, port, orig_name = (
        parse_host_port_and_name(link)
    )

    clean_host = (
        host.strip(
            '[] \t\r\n\'"'
        ).lower()
        if host
        else ""
    )

    resolved_ip = (
        resolve_host_cached(
            clean_host
        )
        if clean_host
        else None
    )

    sni = extract_sni_from_link(
        link
    )

    proto = (
        link.split(
            "://",
            1,
        )[0].lower()
        if "://" in link
        else ""
    )

    path = ""

    try:
        if link.startswith(
            "vmess://"
        ):
            decoded = safe_b64decode(
                link.replace(
                    "vmess://",
                    "",
                    1,
                ).strip()
            )

            data = json.loads(decoded)

            path = data.get(
                "path",
                "",
            )

            sni = (
                data.get("sni")
                or data.get("host")
                or sni
                or ""
            )

        else:
            parsed = urllib.parse.urlparse(
                link
            )

            params = (
                urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
            )

            path = params.get(
                "path",
                [""],
            )[0]

    except Exception:
        pass

    return {
        "ip": resolved_ip or clean_host,
        "sni": (sni or "").lower(),
        "path": urllib.parse.unquote(
            path or "/"
        ),
        "proto": proto,
        "flag": extract_clean_flag(
            orig_name
        ),
        "port": port,
    }


def dedup_after_testing(
    config_list: list,
    list_name: str = "",
) -> list:
    """
    Дедупликация ПОСЛЕ тестирования.

    Приоритет:
      1. разные страны/флаги;
      2. разные SNI;
      3. разные path;
      4. разные IP;
      5. остальные.

    Полностью одинаковый endpoint не размножаем.
    """

    if not config_list:
        return []

    parsed_items = []

    for item in config_list:
        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        info = get_diversity_info(
            link
        )

        parsed_items.append(
            (
                item,
                info,
            )
        )

    # --------------------------------------------------------
    # Сначала выбираем максимально разные конфиги.
    # --------------------------------------------------------

    selected = []

    seen_exact = set()
    seen_ip_sni = set()
    seen_flag = set()
    seen_sni = set()
    seen_path = set()

    # Pass 1:
    # уникальные flag + SNI + path
    for item, info in parsed_items:
        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        exact = get_final_dedup_key(
            link
        )

        if exact in seen_exact:
            continue

        flag = info["flag"]
        sni = info["sni"]
        path = info["path"]
        ip = info["ip"]

        combo = (
            flag,
            sni,
            path,
            ip,
        )

        if combo in seen_ip_sni:
            continue

        if (
            flag in seen_flag
            and sni in seen_sni
            and path in seen_path
        ):
            continue

        seen_exact.add(exact)
        seen_ip_sni.add(combo)

        seen_flag.add(flag)
        seen_sni.add(sni)
        seen_path.add(path)

        selected.append(item)

    # --------------------------------------------------------
    # Pass 2:
    # то, что не прошло diversity,
    # но всё ещё реально отличается.
    # --------------------------------------------------------

    for item, info in parsed_items:
        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list),
            )
            else item
        )

        exact = get_final_dedup_key(
            link
        )

        if exact in seen_exact:
            continue

        seen_exact.add(exact)
        selected.append(item)

    removed = (
        len(config_list)
        - len(selected)
    )

    print(
        f"🔍 Финальная дедупликация "
        f"{list_name}: "
        f"было {len(config_list)}, "
        f"осталось {len(selected)} "
        f"(удалено {removed})."
    )

    return selected


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
            b64_data = link.replace(
                "vmess://",
                "",
                1,
            ).strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(decoded)

            data["ps"] = new_name

            encoded = base64.b64encode(
                json.dumps(
                    data,
                    ensure_ascii=False,
                ).encode("utf-8")
            ).decode("utf-8")

            return f"vmess://{encoded}"

        except Exception:
            pass

    if "://" in link:
        main_part = link.split(
            "#",
            1,
        )[0]

        return (
            f"{main_part}#"
            f"{urllib.parse.quote(new_name)}"
        )

    return link


# ============================================================
# BL PROTOCOL FILTER
# ============================================================

def filter_protocols_bl(
    alive_configs,
    minority_ratio=BL_MINORITY_RATIO,
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
            link.split(
                "://",
                1,
            )[0]
            .lower()
        )

        # НЕ МЕНЯЮ ТВОЮ ЛОГИКУ:
        # VLESS / Hysteria приоритет.
        if proto in (
            "vless",
            "hysteria2",
            "hy2",
        ):
            priority.append(item)
        else:
            minority.append(item)

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
        f"VLESS/Hy2: {len(priority)} шт. | "
        f"Старые: {len(minority)} шт. "
        f"(лимит ~{minority_ratio * 100:.0f}%)"
    )

    return priority + minority


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "🚀 Старт продвинутого Xray-парсера..."
    )

    print(
        "⚙️ WL test: 1/3"
    )

    print(
        "⚙️ BL test: 2/3"
    )

    print(
        "⚙️ WL: без искусственного лимита "
        "на количество конфигов с IP"
    )

    print(
        "⚙️ BL: /24 лимит сохраняется"
    )

    print(
        "⚙️ XHTTP extra: СОХРАНЯЕТСЯ"
    )

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
    # 1. DOWNLOAD
    # ========================================================

    wl_fetched_with_source = (
        fetch_links_parallel_with_source(
            wl_file
        )
    )

    bl_fetched_with_source = (
        fetch_links_parallel_with_source(
            bl_file
        )
    )

    incoming_proxies, incoming_raw_ips = (
        process_incoming_queue()
    )

    # ========================================================
    # 2. WHITE IP DATABASE
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
                    extracted = (
                        parse_ip_or_resolve(
                            line
                        )
                    )

                    white_ips.update(
                        extracted
                    )

        except Exception as e:
            print(
                f"⚠️ Ошибка чтения "
                f"{WHITE_IP_FILE}: {e}"
            )

    for item in incoming_raw_ips:
        extracted = parse_ip_or_resolve(
            item
        )

        white_ips.update(
            extracted
        )

    def ip_sort_key(ip):
        try:
            return ipaddress.ip_address(
                ip
            )
        except ValueError:
            return ip

    with open(
        WHITE_IP_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        for ip in sorted(
            list(white_ips),
            key=ip_sort_key,
        ):
            f.write(
                f"{ip}\n"
            )

    print(
        f"💾 База {WHITE_IP_FILE} "
        f"сохранена. Всего IP: "
        f"{len(white_ips)}"
    )

    # ========================================================
    # 3. TAG EVERYTHING
    # ========================================================

    tagged_items = []

    for link, src in (
        wl_fetched_with_source
    ):
        tagged_items.append(
            (
                link,
                src,
            )
        )

    for link, src in (
        bl_fetched_with_source
    ):
        tagged_items.append(
            (
                link,
                src,
            )
        )

    for link in incoming_proxies:
        tagged_items.append(
            (
                link,
                "INCOMING_TELEGRAM",
            )
        )

    # ========================================================
    # 4. ONLY EXACT STRING DEDUP
    # ========================================================

    clean_items = clean_and_dedup(
        tagged_items
    )

    # ========================================================
    # 5. BL LIMIT BEFORE TEST
    #
    # WL не ограничиваем.
    #
    # Это важно: если на одном белом IP 100 SNI,
    # они не должны исчезнуть до проверки.
    # ========================================================

    clean_items = (
        limit_configs_per_ip(
            clean_items,
            white_ips,
            max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
            max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
            max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL,
        )
    )

    # ========================================================
    # 6. WARM GEO CACHE
    # ========================================================

    all_ips = []

    for link, _ in clean_items:
        host, _, _ = (
            parse_host_port_and_name(
                link
            )
        )

        if host:
            clean_ip = (
                resolve_host_cached(
                    host.strip(
                        '[] \t\r\n\'"'
                    ).lower()
                )
            )

            if clean_ip:
                all_ips.append(
                    clean_ip
                )

    unique_ips = list(
        set(all_ips)
    )

    for ip in unique_ips:
        fetch_country_from_ip(ip)

    # ========================================================
    # 7. CLASSIFY
    # ========================================================

    ping_wl = []
    ping_bl = []

    alive_wl_data = []
    alive_bl_data = []

    seen_links_for_ping = set()

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

        # ----------------------------------------------------
        # Реальный WL IP
        # ----------------------------------------------------

        matched_ip = (
            find_matched_ip_for_link(
                link,
                white_ips,
            )
        )

        if matched_ip:
            # НЕ считаем это автоматически рабочим.
            # Теперь настоящий WL тоже тестируем.
            if link not in seen_links_for_ping:
                ping_wl.append(
                    (
                        link,
                        src,
                    )
                )

                seen_links_for_ping.add(
                    link
                )

            continue

        # ----------------------------------------------------
        # Остальная классификация
        # ----------------------------------------------------

        target_list = classify_config(
            link,
            white_ips,
            ru_sni_ratio=RU_SNI_RATIO,
        )

        if target_list == "WL":

            if link not in seen_links_for_ping:
                ping_wl.append(
                    (
                        link,
                        src,
                    )
                )

                seen_links_for_ping.add(
                    link
                )

        else:

            if link not in seen_links_for_ping:
                ping_bl.append(
                    (
                        link,
                        src,
                    )
                )

                seen_links_for_ping.add(
                    link
                )

    # ========================================================
    # 8. PREVIOUS ALIVE
    #
    # Старые НЕ удаляем.
    # Они тоже проходят новый тест.
    # ========================================================

    prev_wl_links, prev_bl_links = (
        load_previous_alives()
    )

    for link in prev_wl_links:
        if link not in seen_links_for_ping:
            ping_wl.append(
                (
                    link,
                    "PREV_WL",
                )
            )

            seen_links_for_ping.add(
                link
            )

    for link in prev_bl_links:
        if link not in seen_links_for_ping:
            ping_bl.append(
                (
                    link,
                    "PREV_BL",
                )
            )

            seen_links_for_ping.add(
                link
            )

    print(
        f"\n📡 Отправка на проверку Xray:"
        f"\n   WL конфигов: {len(ping_wl)}"
        f"\n   BL конфигов: {len(ping_bl)}"
    )

    # ========================================================
    # 9. TEST WL
    # ========================================================

    wl_ok_count = 0
    wl_fail_count = 0

    print(
        "\n🟢 Начинаю WL-тестирование "
        "(1/3)..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

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

            link, src = wl_futures[
                future
            ]

            try:
                (
                    is_ok,
                    res,
                    reason,
                    cc,
                ) = future.result()

            except Exception as e:
                is_ok = False
                res = None
                reason = (
                    f"EXCEPTION: {e}"
                )
                cc = None

            if is_ok:
                wl_ok_count += 1

                alive_wl_data.append(
                    res
                )

            else:
                wl_fail_count += 1

    print(
        f"🟢 WL завершён: "
        f"рабочих={wl_ok_count}, "
        f"нерабочих={wl_fail_count}"
    )

    # ========================================================
    # 10. TEST BL
    # ========================================================

    bl_ok_count = 0
    bl_fail_count = 0

    print(
        "\n🔴 Начинаю BL-тестирование "
        "(2/3)..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

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

            link, src = bl_futures[
                future
            ]

            try:
                (
                    is_ok,
                    res,
                    reason,
                    cc,
                ) = future.result()

            except Exception as e:
                is_ok = False
                res = None
                reason = (
                    f"EXCEPTION: {e}"
                )
                cc = None

            if is_ok:
                bl_ok_count += 1

                # Российский exit -> WL.
                if (
                    cc
                    and cc.upper() == "RU"
                ):
                    alive_wl_data.append(
                        res
                    )
                else:
                    alive_bl_data.append(
                        res
                    )

            else:
                bl_fail_count += 1

    print(
        f"🔴 BL завершён: "
        f"рабочих={bl_ok_count}, "
        f"нерабочих={bl_fail_count}"
    )

    print(
        f"\n📊 Результат тестов:"
        f"\n   WL: {len(alive_wl_data)}"
        f"\n   BL: {len(alive_bl_data)}"
    )

    # ========================================================
    # 11. DEDUP AFTER TEST
    # ========================================================

    alive_wl_clean = (
        dedup_after_testing(
            alive_wl_data,
            "WL после теста",
        )
    )

    alive_bl_clean = (
        dedup_after_testing(
            alive_bl_data,
            "BL после теста",
        )
    )

    # ========================================================
    # 12. LIMIT AFTER TEST
    #
    # WL по IP не режем.
    # BL /24 сохраняем.
    # ========================================================

    alive_wl_clean = (
        limit_configs_per_ip(
            alive_wl_clean,
            white_ips,
            max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
            max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
            max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL,
        )
    )

    alive_bl_limited = (
        limit_configs_per_ip(
            alive_bl_clean,
            white_ips,
            max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
            max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
            max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL,
        )
    )

    # ========================================================
    # 13. BL PROTOCOL PRIORITY
    # ========================================================

    alive_bl_clean = (
        filter_protocols_bl(
            alive_bl_limited,
            minority_ratio=BL_MINORITY_RATIO,
        )
    )

    # ========================================================
    # 14. FULL LIST
    # ========================================================

    alive_full_raw = (
        alive_wl_clean
        + alive_bl_clean
    )

    alive_full_clean = (
        dedup_after_testing(
            alive_full_raw,
            "FULL",
        )
    )

    # --------------------------------------------------------
    # После объединения снова применяем только BL ограничения.
    # WL остаётся без IP-лимита.
    # --------------------------------------------------------

    # Сначала разделим FULL обратно на WL/BL,
    # чтобы не применить BL-лимит к WL.
    full_wl = []
    full_bl = []

    wl_identity = set()

    for item in alive_wl_clean:
        link = item[0]
        wl_identity.add(
            get_final_dedup_key(link)
        )

    for item in alive_full_clean:
        link = item[0]

        key = get_final_dedup_key(
            link
        )

        if key in wl_identity:
            full_wl.append(item)
        else:
            full_bl.append(item)

    full_bl = limit_configs_per_ip(
        full_bl,
        white_ips,
        max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
        max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
        max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL,
    )

    alive_full_clean = (
        full_wl
        + full_bl
    )

    # ========================================================
    # 15. RENAME
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
        link = item[0]

        key = get_final_dedup_key(
            link
        )

        tag = (
            "[WL]"
            if key in wl_identity
            else "[BL]"
        )

        final_full.append(
            rename_config(
                link,
                idx,
                tag,
                item[1],
            )
        )

    # ========================================================
    # 16. SAVE
    # ========================================================

    with open(
        "alive_bs.txt",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(
            base64.b64encode(
                "\n".join(
                    final_wl
                ).encode("utf-8")
            ).decode("utf-8")
        )

    with open(
        "alive_bl.txt",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(
            base64.b64encode(
                "\n".join(
                    final_bl
                ).encode("utf-8")
            ).decode("utf-8")
        )

    with open(
        "alive_full.txt",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(
            base64.b64encode(
                "\n".join(
                    final_full
                ).encode("utf-8")
            ).decode("utf-8")
        )

    # ========================================================
    # CLOSE GEOIP
    # ========================================================

    if GEO_READER:
        try:
            GEO_READER.close()
        except Exception:
            pass

    print(
        "\n✨ Готово!"
    )

    print(
        f"   WL: {len(final_wl)}"
    )

    print(
        f"   BL: {len(final_bl)}"
    )

    print(
        f"   FULL: {len(final_full)}"
    )

    print(
        "📁 alive_bs.txt"
    )

    print(
        "📁 alive_bl.txt"
    )

    print(
        "📁 alive_full.txt"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()