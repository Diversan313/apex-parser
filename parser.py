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

WHITE_IP_FILE = 'white_ip.txt'
INCOMING_FILE = 'incoming_sources.txt'

MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

MAX_QUEUE_LIMIT = 1000
MAX_WORKERS = 15

MAX_CONFIGS_PER_IP_BL = 2
MAX_CONFIGS_PER_IP_WL = 30
MAX_CONFIGS_PER_SUBNET_BL = 5

# WL:
#   проверяется 1 из 3
# BL:
#   проверяется 2 из 3
WL_MIN_SUCCESS = 1
BL_MIN_SUCCESS = 2

XRAY_TEST_TIMEOUT = 6.0
XRAY_START_TIMEOUT = 1.0

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept': '*/*'
}


# ============================================================
# ГЛОБАЛЬНЫЕ КЭШИ
# ============================================================

DNS_CACHE = {}
DNS_LOCK = threading.Lock()

GEO_ONLINE_CACHE = {}
GEO_LOCK = threading.Lock()


# ============================================================
# REGEX
# ============================================================

WL_KEYWORDS_REGEX = re.compile(
    r'(?i)(?:^|[^a-zA-Zа-яА-Я0-9])'
    r'(бс|обход|глусилк(?:а|и|ок|ам|ах)?|глушилк(?:а|и|ок|ам|ах)?|'
    r'whitelist|lte|бел(?:ый|ые|ых)\s*списк(?:и|а|ов|ам|ах)?)'
    r'(?:$|[^a-zA-Zа-яА-Я0-9])'
)

DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9-]{2,63}$',
    re.IGNORECASE
)

FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')


# ============================================================
# MAXMIND
# ============================================================

try:
    import maxminddb
except ImportError:
    maxminddb = None


# ============================================================
# CLOUDFLARE NETWORKS
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
    "8.52.0.0/22"
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
            headers=HEADERS
        )

        with urllib.request.urlopen(
            req,
            timeout=30,
            context=SSL_CONTEXT
        ) as response:
            with open(MMDB_PATH, 'wb') as out_file:
                out_file.write(response.read())

        print("✅ База GeoIP успешно загружена!")

    except Exception as e:
        print(f"⚠️ Ошибка загрузки базы GeoIP: {e}")


download_geoip_db()

GEO_READER = None

if maxminddb and os.path.exists(MMDB_PATH):
    try:
        GEO_READER = maxminddb.open_database(MMDB_PATH)
    except Exception as e:
        print(f"⚠️ Не удалось открыть MMDB: {e}")


# ============================================================
# BASE64
# ============================================================

def safe_b64decode(s: str) -> str:
    s = s.strip()
    s = re.sub(r'\s+', '', s)

    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)

    return base64.b64decode(
        s,
        validate=False
    ).decode(
        'utf-8',
        errors='ignore'
    )


def safe_b64encode(text: str) -> str:
    return base64.b64encode(
        text.encode('utf-8')
    ).decode('ascii')


# ============================================================
# САНИЗАЦИЯ URI
# ============================================================

def sanitize_v2rayng_link(link: str) -> str:
    """
    Минимальная нормализация.
    Не должна уничтожать рабочие параметры.
    """

    link = link.strip()

    try:

        # -------------------------
        # VMESS
        # -------------------------

        if link.startswith("vmess://"):

            b64_data = link.split(
                "://",
                1
            )[1].strip()

            decoded = safe_b64decode(b64_data)

            data = json.loads(decoded)

            net = str(
                data.get('net', '')
            ).lower()

            if net in ['auto', 'none', '']:
                data['net'] = 'tcp'

            tls = str(
                data.get('tls', '')
            ).lower()

            if tls == 'auto':
                data['tls'] = ''

            typ = str(
                data.get('type', '')
            ).lower()

            if typ == 'auto':
                data['type'] = 'none'

            return (
                "vmess://" +
                safe_b64encode(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                        separators=(',', ':')
                    )
                )
            )

        # -------------------------
        # Остальные URI
        # -------------------------

        main_part = link
        name_part = ""

        if '#' in link:
            main_part, name_part = link.split('#', 1)

        if '?' not in main_part:
            return link

        base, query_part = main_part.split(
            '?',
            1
        )

        params = urllib.parse.parse_qs(
            query_part,
            keep_blank_values=True
        )

        changed = False

        # VLESS encryption
        if base.lower().startswith('vless://'):

            if (
                'encryption' not in params
                or params['encryption'][0].lower() in ['', 'auto']
            ):
                params['encryption'] = ['none']
                changed = True

        # auto transport
        if (
            'type' in params
            and params['type'][0].lower() == 'auto'
        ):
            params['type'] = ['tcp']
            changed = True

        if (
            'net' in params
            and params['net'][0].lower() == 'auto'
        ):
            params['net'] = ['tcp']
            changed = True

        # auto security
        if (
            'security' in params
            and params['security'][0].lower() == 'auto'
        ):
            params['security'] = ['none']
            changed = True

        if not changed:
            return link

        new_query = urllib.parse.urlencode(
            params,
            doseq=True
        )

        new_query = new_query.replace(
            '+',
            '%20'
        )

        new_link = (
            f"{base}?{new_query}"
        )

        if name_part:
            new_link += f"#{name_part}"

        return new_link

    except Exception:
        return link


# ============================================================
# FLAG
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

    if not clean_host:
        return False

    if clean_host.isdigit():
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
        '.' not in clean_host
        or clean_host.startswith('.')
        or clean_host.endswith('.')
    ):
        return False

    if not DOMAIN_REGEX.match(
        clean_host
    ):
        return False

    if clean_host.endswith(
        (
            '.local',
            '.localhost',
            '.internal',
            '.lan',
            '.home',
            '.arpa',
            '.invalid',
            '.test'
        )
    ):
        return False

    return True


# ============================================================
# DNS CACHE
# ============================================================

def resolve_host_cached(clean_host: str):

    if not clean_host:
        return None

    clean_host = clean_host.strip(
        '[] \t\r\n\'"'
    ).lower()

    if not is_valid_public_host(
        clean_host
    ):
        return None

    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[clean_host]

    # IP already
    try:
        ip_obj = ipaddress.ip_address(
            clean_host
        )

        with DNS_LOCK:
            DNS_CACHE[clean_host] = clean_host

        return clean_host

    except ValueError:
        pass

    resolved_ip = None

    try:
        # НЕ используем socket.setdefaulttimeout(),
        # чтобы не менять глобальный timeout процесса.
        old_timeout = socket.getdefaulttimeout()

        try:
            socket.setdefaulttimeout(None)

            infos = socket.getaddrinfo(
                clean_host,
                None,
                type=socket.SOCK_STREAM
            )

        finally:
            socket.setdefaulttimeout(
                old_timeout
            )

        candidates = []

        for info in infos:

            sockaddr = info[4]

            if not sockaddr:
                continue

            candidate = sockaddr[0]

            try:
                ip_obj = ipaddress.ip_address(
                    candidate
                )

                if (
                    not ip_obj.is_private
                    and not ip_obj.is_loopback
                    and not ip_obj.is_reserved
                    and not ip_obj.is_link_local
                    and not ip_obj.is_unspecified
                ):
                    candidates.append(
                        candidate
                    )

            except ValueError:
                pass

        if candidates:

            # Предпочитаем IPv4,
            # чтобы поведение было ближе
            # к старой логике gethostbyname.
            ipv4 = [
                x for x in candidates
                if ipaddress.ip_address(x).version == 4
            ]

            resolved_ip = (
                ipv4[0]
                if ipv4
                else candidates[0]
            )

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
                and 'country' in record
                and 'iso_code' in record['country']
            ):
                return record[
                    'country'
                ]['iso_code']

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
            f"{ip_str}"
            "?fields=status,countryCode"
        )

        req = urllib.request.Request(
            url,
            headers=HEADERS
        )

        with urllib.request.urlopen(
            req,
            timeout=2.0,
            context=SSL_CONTEXT
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    'utf-8'
                )
            )

            if (
                data.get('status') == 'success'
                and data.get('countryCode')
            ):

                cc = data[
                    'countryCode'
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
            for bad in [
                'localhost',
                '127.0.0.1',
                '.ir',
                '.cn',
                '.cf',
                '.ga',
                '.gq',
                '.ml',
                '.tk'
            ]
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
                    "2c0f:f248:"
                )
            ):
                return True

    except Exception:
        return True

    return False


# ============================================================
# HOST / PORT PARSING
# ============================================================

def parse_host_port(server_part: str):

    if not server_part:
        return None, None

    server_part = server_part.rstrip(
        '/'
    )

    try:

        # IPv6 [addr]:port
        if server_part.startswith('['):

            if ']' not in server_part:
                return None, None

            host_b, rest = server_part.split(
                ']',
                1
            )

            host = host_b + ']'

            port_str = (
                rest
                .lstrip(':')
                .split('/')[0]
                .split('?')[0]
            )

            return host, int(port_str)

        # IPv4/domain:port
        if ':' in server_part:

            host, port_str = server_part.rsplit(
                ':',
                1
            )

            port_str = (
                port_str
                .split('/')[0]
                .split('?')[0]
            )

            return host, int(port_str)

    except Exception:
        pass

    return None, None


# ============================================================
# PARSE MAIN HOST
# ============================================================

def parse_host_port_and_name(link: str):

    try:

        orig_name = ""

        if '#' in link:
            orig_name = urllib.parse.unquote(
                link.split('#', 1)[1]
            )

        clean_link = link.split(
            '#',
            1
        )[0]

        # -------------------------
        # VMESS
        # -------------------------

        if clean_link.startswith(
            'vmess://'
        ):

            b64_data = clean_link.split(
                '://',
                1
            )[1].strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            host = data.get('add')
            port = int(
                data.get('port')
            )

            name = (
                data.get('ps')
                or orig_name
                or ""
            )

            return host, port, name

        # -------------------------
        # VLESS / TROJAN / SS / HY2
        # -------------------------

        if clean_link.startswith(
            (
                'vless://',
                'trojan://',
                'ss://',
                'hysteria2://',
                'hy2://'
            )
        ):

            protocol, rest = clean_link.split(
                '://',
                1
            )

            protocol = protocol.lower()

            rest_without_query = rest.split(
                '?',
                1
            )[0]

            if protocol == 'ss':

                if '@' not in rest_without_query:

                    try:

                        decoded = safe_b64decode(
                            rest_without_query
                        )

                        if '@' in decoded:

                            _, host_port = decoded.rsplit(
                                '@',
                                1
                            )

                            host, port = parse_host_port(
                                host_port
                            )

                            return (
                                host,
                                port,
                                orig_name
                            )

                    except Exception:
                        pass

                else:

                    _, host_port = rest_without_query.rsplit(
                        '@',
                        1
                    )

                    host, port = parse_host_port(
                        host_port
                    )

                    return (
                        host,
                        port,
                        orig_name
                    )

            else:

                if '@' in rest_without_query:

                    rest_without_query = rest_without_query.rsplit(
                        '@',
                        1
                    )[1]

                host, port = parse_host_port(
                    rest_without_query
                )

                return (
                    host,
                    port,
                    orig_name
                )

    except Exception:
        pass

    return None, None, ""


# ============================================================
# EXTRACT SNI / HOST
# ============================================================

def extract_sni_from_link(link: str) -> str:

    try:

        if link.startswith(
            'vmess://'
        ):

            b64_data = link.split(
                '://',
                1
            )[1].split(
                '#',
                1
            )[0].strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            return (
                str(
                    data.get('sni')
                    or data.get('host')
                    or ''
                )
                .lower()
                .strip()
            )

        if '?' in link:

            query_part = link.split(
                '?',
                1
            )[1].split(
                '#',
                1
            )[0]

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True
            )

            sni = (
                params.get(
                    'sni',
                    ['']
                )[0]
                or params.get(
                    'host',
                    ['']
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

    except Exception:
        pass

    return ""


def extract_all_hosts_and_ips_from_link(
    link: str
) -> list:

    hosts = set()

    main_host, _, _ = parse_host_port_and_name(
        link
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

    if '?' in link:

        try:

            query_part = link.split(
                '?',
                1
            )[1].split(
                '#',
                1
            )[0]

            params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True
            )

            h_param = params.get(
                'host',
                ['']
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

    # IPv4, которые встретились
    # буквально в ссылке.
    ip_matches = re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        link
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
                hosts.add(
                    ip_cand
                )

        except ValueError:
            pass

    return list(hosts)


# ============================================================
# IP FROM TEXT
# ============================================================

def parse_ip_or_resolve(item: str) -> set:

    if not item:
        return set()

    item = item.strip()

    if (
        not item
        or item.startswith('#')
    ):
        return set()

    if '://' in item:

        try:

            parsed = urllib.parse.urlparse(
                item
            )

            item = (
                parsed.netloc
                or item.split(
                    '://',
                    1
                )[1]
            )

        except Exception:
            pass

    item = (
        item
        .split('/')[0]
        .split('?')[0]
        .split('#')[0]
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

        if not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return {
                str(ip_obj)
            }

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
                return {
                    resolved_ip
                }

        except ValueError:
            pass

    return set()


# ============================================================
# WHITE IP MATCH
# ============================================================

def find_matched_ip_for_link(
    link: str,
    white_ips: set
):

    if not white_ips:
        return None

    all_hosts = extract_all_hosts_and_ips_from_link(
        link
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
# WL KEYWORDS
# ============================================================

def is_wl_by_keywords(
    link: str,
    orig_name: str = ""
) -> bool:

    full_text = (
        f"{link} {orig_name}"
    )

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


# ============================================================
# RUSSIAN SNI
# ============================================================

RU_SNI_LIST = [
    'www.vk.com',
    'vk.com',
    'm.vk.com',
    'm1.vk.ru',
    'st.vk.ru',
    'id.vk.com',
    'sun1-93.userapi.com',
    'yandex.ru',
    'api-maps.yandex.ru',
    'wap.yandex.ru',
    '360.yandex.ru',
    'smartcaptcha.yandexcloud.net',
    'max.ru',
    'web.max.ru',
    'rutube.ru',
    'storage.yandex.net',
    'ads.x5.ru',
    '5post-gate.x5.ru',
    '28.img.avito.st',
    'cdn.tracker.yandex.net',
    'id.pervye.ru',
    'ya.ru',
    'rzd.ru',
    'live.ok.ru',
    'id.ok.ru',
    'qq.utiltools.ru',
    'ru.muzgrape.space',
    'flypobeda.ru',
    'shopping-api-gateway.cdek.shopping',
    'api.acquisition-gwe.plus.yandex.ru'
]


def is_ru_sni(link: str) -> bool:

    link_low = link.lower()

    if re.search(
        r'sni=[^&]*\.(ru|su)(?:&|$)',
        link_low
    ):
        return True

    sni = extract_sni_from_link(
        link
    )

    if sni:

        if sni.endswith(
            ('.ru', '.su')
        ):
            return True

        for ru_sni in RU_SNI_LIST:

            if (
                sni == ru_sni
                or sni.endswith(
                    "." + ru_sni
                )
            ):
                return True

    return False


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_config(
    link: str,
    white_ips: set,
    ru_sni_ratio: float = 0.3
) -> str:

    # 1. Явный white IP
    matched_ip = find_matched_ip_for_link(
        link,
        white_ips
    )

    if matched_ip:
        return 'WL'

    # 2. Валидный host
    host, _, orig_name = parse_host_port_and_name(
        link
    )

    if (
        not host
        or not is_valid_public_host(host)
    ):
        return 'BL'

    # 3. Ключевые слова
    if is_wl_by_keywords(
        link,
        orig_name
    ):
        return 'WL'

    # 4. RU IP
    clean_ip = resolve_host_cached(
        host.strip(
            '[] \t\r\n\'"'
        ).lower()
    )

    if clean_ip:

        cc = fetch_country_from_ip(
            clean_ip
        )

        if (
            cc
            and cc.upper() == 'RU'
        ):
            return 'WL'

    # 5. RU SNI
    if is_ru_sni(link):

        return (
            'WL'
            if random.random() < ru_sni_ratio
            else 'BL'
        )

    return 'BL'


# ============================================================
# QUERY HELPERS
# ============================================================

def parse_query(link: str) -> dict:

    if '?' not in link:
        return {}

    try:

        query_part = link.split(
            '?',
            1
        )[1].split(
            '#',
            1
        )[0]

        return urllib.parse.parse_qs(
            query_part,
            keep_blank_values=True
        )

    except Exception:
        return {}


def q(
    params: dict,
    key: str,
    default: str = ""
) -> str:

    value = params.get(
        key,
        [default]
    )

    if not value:
        return default

    return urllib.parse.unquote(
        str(value[0])
    )


# ============================================================
# XHHTTP / WS / GRPC EXTRA
# ============================================================

def parse_extra_param(
    params: dict
) -> dict:

    raw = q(
        params,
        'extra',
        ''
    )

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
            dict
        ):
            return data

    except Exception:
        pass

    return {}


# ============================================================
# XBOX/XRAY OUTBOUND
# ============================================================

def link_to_xray_outbound(
    link: str
):

    try:

        main_part = link.split(
            '#',
            1
        )[0]

        if '://' not in main_part:
            return None

        protocol, rest = main_part.split(
            '://',
            1
        )

        protocol = protocol.lower()

        query_params = {}

        if '?' in rest:

            rest, query_part = rest.split(
                '?',
                1
            )

            query_params = urllib.parse.parse_qs(
                query_part,
                keep_blank_values=True
            )

        outbound = {
            "streamSettings": {}
        }

        # ====================================================
        # SHADOWSOCKS
        # ====================================================

        if protocol == 'ss':

            user_info = None
            host_port = None

            # ss://base64(method:password@host:port)
            if '@' not in rest:

                try:

                    decoded = safe_b64decode(
                        rest
                    )

                    if '@' not in decoded:
                        return None

                    user_info, host_port = decoded.rsplit(
                        '@',
                        1
                    )

                except Exception:
                    return None

            else:

                user_info, host_port = rest.rsplit(
                    '@',
                    1
                )

                # Возможный base64 userinfo
                if ':' not in user_info:

                    try:
                        user_info = safe_b64decode(
                            user_info
                        )
                    except Exception:
                        pass

            if (
                not user_info
                or ':' not in user_info
            ):
                return None

            method, password = user_info.split(
                ':',
                1
            )

            host, port = parse_host_port(
                host_port
            )

            if (
                not host
                or not port
            ):
                return None

            outbound.update({
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "method": method,
                            "password": password
                        }
                    ]
                }
            })

        # ====================================================
        # VLESS
        # ====================================================

        elif protocol == 'vless':

            if '@' not in rest:
                return None

            user_info, host_port = rest.rsplit(
                '@',
                1
            )

            user_info = urllib.parse.unquote(
                user_info
            )

            host, port = parse_host_port(
                host_port
            )

            if (
                not host
                or not port
                or not user_info
            ):
                return None

            flow = q(
                query_params,
                'flow',
                ''
            )

            user = {
                "id": user_info,
                "encryption": q(
                    query_params,
                    'encryption',
                    'none'
                )
            }

            if flow:
                user["flow"] = flow

            outbound.update({
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [user]
                        }
                    ]
                }
            })

        # ====================================================
        # TROJAN
        # ====================================================

        elif protocol == 'trojan':

            if '@' not in rest:
                return None

            user_info, host_port = rest.rsplit(
                '@',
                1
            )

            password = urllib.parse.unquote(
                user_info
            )

            host, port = parse_host_port(
                host_port
            )

            if (
                not host
                or not port
                or not password
            ):
                return None

            outbound.update({
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "password": password
                        }
                    ]
                }
            })

        # ====================================================
        # VMESS
        # ====================================================

        elif protocol == 'vmess':

            decoded = safe_b64decode(
                rest
            )

            data = json.loads(
                decoded
            )

            host = data.get(
                'add'
            )

            port = int(
                data.get(
                    'port'
                )
            )

            uuid = data.get(
                'id'
            )

            if (
                not host
                or not port
                or not uuid
            ):
                return None

            alter_id = int(
                data.get(
                    'aid',
                    0
                )
            )

            user = {
                "id": uuid,
                "alterId": alter_id,
                "security": (
                    data.get(
                        'scy'
                    )
                    or 'auto'
                )
            }

            outbound.update({
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [user]
                        }
                    ]
                }
            })

            # Переводим VMess JSON
            # в единый query-like набор.
            query_params = {
                'security': [
                    str(
                        data.get(
                            'tls',
                            ''
                        )
                    )
                ],
                'sni': [
                    str(
                        data.get(
                            'sni'
                        )
                        or data.get(
                            'host',
                            ''
                        )
                    )
                ],
                'type': [
                    str(
                        data.get(
                            'net',
                            ''
                        )
                    )
                ],
                'path': [
                    str(
                        data.get(
                            'path',
                            '/'
                        )
                    )
                ],
                'host': [
                    str(
                        data.get(
                            'host',
                            ''
                        )
                    )
                ],
                'alpn': [
                    str(
                        data.get(
                            'alpn',
                            ''
                        )
                    )
                ],
                'fp': [
                    str(
                        data.get(
                            'fp',
                            ''
                        )
                    )
                ],
                'allowInsecure': [
                    str(
                        data.get(
                            'allowInsecure',
                            ''
                        )
                    )
                ]
            }

            # flow бывает в новых VMess-совместимых
            # форматах/импортах.
            if data.get('flow'):
                query_params['flow'] = [
                    str(
                        data.get(
                            'flow'
                        )
                    )
                ]

        # ====================================================
        # HYSTERIA2
        # ====================================================

        elif protocol in (
            'hysteria2',
            'hy2'
        ):

            # hysteria2://PASSWORD@host:port?...
            parsed = urllib.parse.urlsplit(
                main_part
            )

            host = parsed.hostname

            try:
                port = parsed.port
            except ValueError:
                return None

            password = urllib.parse.unquote(
                parsed.username or ''
            )

            if (
                not host
                or not port
                or not password
            ):
                return None

            # В Xray Hysteria2 реализуется
            # как protocol=hysteria + version=2.
            outbound = {
                "protocol": "hysteria",
                "settings": {
                    "version": 2,
                    "address": host,
                    "port": port
                },
                "streamSettings": {
                    "network": "hysteria",
                    "method": "hysteria",
                    "security": "tls",
                    "tlsSettings": {}
                }
            }

            hysteria_settings = {
                "version": 2,
                "auth": password
            }

            outbound[
                "streamSettings"
            ][
                "hysteriaSettings"
            ] = hysteria_settings

            # Parse Hysteria2 query
            sni = q(
                query_params,
                'sni',
                ''
            )

            insecure = q(
                query_params,
                'insecure',
                ''
            ).lower()

            alpn_raw = q(
                query_params,
                'alpn',
                ''
            )

            alpn = [
                x.strip()
                for x in alpn_raw.split(',')
                if x.strip()
            ]

            if sni:
                outbound[
                    "streamSettings"
                ][
                    "tlsSettings"
                ][
                    "serverName"
                ] = sni

            if alpn:
                outbound[
                    "streamSettings"
                ][
                    "tlsSettings"
                ][
                    "alpn"
                ] = alpn

            if insecure in (
                '1',
                'true',
                'yes',
                'on'
            ):
                outbound[
                    "streamSettings"
                ][
                    "tlsSettings"
                ][
                    "allowInsecure"
                ] = True

            # Hysteria2 Salamander
            obfs = q(
                query_params,
                'obfs',
                ''
            ).lower()

            obfs_password = q(
                query_params,
                'obfs-password',
                ''
            )

            if (
                obfs == 'salamander'
                and obfs_password
            ):
                outbound[
                    "streamSettings"
                ][
                    "finalmask"
                ] = {
                    "type": "salamander",
                    "settings": {
                        "password": obfs_password
                    }
                }

            # Hysteria уже полностью собран.
            return outbound

        else:
            return None

        # ====================================================
        # SECURITY
        # ====================================================

        security = q(
            query_params,
            'security',
            ''
        ).lower()

        if security in (
            '',
            'none',
            'plain'
        ):

            security = ''

        if (
            protocol == 'trojan'
            and not security
        ):
            security = 'tls'

        if security in (
            'tls',
            'reality'
        ):

            outbound[
                "streamSettings"
            ][
                "security"
            ] = security

            sni = q(
                query_params,
                'sni',
                ''
            ) or q(
                query_params,
                'host',
                ''
            )

            alpn_raw = q(
                query_params,
                'alpn',
                ''
            )

            alpn_list = [
                x.strip()
                for x in alpn_raw.split(',')
                if x.strip()
            ]

            if security == 'tls':

                tls_obj = {}

                if sni:
                    tls_obj[
                        "serverName"
                    ] = sni

                # FIX:
                # раньше fp терялся.
                fp = (
                    q(
                        query_params,
                        'fp',
                        ''
                    )
                    or q(
                        query_params,
                        'fingerprint',
                        ''
                    )
                )

                if fp:
                    tls_obj[
                        "fingerprint"
                    ] = fp

                # FIX:
                # раньше allowInsecure терялся.
                allow_insecure = q(
                    query_params,
                    'allowInsecure',
                    ''
                ).lower()

                if allow_insecure in (
                    '1',
                    'true',
                    'yes',
                    'on'
                ):
                    tls_obj[
                        "allowInsecure"
                    ] = True

                if alpn_list:
                    tls_obj[
                        "alpn"
                    ] = alpn_list

                # Сохраняем некоторые дополнительные
                # TLS параметры, если они есть.
                for key in (
                    'minVersion',
                    'maxVersion',
                    'disableSystemRoot',
                    'enableSessionResumption'
                ):

                    value = q(
                        query_params,
                        key,
                        ''
                    )

                    if value:

                        if value.lower() in (
                            'true',
                            'false'
                        ):
                            tls_obj[key] = (
                                value.lower()
                                == 'true'
                            )
                        else:
                            tls_obj[key] = value

                outbound[
                    "streamSettings"
                ][
                    "tlsSettings"
                ] = tls_obj

            elif security == 'reality':

                # Актуальное имя поля Xray:
                # password.
                # pbk из URI = public key.
                pbk = (
                    q(
                        query_params,
                        'pbk',
                        ''
                    )
                    or q(
                        query_params,
                        'publicKey',
                        ''
                    )
                    or q(
                        query_params,
                        'password',
                        ''
                    )
                )

                sid = q(
                    query_params,
                    'sid',
                    ''
                )

                fp = (
                    q(
                        query_params,
                        'fp',
                        ''
                    )
                    or 'chrome'
                )

                reality_obj = {
                    "serverName": sni,
                    "password": pbk,
                    "shortId": sid,
                    "fingerprint": fp
                }

                spx = q(
                    query_params,
                    'spx',
                    ''
                )

                if spx:
                    reality_obj[
                        "spiderX"
                    ] = spx

                mldsa_verify = q(
                    query_params,
                    'mldsa65Verify',
                    ''
                )

                if mldsa_verify:
                    reality_obj[
                        "mldsa65Verify"
                    ] = mldsa_verify

                outbound[
                    "streamSettings"
                ][
                    "realitySettings"
                ] = reality_obj

        # ====================================================
        # TRANSPORT
        # ====================================================

        net = (
            q(
                query_params,
                'type',
                ''
            )
            or q(
                query_params,
                'net',
                ''
            )
        ).lower()

        if not net:
            return outbound

        # normalized names
        if net == 'ws':
            method_name = 'websocket'
        elif net == 'mkcp':
            method_name = 'mkcp'
        else:
            method_name = net

        outbound[
            "streamSettings"
        ][
            "network"
        ] = method_name

        # Xray modern syntax uses method.
        outbound[
            "streamSettings"
        ][
            "method"
        ] = method_name

        path_val = (
            q(
                query_params,
                'path',
                '/'
            )
            or '/'
        )

        host_val = q(
            query_params,
            'host',
            ''
        )

        extra_data = parse_extra_param(
            query_params
        )

        # -------------------------
        # RAW / TCP
        # -------------------------

        if net in (
            'tcp',
            'raw'
        ):

            raw_settings = {}

            header_type = q(
                query_params,
                'headerType',
                ''
            )

            if header_type:
                raw_settings[
                    "header"] = {
                        "type": header_type
                    }

            if extra_data:
                raw_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "rawSettings"
            ] = raw_settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "raw"

        # -------------------------
        # WebSocket
        # -------------------------

        elif net == 'ws':

            ws_settings = {
                "path": path_val
            }

            if host_val:
                ws_settings[
                    "headers"
                ] = {
                    "Host": host_val
                }

            if extra_data:
                ws_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "wsSettings"
            ] = ws_settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "websocket"

        # -------------------------
        # gRPC
        # -------------------------

        elif net == 'grpc':

            service_name = (
                q(
                    query_params,
                    'serviceName',
                    ''
                )
                or path_val.lstrip('/')
            )

            grpc_settings = {
                "serviceName": service_name
            }

            authority = q(
                query_params,
                'authority',
                ''
            )

            if authority:
                grpc_settings[
                    "authority"
                ] = authority

            mode = q(
                query_params,
                'mode',
                ''
            )

            if mode:
                grpc_settings[
                    "mode"
                ] = mode

            if extra_data:
                grpc_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "grpcSettings"
            ] = grpc_settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "grpc"

        # -------------------------
        # XHTTP / SplitHTTP
        # -------------------------

        elif net in (
            'xhttp',
            'splithttp'
        ):

            xhttp_settings = {
                "path": path_val or "/"
            }

            if host_val:
                xhttp_settings[
                    "host"
                ] = host_val

            mode = q(
                query_params,
                'mode',
                ''
            )

            if mode:
                xhttp_settings[
                    "mode"
                ] = mode

            if extra_data:
                xhttp_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "xhttpSettings"
            ] = xhttp_settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "xhttp"

        # -------------------------
        # HTTPUpgrade
        # -------------------------

        elif net == 'httpupgrade':

            settings = {
                "path": path_val or "/"
            }

            if host_val:
                settings[
                    "host"
                ] = host_val

            if extra_data:
                settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "httpupgradeSettings"
            ] = settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "httpupgrade"

        # -------------------------
        # HTTP / H2
        # -------------------------

        elif net in (
            'http',
            'h2'
        ):

            http_settings = {
                "path": path_val or "/"
            }

            if host_val:
                http_settings[
                    "host"
                ] = [
                    host_val
                ]

            if extra_data:
                http_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "httpSettings"
            ] = http_settings

            # Xray transport name для старого
            # HTTP-over-2.
            outbound[
                "streamSettings"
            ][
                "method"
            ] = "raw"

        # -------------------------
        # mKCP
        # -------------------------

        elif net in (
            'kcp',
            'mkcp'
        ):

            header_type = q(
                query_params,
                'headerType',
                'none'
            )

            kcp_settings = {
                "header": {
                    "type": header_type
                }
            }

            seed = q(
                query_params,
                'seed',
                ''
            )

            if seed:
                kcp_settings[
                    "seed"
                ] = seed

            mtu = q(
                query_params,
                'mtu',
                ''
            )

            if mtu:
                try:
                    kcp_settings[
                        "mtu"
                    ] = int(mtu)
                except ValueError:
                    pass

            tti = q(
                query_params,
                'tti',
                ''
            )

            if tti:
                try:
                    kcp_settings[
                        "tti"
                    ] = int(tti)
                except ValueError:
                    pass

            uplink_capacity = q(
                query_params,
                'uplinkCapacity',
                ''
            )

            if uplink_capacity:
                try:
                    kcp_settings[
                        "uplinkCapacity"
                    ] = int(
                        uplink_capacity
                    )
                except ValueError:
                    pass

            downlink_capacity = q(
                query_params,
                'downlinkCapacity',
                ''
            )

            if downlink_capacity:
                try:
                    kcp_settings[
                        "downlinkCapacity"
                    ] = int(
                        downlink_capacity
                    )
                except ValueError:
                    pass

            if extra_data:
                kcp_settings.update(
                    extra_data
                )

            outbound[
                "streamSettings"
            ][
                "kcpSettings"
            ] = kcp_settings

            outbound[
                "streamSettings"
            ][
                "method"
            ] = "mkcp"

        else:
            # Не ломаем конфиг неизвестным transport.
            return outbound

        return outbound

    except Exception as e:
        print(
            f"⚠️ link_to_xray_outbound(): "
            f"{type(e).__name__}: {e}"
        )
        return None


# ============================================================
# PORT
# ============================================================

def get_free_port() -> int:

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as s:

        s.bind(
            (
                '127.0.0.1',
                0
            )
        )

        return s.getsockname()[1]


def wait_for_port(
    port: int,
    timeout: float = 0.6
) -> bool:

    start = time.time()

    while (
        time.time() - start
        < timeout
    ):

        try:

            with socket.create_connection(
                (
                    '127.0.0.1',
                    port
                ),
                timeout=0.05
            ):
                return True

        except (
            OSError,
            ConnectionRefusedError
        ):
            time.sleep(
                0.01
            )

    return False


# ============================================================
# XRAY COMMAND
# ============================================================

def get_xray_cmd() -> list:

    exe = (
        "xray.exe"
        if os.name == 'nt'
        else "./xray"
    )

    if not os.path.exists(exe):
        exe = "xray"

    return [
        exe,
        "run",
        "-c",
        "stdin:"
    ]


# ============================================================
# EXIT COUNTRY
# ============================================================

def get_exit_country_via_proxy(
    opener,
    timeout
):

    results = []

    # 1. ip-api
    try:

        req = urllib.request.Request(
            "http://ip-api.com/json?fields=status,countryCode",
            headers=HEADERS
        )

        with opener.open(
            req,
            timeout=timeout
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    'utf-8'
                )
            )

            if (
                data.get('status') == 'success'
                and data.get('countryCode')
            ):
                results.append(
                    (
                        'ip-api',
                        data[
                            'countryCode'
                        ].upper()
                    )
                )

    except Exception:
        pass

    # 2. ip2location
    try:

        req = urllib.request.Request(
            "https://api.ip2location.io/",
            headers=HEADERS
        )

        with opener.open(
            req,
            timeout=timeout
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    'utf-8'
                )
            )

            if data.get(
                'country_code'
            ):
                results.append(
                    (
                        'ip2location',
                        data[
                            'country_code'
                        ].upper()
                    )
                )

    except Exception:
        pass

    # 3. ip.sb
    try:

        req = urllib.request.Request(
            "https://api.ip.sb/geoip",
            headers=HEADERS
        )

        with opener.open(
            req,
            timeout=timeout
        ) as resp:

            data = json.loads(
                resp.read().decode(
                    'utf-8'
                )
            )

            cc = (
                data.get(
                    'country_code'
                )
                or data.get(
                    'country'
                )
            )

            if cc:
                results.append(
                    (
                        'ip.sb',
                        cc.upper()
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
                0
            )
            + 1
        )

    for cc, count in counts.items():

        if count >= 2:
            return cc

    for name, cc in results:

        if name == 'ip-api':
            return cc

    return results[0][1]


# ============================================================
# XRAY TEST
# ============================================================

def check_via_xray_detailed(
    outbound_obj: dict,
    timeout: float = XRAY_TEST_TIMEOUT,
    min_success_count: int = 2
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
                }
            }
        ],
        "outbounds": [
            outbound_obj
        ]
    }

    proc = None
    stderr_text = ""

    try:

        cmd = get_xray_cmd()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )

        config_bytes = json.dumps(
            config,
            ensure_ascii=False
        ).encode(
            'utf-8'
        )

        proc.stdin.write(
            config_bytes
        )

        proc.stdin.flush()
        proc.stdin.close()
        proc.stdin = None

        # Даём Xray поднять inbound.
        if not wait_for_port(
            port,
            XRAY_START_TIMEOUT
        ):

            try:
                proc.terminate()
                proc.wait(
                    timeout=0.5
                )
            except Exception:
                pass

            try:
                if proc.stderr:
                    stderr_text = (
                        proc.stderr.read()
                        .decode(
                            'utf-8',
                            errors='ignore'
                        )
                        .strip()
                    )
            except Exception:
                pass

            reason = (
                "Локальный Xray не запустился"
            )

            if stderr_text:
                reason += (
                    f" | Xray: {stderr_text[:800]}"
                )

            return (
                False,
                None,
                reason
            )

        proxy_handler = urllib.request.ProxyHandler(
            {
                'http':
                    f'http://127.0.0.1:{port}',
                'https':
                    f'http://127.0.0.1:{port}'
            }
        )

        opener = urllib.request.build_opener(
            proxy_handler
        )

        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.microsoft.com/connecttest.txt"
        ]

        success_count = 0

        for url in test_urls:

            try:

                req = urllib.request.Request(
                    url,
                    headers=HEADERS
                )

                with opener.open(
                    req,
                    timeout=timeout
                ) as resp:

                    if resp.status in (
                        200,
                        204
                    ):
                        success_count += 1

            except Exception:
                pass

        if success_count < min_success_count:

            return (
                False,
                None,
                f"Тест провален "
                f"({success_count}/3)"
            )

        cc = get_exit_country_via_proxy(
            opener,
            timeout
        )

        return (
            True,
            cc,
            f"OK ({success_count}/3)"
        )

    except Exception as e:

        return (
            False,
            None,
            f"Ошибка Xray test: "
            f"{type(e).__name__}: {e}"
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

            # Если Xray что-то написал в stderr,
            # забираем хвост для диагностики.
            try:

                if proc.stderr:

                    stderr_text = (
                        proc.stderr.read()
                        .decode(
                            'utf-8',
                            errors='ignore'
                        )
                        .strip()
                    )

            except Exception:
                pass


# ============================================================
# CHECK ONE PROXY
# ============================================================

def check_proxy_alive_detailed(
    link: str,
    min_success_count: int = 2
):

    host, port, orig_name = parse_host_port_and_name(
        link
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
            None
        )

    # Оставляем твою фильтрацию Cloudflare.
    if is_cloudflare_or_warp(
        host
    ):
        return (
            False,
            None,
            "Отфильтрован (Cloudflare/WARP)",
            None
        )

    outbound = link_to_xray_outbound(
        link
    )

    if not outbound:

        return (
            False,
            None,
            "Ошибка генерации JSON для Xray",
            None
        )

    is_ok, cc, reason = check_via_xray_detailed(
        outbound,
        timeout=XRAY_TEST_TIMEOUT,
        min_success_count=min_success_count
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
                final_flag
            ),
            reason,
            cc
        )

    return (
        False,
        None,
        reason,
        None
    )


# ============================================================
# FETCH SOURCE
# ============================================================

SUPPORTED_PROTOCOLS = (
    'vless://',
    'vmess://',
    'trojan://',
    'ss://',
    'hysteria2://',
    'hy2://'
)


def fetch_single_url_with_details(
    url: str
) -> dict:

    url_clean = (
        url
        .strip()
        .replace(
            ' ',
            '%20'
        )
    )

    info = {
        'url': url,
        'http_status': None,
        'size_bytes': 0,
        'is_base64': False,
        'total_lines': 0,
        'configs': [],
        'error': None
    }

    try:

        req = urllib.request.Request(
            url_clean,
            headers=HEADERS
        )

        with urllib.request.urlopen(
            req,
            timeout=12,
            context=SSL_CONTEXT
        ) as response:

            info[
                'http_status'
            ] = response.status

            raw_data = response.read()

            info[
                'size_bytes'
            ] = len(raw_data)

            content = raw_data.decode(
                'utf-8',
                errors='ignore'
            )

            content = (
                content
                .replace('\ufeff', '')
            )

            # ------------------------------------------------
            # DIRECT URI
            # ------------------------------------------------

            if not any(
                p in content
                for p in SUPPORTED_PROTOCOLS
            ):

                # ------------------------------------------------
                # BASE64
                # ------------------------------------------------

                try:

                    decoded = safe_b64decode(
                        content
                    )

                    if any(
                        p in decoded
                        for p in SUPPORTED_PROTOCOLS
                    ):

                        content = decoded
                        info[
                            'is_base64'
                        ] = True

                except Exception:
                    pass

            raw_lines = [
                line.strip()
                for line in content.splitlines()
                if line.strip()
            ]

            info[
                'total_lines'
            ] = len(raw_lines)

            valid_configs = []

            for line in raw_lines:

                # Иногда source может иметь BOM.
                line = line.lstrip(
                    '\ufeff'
                ).strip()

                if line.startswith(
                    SUPPORTED_PROTOCOLS
                ):

                    valid_configs.append(
                        sanitize_v2rayng_link(
                            line
                        )
                    )

            info[
                'configs'
            ] = valid_configs

    except Exception as e:

        info[
            'error'
        ] = (
            f"{type(e).__name__}: {e}"
        )

    return info


def fetch_links_parallel_with_source(
    url_file: str
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
            'r',
            encoding='utf-8'
        ) as f:

            urls = [
                line.strip()
                for line in f
                if (
                    line.strip()
                    and not line.strip().startswith('#')
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
                    url
                ): idx
                for idx, url
                in enumerate(
                    urls,
                    1
                )
            }

            for future in as_completed(
                futures
            ):

                idx = futures[
                    future
                ]

                try:
                    res = future.result()
                except Exception as e:
                    print(
                        f"  ├─ ❌ Источник #{idx}: "
                        f"{type(e).__name__}: {e}"
                    )
                    continue

                configs = res[
                    'configs'
                ]

                status_str = (
                    f"HTTP {res['http_status']}"
                    if res['http_status']
                    else "ОШИБКА"
                )

                b64_str = (
                    " [Base64]"
                    if res['is_base64']
                    else ""
                )

                err_str = (
                    f" (Ошибка: {res['error']})"
                    if res['error']
                    else ""
                )

                if (
                    res['http_status']
                    in [200, 204]
                    or configs
                ):
                    successful_sources += 1

                print(
                    f"  ├─ 🔗 Источник #{idx:<3} "
                    f"| Статус: {status_str:<10} "
                    f"| Размер: {res['size_bytes']}B "
                    f"| Строк: {res['total_lines']} "
                    f"| Конфигов: {len(configs)}"
                    f"{b64_str}{err_str}"
                )

                for cfg in configs:

                    links_with_source.append(
                        (
                            cfg,
                            res['url']
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
            f"{url_file}: "
            f"{type(e).__name__}: {e}"
        )

    return links_with_source


# ============================================================
# INCOMING QUEUE
# ============================================================

def process_incoming_queue():

    incoming_proxies = []
    incoming_raw_ips = []

    if not os.path.exists(
        INCOMING_FILE
    ):
        return (
            incoming_proxies,
            incoming_raw_ips
        )

    try:

        with open(
            INCOMING_FILE,
            'r',
            encoding='utf-8'
        ) as f:

            lines = [
                line.strip()
                for line in f
                if (
                    line.strip()
                    and not line.strip().startswith('#')
                )
            ]

        unique_lines = list(
            dict.fromkeys(
                lines
            )
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

                extracted = parse_ip_or_resolve(
                    item
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
            f"⚠️ Ошибка чтения очереди: "
            f"{type(e).__name__}: {e}"
        )

    return (
        incoming_proxies,
        incoming_raw_ips
    )


# ============================================================
# PREVIOUS ALIVES
# ============================================================

def load_previous_alives():

    prev_wl = []
    prev_bl = []

    if os.path.exists(
        'alive_bs.txt'
    ):

        try:

            with open(
                'alive_bs.txt',
                'r',
                encoding='utf-8'
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
        'alive_bl.txt'
    ):

        try:

            with open(
                'alive_bl.txt',
                'r',
                encoding='utf-8'
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

    return (
        prev_wl,
        prev_bl
    )


# ============================================================
# DEDUP KEY
# ============================================================

def get_config_dedup_key(
    link: str
):

    host, port, _ = parse_host_port_and_name(
        link
    )

    if (
        not host
        or not port
    ):
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
            '://',
            1
        )[0].lower()
        if '://' in link
        else ''
    )

    sni = extract_sni_from_link(
        link
    )

    # Идентификатор конкретного аккаунта.
    identity = ""

    method = ""
    password = ""

    net = ""
    path = ""
    security = ""
    flow = ""
    pbk = ""
    sid = ""
    fp = ""
    host_param = ""
    service_name = ""
    mode = ""

    try:

        # --------------------------------------------
        # VMESS
        # --------------------------------------------

        if protocol == 'vmess':

            b64_data = link.split(
                '://',
                1
            )[1].split(
                '#',
                1
            )[0]

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            identity = str(
                data.get(
                    'id',
                    ''
                )
            )

            method = str(
                data.get(
                    'scy',
                    'auto'
                )
            )

            net = str(
                data.get(
                    'net',
                    'raw'
                )
            ).lower()

            path = str(
                data.get(
                    'path',
                    ''
                )
            )

            security = str(
                data.get(
                    'tls',
                    ''
                )
            ).lower()

            flow = str(
                data.get(
                    'flow',
                    ''
                )
            )

            host_param = str(
                data.get(
                    'host',
                    ''
                )
            )

        # --------------------------------------------
        # Остальные
        # --------------------------------------------

        else:

            parsed = urllib.parse.urlsplit(
                link
            )

            identity = (
                urllib.parse.unquote(
                    parsed.username or ''
                )
            )

            # Для SS username/password
            # являются частью уникальности.
            if protocol == 'ss':

                password = (
                    urllib.parse.unquote(
                        parsed.password or ''
                    )
                )

            elif protocol == 'trojan':

                password = identity

            elif protocol in (
                'hysteria2',
                'hy2'
            ):

                password = identity

            query_params = parse_query(
                link
            )

            net = (
                q(
                    query_params,
                    'type',
                    ''
                )
                or q(
                    query_params,
                    'net',
                    'raw'
                )
            ).lower()

            path = q(
                query_params,
                'path',
                ''
            )

            security = q(
                query_params,
                'security',
                ''
            ).lower()

            flow = q(
                query_params,
                'flow',
                ''
            ).lower()

            pbk = q(
                query_params,
                'pbk',
                ''
            )

            sid = q(
                query_params,
                'sid',
                ''
            )

            fp = (
                q(
                    query_params,
                    'fp',
                    ''
                )
                or q(
                    query_params,
                    'fingerprint',
                    ''
                )
            )

            host_param = q(
                query_params,
                'host',
                ''
            )

            service_name = q(
                query_params,
                'serviceName',
                ''
            )

            mode = q(
                query_params,
                'mode',
                ''
            )

            method = q(
                query_params,
                'method',
                ''
            )

            if protocol == 'ss':

                # Некоторые SS URI имеют
                # credential в encoded netloc.
                if '@' in link:

                    try:

                        parsed_user = (
                            parsed.username
                            or ''
                        )

                        parsed_pass = (
                            parsed.password
                            or ''
                        )

                        identity = (
                            urllib.parse.unquote(
                                parsed_user
                            )
                        )

                        password = (
                            urllib.parse.unquote(
                                parsed_pass
                            )
                        )

                    except Exception:
                        pass

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
        identity,
        method,
        password,
        flow,
        pbk,
        sid,
        fp,
        host_param,
        service_name,
        mode
    )


# ============================================================
# CLEAN + DEDUP
# ============================================================

def clean_and_dedup(
    tagged_items: list
) -> list:

    seen_strings = set()
    seen_keys = set()

    result = []

    removed_text = 0
    removed_keys = 0
    invalid = 0

    for item in tagged_items:

        if len(item) >= 3:

            link = item[0]
            source_tag = item[1]
            forced_category = item[2]

        else:

            link = item[0]
            source_tag = item[1]
            forced_category = None

        link = (
            link
            .strip()
        )

        if not link.startswith(
            SUPPORTED_PROTOCOLS
        ):
            invalid += 1
            continue

        if link in seen_strings:

            removed_text += 1
            continue

        seen_strings.add(
            link
        )

        key = get_config_dedup_key(
            link
        )

        if not key:

            invalid += 1
            continue

        if key in seen_keys:

            removed_keys += 1
            continue

        seen_keys.add(
            key
        )

        result.append(
            (
                link,
                source_tag,
                forced_category
            )
        )

    print(
        f"🧹 Дедуп до пинга: "
        f"было {len(tagged_items)}, "
        f"стало {len(result)} | "
        f"полных дублей: {removed_text}, "
        f"логических дублей: {removed_keys}, "
        f"невалидных: {invalid}"
    )

    return result


# ============================================================
# LIMIT PER IP
# ============================================================

def limit_configs_per_ip(
    items_list: list,
    white_ips: set,
    is_wl_list: bool = False,
    max_per_ip_bl: int = MAX_CONFIGS_PER_IP_BL,
    max_per_ip_wl: int = MAX_CONFIGS_PER_IP_WL,
    max_per_subnet_bl: int = MAX_CONFIGS_PER_SUBNET_BL
) -> list:

    ip_counter = defaultdict(
        int
    )

    subnet_counter = defaultdict(
        int
    )

    filtered = []

    grouped_by_ip = defaultdict(
        list
    )

    for item in items_list:

        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list)
            )
            else item
        )

        host, _, _ = parse_host_port_and_name(
            link
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

        grouped_by_ip[
            ip_str
        ].append(
            item
        )

    for ip_str, items in grouped_by_ip.items():

        # Если весь список явно WL —
        # WL limit применяется всегда.
        # Это нужно для alive_wl_data.
        is_wl = (
            is_wl_list
            or ip_str in white_ips
        )

        limit = (
            max_per_ip_wl
            if is_wl
            else max_per_ip_bl
        )

        # Для WL сначала разные SNI.
        if is_wl:

            seen_snis = set()

            priority = []
            rest = []

            for item in items:

                link = (
                    item[0]
                    if isinstance(
                        item,
                        (tuple, list)
                    )
                    else item
                )

                sni = (
                    extract_sni_from_link(
                        link
                    )
                    or ""
                )

                if sni not in seen_snis:

                    seen_snis.add(
                        sni
                    )

                    priority.append(
                        item
                    )

                else:

                    rest.append(
                        item
                    )

            items = (
                priority
                + rest
            )

        for item in items:

            if (
                ip_counter[
                    ip_str
                ] >= limit
            ):
                break

            # BL subnet limit
            if not is_wl:

                try:

                    ip_obj = ipaddress.ip_address(
                        ip_str
                    )

                    if ip_obj.version == 4:

                        subnet_key = str(
                            ipaddress.ip_network(
                                f"{ip_str}/24",
                                strict=False
                            )
                        )

                    else:

                        subnet_key = str(
                            ipaddress.ip_network(
                                f"{ip_str}/64",
                                strict=False
                            )
                        )

                    if (
                        subnet_counter[
                            subnet_key
                        ] >= max_per_subnet_bl
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

            filtered.append(
                item
            )

    print(
        f"✂️ Ограничение IP: "
        f"было {len(items_list)}, "
        f"стало {len(filtered)} | "
        f"BL/IP={max_per_ip_bl}, "
        f"WL/IP={max_per_ip_wl}, "
        f"BL/subnet={max_per_subnet_bl}"
    )

    return filtered


# ============================================================
# FINAL DEDUP
# ============================================================

def dedup_advanced(
    config_list: list,
    list_name: str = ""
) -> list:

    seen_keys = set()
    result = []

    for item in config_list:

        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list)
            )
            else item
        )

        key = get_config_dedup_key(
            link
        )

        if (
            key
            and key not in seen_keys
        ):

            seen_keys.add(
                key
            )

            result.append(
                item
            )

    removed = (
        len(config_list)
        - len(result)
    )

    print(
        f"🔍 Финальная дедупликация "
        f"{list_name}: "
        f"было {len(config_list)}, "
        f"осталось {len(result)}, "
        f"удалено {removed}"
    )

    return result


# ============================================================
# RENAME
# ============================================================

def rename_config(
    link: str,
    index: int,
    tag: str,
    detected_flag: str
) -> str:

    new_name = (
        f"{detected_flag} "
        f"{tag} "
        f"Сервер {index}"
    )

    # VMESS name хранится в ps.
    if link.startswith(
        "vmess://"
    ):

        try:

            b64_data = link.split(
                '://',
                1
            )[1].strip()

            decoded = safe_b64decode(
                b64_data
            )

            data = json.loads(
                decoded
            )

            data['ps'] = new_name

            return (
                "vmess://"
                +
                safe_b64encode(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                        separators=(',', ':')
                    )
                )
            )

        except Exception:
            pass

    if "://" in link:

        main_part = link.split(
            '#',
            1
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
    minority_ratio=0.10
):

    priority = []
    minority = []

    for item in alive_configs:

        link = (
            item[0]
            if isinstance(
                item,
                (tuple, list)
            )
            else item
        )

        proto = link.split(
            '://',
            1
        )[0].lower()

        if proto in (
            'vless',
            'hysteria2',
            'hy2'
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
        )
    )

    if len(minority) > max_minority:

        minority = minority[
            :max_minority
        ]

    print(
        f"🎯 Фильтр BL: "
        f"VLESS/Hy2={len(priority)}, "
        f"остальные={len(minority)} "
        f"(лимит {minority_ratio * 100:.0f}%)"
    )

    return (
        priority
        + minority
    )


# ============================================================
# BUILD WHITE IP DATABASE
# ============================================================

def load_white_ips():
    white_ips = set()

    if os.path.exists(
        WHITE_IP_FILE
    ):

        try:

            with open(
                WHITE_IP_FILE,
                'r',
                encoding='utf-8'
            ) as f:

                for line in f:

                    extracted = parse_ip_or_resolve(
                        line
                    )

                    white_ips.update(
                        extracted
                    )

        except Exception as e:

            print(
                f"⚠️ Ошибка чтения "
                f"{WHITE_IP_FILE}: {e}"
            )

    return white_ips


def save_white_ips(
    white_ips: set
):

    def ip_sort_key(ip):

        try:
            return (
                0,
                ipaddress.ip_address(ip)
            )
        except ValueError:
            return (
                1,
                ip
            )

    with open(
        WHITE_IP_FILE,
        'w',
        encoding='utf-8'
    ) as f:

        for ip in sorted(
            white_ips,
            key=ip_sort_key
        ):
            f.write(
                f"{ip}\n"
            )

    print(
        f"💾 База {WHITE_IP_FILE} "
        f"сохранена. Всего IP: "
        f"{len(white_ips)}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "🚀 Старт продвинутого "
        "Xray-парсера..."
    )

    wl_file = (
        'sources_wl.txt'
        if os.path.exists(
            'sources_wl.txt'
        )
        else 'source_wl.txt'
    )

    bl_file = (
        'sources_bl.txt'
        if os.path.exists(
            'sources_bl.txt'
        )
        else 'source_bl.txt'
    )

    # ========================================================
    # 1. DOWNLOAD SOURCES
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
    # 2. WHITE IP DATABASE
    # ========================================================

    white_ips = load_white_ips()

    # Важный момент:
    # incoming_raw_ips добавляются в white_ip.
    for ip in incoming_raw_ips:
        white_ips.add(ip)

    save_white_ips(
        white_ips
    )

    # ========================================================
    # 3. ДЕДУП
    #
    # WL И BL ДЕРЖИМ РАЗДЕЛЬНО.
    #
    # Это исправляет главную проблему твоей текущей версии:
    # source_wl.txt теперь действительно является WL source,
    # а не просто ещё одним источником для общего classify.
    # ========================================================

    wl_tagged = []

    for link, src in wl_fetched:

        wl_tagged.append(
            (
                link,
                src,
                'WL_SOURCE'
            )
        )

    bl_tagged = []

    for link, src in bl_fetched:

        bl_tagged.append(
            (
                link,
                src,
                'BL_SOURCE'
            )
        )

    # incoming proxies:
    # классифицируем отдельно.
    incoming_tagged = []

    for link in incoming_proxies:

        category = classify_config(
            link,
            white_ips,
            ru_sni_ratio=0.3
        )

        incoming_tagged.append(
            (
                link,
                'INCOMING_TELEGRAM',
                category
            )
        )

    clean_wl = clean_and_dedup(
        wl_tagged
    )

    clean_bl = clean_and_dedup(
        bl_tagged
    )

    clean_incoming = clean_and_dedup(
        incoming_tagged
    )

    # ========================================================
    # 4. CROSS-SOURCE DEDUP
    #
    # Если конфиг есть одновременно
    # в WL и BL, WL имеет приоритет.
    # ========================================================

    final_candidates = []

    seen_keys = set()

    def append_unique(
        items
    ):

        for item in items:

            link = item[0]

            key = get_config_dedup_key(
                link
            )

            if not key:
                continue

            if key in seen_keys:
                continue

            seen_keys.add(
                key
            )

            final_candidates.append(
                item
            )

    # WL source первым.
    append_unique(
        clean_wl
    )

    # Incoming после WL.
    append_unique(
        clean_incoming
    )

    # BL последним.
    append_unique(
        clean_bl
    )

    print(
        f"📦 После cross-source дедуп: "
        f"{len(final_candidates)}"
    )

    # ========================================================
    # 5. РАЗДЕЛЯЕМ WL / BL
    #
    # WL НЕ режем до пинга.
    #
    # BL режем до пинга.
    # ========================================================

    pre_ping_wl = []
    pre_ping_bl = []

    for item in final_candidates:

        link = item[0]
        source = item[1]
        forced_category = item[2]

        # WL source => ВСЕГДА WL
        if forced_category == 'WL_SOURCE':

            pre_ping_wl.append(
                (
                    link,
                    source
                )
            )

            continue

        # Explicit incoming category.
        if forced_category == 'WL':

            pre_ping_wl.append(
                (
                    link,
                    source
                )
            )

            continue

        if forced_category == 'BL':

            pre_ping_bl.append(
                (
                    link,
                    source
                )
            )

            continue

        # Теоретически сюда не должно попасть.
        category = classify_config(
            link,
            white_ips,
            ru_sni_ratio=0.3
        )

        if category == 'WL':

            pre_ping_wl.append(
                (
                    link,
                    source
                )
            )

        else:

            pre_ping_bl.append(
                (
                    link,
                    source
                )
            )

    # --------------------------------------------------------
    # BL pre-ping limit.
    # WL никаких лимитов здесь не получает.
    # --------------------------------------------------------

    pre_ping_bl = limit_configs_per_ip(
        pre_ping_bl,
        white_ips,
        is_wl_list=False,
        max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
        max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
        max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL
    )

    print(
        f"\n📡 До пинга:"
        f" WL={len(pre_ping_wl)}"
        f" | BL={len(pre_ping_bl)}"
    )

    # ========================================================
    # 6. PREVIOUS ALIVES
    # ========================================================

    prev_wl_links, prev_bl_links = (
        load_previous_alives()
    )

    seen_ping = set()

    for link, _ in pre_ping_wl:
        seen_ping.add(link)

    for link, _ in pre_ping_bl:
        seen_ping.add(link)

    # Previous WL.
    for link in prev_wl_links:

        if link not in seen_ping:

            pre_ping_wl.append(
                (
                    link,
                    'PREV_WL'
                )
            )

            seen_ping.add(
                link
            )

    # Previous BL.
    for link in prev_bl_links:

        if link not in seen_ping:

            pre_ping_bl.append(
                (
                    link,
                    'PREV_BL'
                )
            )

            seen_ping.add(
                link
            )

    # ========================================================
    # 7. FORCE WHITE-IP CONFIGS
    #
    # Эти конфиги считаются WL без пинга,
    # как и в твоей исходной логике.
    # ========================================================

    alive_wl_data = []
    alive_bl_data = []

    ping_wl = []
    ping_bl = []

    for link, src in pre_ping_wl:

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

        matched_ip = (
            find_matched_ip_for_link(
                link,
                white_ips
            )
        )

        if matched_ip:

            orig_flag = (
                extract_clean_flag(
                    orig_name
                )
            )

            alive_wl_data.append(
                (
                    link,
                    orig_flag
                )
            )

        else:

            ping_wl.append(
                (
                    link,
                    src
                )
            )

    for link, src in pre_ping_bl:

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

        matched_ip = (
            find_matched_ip_for_link(
                link,
                white_ips
            )
        )

        if matched_ip:

            orig_flag = (
                extract_clean_flag(
                    orig_name
                )
            )

            alive_wl_data.append(
                (
                    link,
                    orig_flag
                )
            )

        else:

            # BL source может всё-таки стать WL
            # по твоим правилам RU IP/SNI/keywords.
            category = classify_config(
                link,
                white_ips,
                ru_sni_ratio=0.3
            )

            if category == 'WL':

                ping_wl.append(
                    (
                        link,
                        src
                    )
                )

            else:

                ping_bl.append(
                    (
                        link,
                        src
                    )
                )

    print(
        f"\n📡 Отправка на Xray:"
        f" WL={len(ping_wl)}"
        f" | BL={len(ping_bl)}"
    )

    # ========================================================
    # 8. XRAY PING
    # ========================================================

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        # ----------------------------------------------------
        # WL: 1/3
        # ----------------------------------------------------

        wl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                WL_MIN_SUCCESS
            ): (
                link,
                src
            )
            for link, src in ping_wl
        }

        wl_ok = 0
        wl_fail = 0

        for future in as_completed(
            wl_futures
        ):

            link, src = wl_futures[
                future
            ]

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception as e:

                is_ok = False
                res = None
                reason = (
                    f"Worker error: "
                    f"{type(e).__name__}: {e}"
                )
                cc = None

            if is_ok:

                alive_wl_data.append(
                    res
                )

                wl_ok += 1

            else:

                wl_fail += 1

        print(
            f"✅ WL ping: "
            f"OK={wl_ok} "
            f"| FAIL={wl_fail}"
        )

        # ----------------------------------------------------
        # BL: 2/3
        # ----------------------------------------------------

        bl_futures = {
            executor.submit(
                check_proxy_alive_detailed,
                link,
                BL_MIN_SUCCESS
            ): (
                link,
                src
            )
            for link, src in ping_bl
        }

        bl_ok = 0
        bl_fail = 0
        bl_ru = 0

        for future in as_completed(
            bl_futures
        ):

            link, src = bl_futures[
                future
            ]

            try:

                is_ok, res, reason, cc = (
                    future.result()
                )

            except Exception as e:

                is_ok = False
                res = None
                reason = (
                    f"Worker error: "
                    f"{type(e).__name__}: {e}"
                )
                cc = None

            if not is_ok:

                bl_fail += 1
                continue

            # Живой BL с RU exit
            # переносим в WL.
            if (
                cc
                and cc.upper() == 'RU'
            ):

                alive_wl_data.append(
                    res
                )

                bl_ru += 1

            else:

                alive_bl_data.append(
                    res
                )

                bl_ok += 1

        print(
            f"✅ BL ping: "
            f"OK={bl_ok} "
            f"| RU→WL={bl_ru} "
            f"| FAIL={bl_fail}"
        )

    # ========================================================
    # 9. FINAL WL / BL DEDUP
    # ========================================================

    alive_wl_data = dedup_advanced(
        alive_wl_data,
        "WL"
    )

    alive_bl_data = dedup_advanced(
        alive_bl_data,
        "BL"
    )

    # ========================================================
    # 10. FINAL LIMITS
    # ========================================================

    # WL list => WL limit на IP.
    alive_wl_clean = limit_configs_per_ip(
        alive_wl_data,
        white_ips,
        is_wl_list=True,
        max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
        max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
        max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL
    )

    # BL => BL limits.
    alive_bl_limited = limit_configs_per_ip(
        alive_bl_data,
        white_ips,
        is_wl_list=False,
        max_per_ip_bl=MAX_CONFIGS_PER_IP_BL,
        max_per_ip_wl=MAX_CONFIGS_PER_IP_WL,
        max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL
    )

    # Старые протоколы режем только BL.
    alive_bl_clean = filter_protocols_bl(
        alive_bl_limited,
        minority_ratio=0.10
    )

    # ========================================================
    # 11. FULL
    #
    # WL имеет приоритет над BL.
    # НЕТ повторного WL-limit на весь смешанный список.
    # ========================================================

    alive_full_raw = (
        alive_wl_clean
        + alive_bl_clean
    )

    alive_full_clean = dedup_advanced(
        alive_full_raw,
        "FULL"
    )

    # ========================================================
    # 12. SET WL KEYS
    # ========================================================

    wl_keys = set()

    for item in alive_wl_clean:

        link = item[0]

        key = get_config_dedup_key(
            link
        )

        if key:
            wl_keys.add(
                key
            )

    # ========================================================
    # 13. FINAL FILES
    # ========================================================

    final_wl = []

    for idx, item in enumerate(
        alive_wl_clean,
        1
    ):

        link, flag = item

        final_wl.append(
            rename_config(
                link,
                idx,
                "[WL]",
                flag
            )
        )

    final_bl = []

    for idx, item in enumerate(
        alive_bl_clean,
        1
    ):

        link, flag = item

        final_bl.append(
            rename_config(
                link,
                idx,
                "[BL]",
                flag
            )
        )

    final_full = []

    for idx, item in enumerate(
        alive_full_clean,
        1
    ):

        link, flag = item

        key = get_config_dedup_key(
            link
        )

        tag = (
            "[WL]"
            if key in wl_keys
            else "[BL]"
        )

        final_full.append(
            rename_config(
                link,
                idx,
                tag,
                flag
            )
        )

    # ========================================================
    # 14. SAVE BASE64 SUBSCRIPTIONS
    # ========================================================

    with open(
        'alive_bs.txt',
        'w',
        encoding='utf-8'
    ) as f:

        f.write(
            safe_b64encode(
                '\n'.join(
                    final_wl
                )
            )
        )

    with open(
        'alive_bl.txt',
        'w',
        encoding='utf-8'
    ) as f:

        f.write(
            safe_b64encode(
                '\n'.join(
                    final_bl
                )
            )
        )

    with open(
        'alive_full.txt',
        'w',
        encoding='utf-8'
    ) as f:

        f.write(
            safe_b64encode(
                '\n'.join(
                    final_full
                )
            )
        )

    # ========================================================
    # 15. SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("📊 ФИНАЛЬНАЯ СТАТИСТИКА")
    print("=" * 70)
    print(
        f"WL alive:   {len(final_wl)}"
    )
    print(
        f"BL alive:   {len(final_bl)}"
    )
    print(
        f"FULL alive: {len(final_full)}"
    )
    print(
        f"White IPs:  {len(white_ips)}"
    )
    print("=" * 70)

    if GEO_READER:

        try:
            GEO_READER.close()
        except Exception:
            pass

    print(
        "✨ Готово! "
        "alive_bs.txt, "
        "alive_bl.txt и "
        "alive_full.txt записаны."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    main()