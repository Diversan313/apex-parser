"""Константы, пути, regex, кэши, SSL, флаги вывода."""
import os
import re
import ssl
import threading
import ipaddress

# Пути и файлы
WHITE_IP_FILE = "white_ip.txt"
INCOMING_FILE = "incoming_sources.txt"
MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
SNI_WHITELIST_PATH = os.path.join("arch", "lists", "whitelist.txt")
SNI_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

# Параллелизм
MAX_QUEUE_LIMIT = 1000
MAX_WORKERS = 15

# Лимиты уникальности
MAX_CONFIGS_PER_IP_WL = 30          # макс. конфигов на один IP в WL
MAX_CONFIGS_PER_IP_BL = 2           # макс. конфигов на один IP в BL
MAX_CONFIGS_PER_SUBNET_BL = 5       # макс. конфигов на /24 в BL

# WL / SNI
RU_SNI_RATIO = 0.30                 # доля прочих .ru/.su SNI → WL (0.0–1.0)

# Xray / сетевые тесты
WL_MIN_SUCCESS_COUNT = 1            # успешных тестов для WL
BL_MIN_SUCCESS_COUNT = 2            # успешных тестов для BL
XRAY_START_TIMEOUT = 1.2            # сек, старт xray
XRAY_TEST_TIMEOUT = 6.0             # сек, проверка через xray
TCP_CHECK_TIMEOUT = 2.5             # сек, TCP pre-check

# Фильтры
REMOVE_CF_WARP = True               # отсекать Cloudflare / WARP
REMOVE_PRIVATE_INVALID = True       # отсекать private / invalid / loopback
KEEP_PREV_ALIVES = True             # подмешивать прошлые alive в кандидаты

# Вывод файлов
WRITE_BASE64 = True                 # alive_*.txt (base64)
WRITE_PLAIN = True                  # alive_plain_*.txt
WRITE_YAML = True                   # alive_*.yaml (Clash)
WRITE_FULL = True                   # писать full-списки (иначе только WL/BL)
WRITE_LATEST_JSON = True            # stats/latest.json
WRITE_COUNTRY = False               # списки по странам
DELETE_MISSING_COUNTRIES = False    # удалять старые country-файлы
WRITE_OTHER_AI = False              # отдельный список под AI
WRITE_OTHER_TORRENT = False         # отдельный список под торрент

# Rename (имя в клиенте)
RENAME_PREFIX_WL = "[WL]"
RENAME_PREFIX_BL = "[BL]"
RENAME_PREFIX_AI = "[AI]"
RENAME_PREFIX_TORRENT = "[TR]"
# Плейсхолдеры: {flag} {tag} {index}
# Пример: 🇳🇱 [WL] Сервер 12
RENAME_TEMPLATE = "{flag} {tag} Сервер {index}"

# SSL / HTTP
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

# Cache
DNS_CACHE = {}
DNS_LOCK = threading.Lock()
GEO_ONLINE_CACHE = {}
GEO_LOCK = threading.Lock()

# Regex
WL_KEYWORDS_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(?:wl|бс|обход|глусилк(?:а|и|ок|ам|ах)?|"
    r"глушилк(?:а|и|ок|ам|ах)?|whitelist|lte|"
    r"бел(?:ый|ая|ое|ые|ых|ому|ым|ыми)?(?:\s*списк(?:и|а|ов|ам|ах)?)?)"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)
BL_KEYWORDS_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(?:bl|blacklist|black[\s_-]?list|"
    r"блеклист|блаклист|блэклист|"
    r"wifi|wi[\s_-]?fi|вай[\s_-]?фай|"
    r"чс|чёрн(?:ый|ая|ое|ые|ых|ому)?|черн(?:ый|ая|ое|ые|ых|ому)?)"
    r"(?:\s*списк(?:и|а|ов|ам|ах)?)?"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)
EXPIRED_MARKERS_REGEX = re.compile(
    r"(?i)(?:expired|истек\w*|переехал\w*|"
    r"возьмите\s*новую|подписка\s*истекла|"
    r"недействительн\w*|не\s*действует|невалидн\w*|"
    r"invalid(?:ated)?|disabled|заблокир\w*|blocked|deactivated|"
    r"renew\s*sub|subscription\s*(?:expired|ended)|"
    r"outdated|out\s*of\s*date)"
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

# Cloudflare
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
CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CF_CIDRS]

# MaxMind (инициализируется в geoip.init_geoip)
try:
    import maxminddb
except ImportError:
    maxminddb = None
GEO_READER = None
