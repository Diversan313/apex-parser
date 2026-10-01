"""Константы, пути, regex, кэши, SSL, флаги вывода."""
import os
import re
import ssl
import threading
import ipaddress

# Пути и файлы
WHITE_IP_FILE = "white_ip.txt"
WHITE_IP_URL = "https://raw.githubusercontent.com/Diversan313/apex-white-ip/main/white_ip.txt"  # пусто = локал white_ip.txt
MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
SNI_WHITELIST_PATH = os.path.join("arch", "lists", "whitelist.txt")
SNI_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

# Hysteria2: отдельное официальное ядро для теста(только hy2)
HYSTERIA2_CORE = False
HY2_CORE_FILE = "hysteria2.exe" if os.name == "nt" else "hysteria2"
HY2_CORE_URL_WINDOWS = "https://github.com/apernet/hysteria/releases/latest/download/hysteria-windows-amd64.exe"
HY2_CORE_URL_LINUX = "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64"

# Ядро Xray
AUTO_DOWNLOAD_XRAY = True           # качать ядро Xray, если его нет в корне (win/linux)
XRAY_CORE_URL_WINDOWS = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
XRAY_CORE_URL_LINUX = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

# Зеркало GitVerse (деплой из workflow; токен — в секретах GITVERSE_TOKEN)
GITVERSE_ENABLED = True             # False = GitVerse пропускается
GITVERSE_REPO = "https://gitverse.ru/bikinitw22/apelsintel.git"

# Sources
SECURE_SOURCES_GITHUB = True        # скрыть сурса в приватном репо
SPLIT_SOURCES = True                # True = sources_wl/bl, False = один sources.txt
ENABLE_TG_SOURCES = True            # parser_tg.py и sources_tg.txt (нужны TG_API_ID / HASH / SESSION)
DECRYPT_HAPP = True                 # расшифровывать happ://crypt* ссылки в источниках
SOURCES_DIR = os.path.join("apex", "sources")  # локальные сурса при SECURE=False

# Параллелизм
MAX_WORKERS = 15                    # потоки RD теста Xray

# Лимиты уникальности
MAX_CONFIGS_PER_IP_WL = 5           # макс. конфигов на один IP в WL
MAX_CONFIGS_PER_IP_BL = 1           # макс. конфигов на один IP в BL
MAX_CONFIGS_PER_SUBNET_BL = 5       # макс. конфигов на /24 в BL
EXOTIC_MAX_NODES = 5                # страна «экзотическая», если в ней нод <= N

# WL / SNI
RU_SNI_RATIO = 0.0                  # доля прочих .ru/.su SNI → WL (0.0–1.0)

# BL
BL_RU_TO_WL = True                  # живые BL с RU-выходом перекидывать в WL
BL_MINORITY_RATIO = 0.10            # доля старых протоколов (vmess/trojan/ss) в BL

# Xray / сетевые тесты
WL_MIN_SUCCESS_COUNT = 1            # успешных тестов для WL
BL_MIN_SUCCESS_COUNT = 2            # успешных тестов для BL
XRAY_START_TIMEOUT = 1.2            # сек, старт xray
XRAY_TEST_TIMEOUT = 6.0             # сек, проверка через xray
TCP_CHECK_TIMEOUT = 2.5             # сек, TCP pre-check

# Фильтры
REMOVE_CF_WARP = True               # отсекать Cloudflare / WARP
REMOVE_PRIVATE_INVALID = True       # отсекать private / invalid / loopback
REMOVE_UNSAFE = True                # отсекать небезопасные: allowInsecure=1, plaintext без TLS
HEAL_CONFIG = True                  # вычищать рекламный мусор из параметров ссылок
KEEP_PREV_ALIVES = True             # подмешивать прошлые alive в кандидаты

# Вывод файлов
WRITE_LATEST_JSON = True            # stats/latest.json
WRITE_BASE64 = True                 # alive_*.txt (base64)
WRITE_PLAIN = True                  # alive_plain_*.txt
WRITE_YAML = True                   # alive_*.yaml (Clash)
WRITE_FULL = True                   # писать full-списки (иначе только WL/BL)
WRITE_OTHER_AI = True               # отдельный список под AI
WRITE_OTHER_TORRENT = True          # отдельный список под торрент
WRITE_OTHER_PROTOCOLS = True        # разбивка по протоколам в subs/other/protocols/
WRITE_OTHER_EXOTIC = True           # редкие страны (мало нод) в subs/other/exotic/
WRITE_OTHER_COUNTRIES = True        # списки по странам
WRITE_OTHER_CONTINENTS = True       # списки по континентам subs/other/continents/
DELETE_MISSING_COUNTRIES = True     # удалять старые country-папки

# Rename (имя в клиенте)
RENAME_PREFIX_WL = "[WL]"
RENAME_PREFIX_BL = "[BL]"
RENAME_PREFIX_AI = "[AI]"
RENAME_PREFIX_TORRENT = "[TR]"
# Плейсхолдеры: {flag} {tag} {index}
# Пример: 🇳🇱 [WL] Сервер 12
RENAME_TEMPLATE = "{flag} {tag} Сервер {index}"
UTF8_CONFIG_NAMES = True            # False = обычная кодировка (совместимость), True = raw UTF-8 (оптимизация и читабельность)

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
AI_KEYWORDS_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(?:"
    r"ии|нейро|нейро(?:сеть|нка|нки|сети)?|нейросет(?:ь|и|ей|ям|ями|ях)?|"
    r"искусственн(?:ый|ая|ое|ые)\s*интеллект(?:а|у|ом|е)?|"
    r"ai|a\.i\.|llm|llms|gpt|chatgpt|chat[\s_-]?gpt|"
    r"openai|open[\s_-]?ai|"
    r"gemini|bard|claude|anthropic|grok|xai|x\.ai|"
    r"perplexity|copilot|bing[\s_-]?chat|"
    r"deepseek|qwen|llama|mistral|mixtral|phi[\s_-]?3?|"
    r"yi[\s_-]?large|yi[\s_-]?34b|command[\s_-]?r|"
    r"midjourney|stable[\s_-]?diffusion|sdxl|flux|"
    r"dall[\s_-]?e|dalle|sora|runway|"
    r"джбт|джпт|джипити|джи[\s_-]?пити"
    r")"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)
TORRENT_KEYWORDS_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(?:torrent|p2p|bittorrent|"
    r"торрент|торент|п2п|пи2пи|питупи)"
    r"(?:$|[^a-zA-Zа-яА-Я0-9])"
)
TORRENT_NEGATIVE_REGEX = re.compile(
    r"(?i)(?:^|[^a-zA-Zа-яА-Я0-9])"
    r"(?:not|no|dont\s*use|don't\s*use|"
    r"не|не\s*для|нельзя|запрещено)"
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

# Cloudflare IPv6
CF_IPV6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]
CF_IPV6_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in CF_IPV6_CIDRS
]

# MaxMind (инициализируется в geoip.init_geoip)
try:
    import maxminddb
except ImportError:
    maxminddb = None
GEO_READER = None
