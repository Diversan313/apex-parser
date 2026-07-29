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
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ И ЛИМИТЫ ---
WHITE_IP_FILE = 'white_ip.txt'
INCOMING_FILE = 'incoming_sources.txt'
MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

MAX_QUEUE_LIMIT = 1000        # Максимум элементов из очереди Telegram за раз
MAX_WORKERS = 15              # Ограничение потоков

# --- КЭШИ И БЛОКИРОВКИ ПОТОКОВ ---
DNS_CACHE = {}
DNS_LOCK = threading.Lock()

GEO_ONLINE_CACHE = {}
GEO_LOCK = threading.Lock()

TRACE_LOCK = threading.Lock()

# Регулярка для ключевых слов белых списков
WL_KEYWORDS_REGEX = re.compile(
    r'(?i)(?:^|[^a-zA-Zа-яА-Я0-9])(бс|обход|глусилк(?:а|и|ок|ам|ах)?|глушилк(?:а|и|ок|ам|ах)?|whitelist|lte|бел(?:ый|ые|ых)\s*списк(?:и|а|ов|ам|ах)?)(?:$|[^a-zA-Zа-яА-Я0-9])'
)

# Регулярка для валидации доменных имен
DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$',
    re.IGNORECASE
)

try:
    import maxminddb
except ImportError:
    maxminddb = None

FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

CF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "162.159.0.0/16"
]
CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CF_CIDRS]

def is_valid_public_host(host):
    """ Проверка хоста на валидность и исключение локального/числового мусора """
    if not host:
        return False
    clean_host = host.strip('[]').strip().lower()
    if not clean_host:
        return False

    # Если хост состоит только из цифр (например, 9338383929) — это мусор
    if clean_host.isdigit():
        return False

    # Проверка на IP адрес (IPv4 / IPv6)
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if ip_obj.version == 4 and '.' not in clean_host:
            return False
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_reserved or ip_obj.is_link_local or 
            ip_obj.is_unspecified):
            return False
        return True
    except ValueError:
        pass

    # Если это не IP, проверяем как доменное имя
    if '.' not in clean_host or clean_host.startswith('.') or clean_host.endswith('.'):
        return False

    if not DOMAIN_REGEX.match(clean_host):
        return False

    if clean_host.endswith(('.local', '.localhost', '.internal', '.lan', '.home', '.arpa', '.invalid', '.test')):
        return False

    return True

def download_geoip_db():
    if not os.path.exists(MMDB_PATH):
        print("📥 Скачиваю оффлайн базу GeoIP...")
        try:
            req = urllib.request.Request(MMDB_URL, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=30) as response, open(MMDB_PATH, 'wb') as out_file:
                out_file.write(response.read())
            print("✅ База GeoIP загружена!")
        except Exception as e:
            print(f"⚠️ Ошибка GeoIP базы: {e}")

download_geoip_db()
GEO_READER = None
if maxminddb and os.path.exists(MMDB_PATH):
    try:
        GEO_READER = maxminddb.open_database(MMDB_PATH)
    except Exception:
        pass

def safe_b64decode(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s).decode('utf-8', errors='ignore')

def cc_to_flag(cc):
    if not cc or len(cc) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cc.upper())

def extract_clean_flag(text):
    if not text:
        return "🌐"
    flags = FLAG_REGEX.findall(text)
    return flags[0] if flags else "🌐"

def resolve_host_cached(clean_host):
    clean_host = clean_host.strip('[]').strip().lower()
    if not is_valid_public_host(clean_host):
        return None

    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[clean_host]

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        with DNS_LOCK:
            DNS_CACHE[clean_host] = clean_host
        return clean_host
    except ValueError:
        pass

    try:
        socket.setdefaulttimeout(2.0)
        ip = socket.gethostbyname(clean_host)
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_reserved or ip_obj.is_link_local or 
            ip_obj.is_unspecified):
            resolved_ip = None
        else:
            resolved_ip = ip
    except Exception:
        resolved_ip = None

    with DNS_LOCK:
        DNS_CACHE[clean_host] = resolved_ip
    return resolved_ip

def bulk_fetch_countries_online(ip_list):
    """ Пакетная выкачка геолокаций входных IP с обработкой лимита 429 """
    unique_ips = list(set([ip for ip in ip_list if ip and is_valid_public_host(ip)]))
    to_fetch = []
    with GEO_LOCK:
        for ip in unique_ips:
            if ip not in GEO_ONLINE_CACHE:
                to_fetch.append(ip)

    if not to_fetch:
        return

    print(f"🌐 Запрашиваем входную геолокацию для {len(to_fetch)} IP...")
    success_count = 0

    for i in range(0, len(to_fetch), 100):
        batch = to_fetch[i:i+100]
        retries = 3
        for attempt in range(retries):
            try:
                url = "http://ip-api.com/batch?fields=query,status,countryCode"
                data = json.dumps(batch).encode('utf-8')
                req = urllib.request.Request(
                    url, 
                    data=data, 
                    headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    res_list = json.loads(resp.read().decode('utf-8'))
                    with GEO_LOCK:
                        for item in res_list:
                            if isinstance(item, dict) and item.get('status') == 'success' and item.get('countryCode'):
                                GEO_ONLINE_CACHE[item['query']] = item['countryCode']
                                success_count += 1
                break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(4.0)
                else:
                    break
            except Exception:
                time.sleep(2.0)

        time.sleep(1.4)

    print(f"✅ Успешно получена геолокация для {success_count} из {len(to_fetch)} IP.")

def fetch_country_online(ip_str):
    with GEO_LOCK:
        if ip_str in GEO_ONLINE_CACHE:
            return GEO_ONLINE_CACHE[ip_str]

    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success' and data.get('countryCode'):
                cc = data['countryCode']
                with GEO_LOCK:
                    GEO_ONLINE_CACHE[ip_str] = cc
                return cc
    except Exception:
        pass

    return None

def is_cloudflare_or_warp(host):
    try:
        clean_host = host.strip('[]').lower()
        if not is_valid_public_host(clean_host):
            return True

        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
            return True

        ip_str = resolve_host_cached(clean_host)
        if not ip_str:
            return True

        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return True

        if ip_obj.version == 4:
            for network in CF_NETWORKS:
                if ip_obj in network:
                    return True
        elif ip_obj.version == 6:
            if str(ip_obj).startswith(("2400:cb00:", "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c0:", "2c0f:f248:")):
                return True
    except Exception:
        return True
    return False

def resolve_to_clean_ip(host):
    try:
        clean_host = host.strip('[]').lower()
        if is_cloudflare_or_warp(clean_host):
            return None
        ip = resolve_host_cached(clean_host)
        return ip if ip and not is_cloudflare_or_warp(ip) else None
    except Exception:
        return None

def get_real_ip_and_flag(host, orig_flag):
    try:
        clean_host = host.strip('[]').lower()
        ip_str = resolve_host_cached(clean_host)
        if ip_str:
            with GEO_LOCK:
                if ip_str in GEO_ONLINE_CACHE:
                    return cc_to_flag(GEO_ONLINE_CACHE[ip_str])

            online_cc = fetch_country_online(ip_str)
            if online_cc:
                return cc_to_flag(online_cc)

            if GEO_READER:
                record = GEO_READER.get(ip_str)
                if record and 'country' in record and 'iso_code' in record['country']:
                    return cc_to_flag(record['country']['iso_code'])
    except Exception:
        pass

    return orig_flag if orig_flag != "🌐" else "🌐"

def parse_host_port(server_part):
    if not server_part:
        return None, None
    server_part = server_part.rstrip('/')
    try:
        if server_part.startswith('['):
            if ']' in server_part:
                host_b, rest = server_part.split(']', 1)
                host = host_b + ']'
                port_str = rest.lstrip(':').split('/')[0].split('?')[0]
                return host, int(port_str)
        else:
            if ':' in server_part:
                host, port_str = server_part.rsplit(':', 1)
                port_str = port_str.split('/')[0].split('?')[0]
                return host, int(port_str)
    except Exception:
        pass
    return None, None

def parse_host_port_and_name(link):
    try:
        orig_name = ""
        if '#' in link:
            orig_name = urllib.parse.unquote(link.split('#', 1)[1])
        clean_link = link.split('#')[0]

        if clean_link.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            protocol, rest = clean_link.split('://', 1)
            rest = rest.split('?')[0]

            if protocol == 'ss':
                if '@' not in rest:
                    try:
                        decoded = safe_b64decode(rest)
                        if '@' in decoded:
                            _, host_port = decoded.split('@', 1)
                            host, port = parse_host_port(host_port)
                            return host, port, orig_name
                    except Exception:
                        pass
                else:
                    _, host_port = rest.split('@', 1)
                    host, port = parse_host_port(host_port)
                    return host, port, orig_name
            else:
                if '@' in rest:
                    rest = rest.split('@', 1)[1]
                host, port = parse_host_port(rest)
                return host, port, orig_name

        elif clean_link.startswith('vmess://'):
            b64_data = clean_link.replace('vmess://', '').strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            return data.get('add'), int(data.get('port')), data.get('ps', '')
    except Exception:
        pass
    return None, None, ""

def is_wl_by_keywords(link, orig_name=""):
    full_text = f"{link} {orig_name}"
    try:
        full_text = urllib.parse.unquote(full_text)
    except Exception:
        pass
    return bool(WL_KEYWORDS_REGEX.search(full_text))

def is_ru_sni(link):
    link_low = link.lower()
    if bool(re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link_low)):
        return True
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            if any(x.endswith(('.ru', '.su')) or '.ru:' in x for x in [data.get('sni', ''), data.get('host', ''), data.get('add', '')] if x):
                return True
        except Exception:
            pass
    else:
        host, _, _ = parse_host_port_and_name(link)
        if host and (host.lower().endswith(('.ru', '.su')) or '.ru]' in host.lower()):
            return True
    return False

def classify_config(link, white_ips, ru_sni_ratio=0.3):
    host, _, orig_name = parse_host_port_and_name(link)
    if not host or not is_valid_public_host(host):
        return 'BL'

    clean_host = host.strip('[]').lower()

    if clean_host in white_ips:
        return 'WL'

    resolved_ip = resolve_host_cached(clean_host)
    if resolved_ip and resolved_ip in white_ips:
        return 'WL'

    if is_wl_by_keywords(link, orig_name):
        return 'WL'

    clean_ip = resolve_to_clean_ip(host)
    if clean_ip:
        orig_flag = extract_clean_flag(orig_name)
        flag = get_real_ip_and_flag(clean_ip, orig_flag)
        if flag == "🇷🇺":
            return 'WL'

    if is_ru_sni(link):
        return 'WL' if random.random() < ru_sni_ratio else 'BL'

    return 'BL'

def link_to_xray_outbound(link):
    try:
        main_part = link.split('#')[0]
        if '://' not in main_part:
            return None
        protocol, rest = main_part.split('://', 1)
        protocol = protocol.lower()

        if protocol in ['hysteria2', 'hy2']:
            return None

        query_params = {}
        if '?' in rest:
            rest, query_part = rest.split('?', 1)
            query_params = urllib.parse.parse_qs(query_part)

        outbound = {"streamSettings": {}}

        if protocol == 'ss':
            if '@' not in rest:
                decoded = safe_b64decode(rest)
                if '@' in decoded:
                    user_info, host_port = decoded.split('@', 1)
                else:
                    return None
            else:
                user_info, host_port = rest.split('@', 1)
                if ':' not in user_info:
                    try:
                        user_info = safe_b64decode(user_info)
                    except Exception:
                        pass

            if ':' not in user_info:
                return None

            method, password = user_info.split(':', 1)
            host, port = parse_host_port(host_port)
            if not host or not port:
                return None

            outbound.update({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}
            })
        elif protocol in ['vless', 'trojan']:
            user_info, host_port = rest.split('@', 1) if '@' in rest else ("", rest)
            host, port = parse_host_port(host_port)
            if not host or not port:
                return None
            if protocol == 'vless':
                flow = query_params.get('flow', [''])[0]
                outbound.update({
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": user_info, "encryption": "none", "flow": flow}]}]}
                })
            elif protocol == 'trojan':
                outbound.update({
                    "protocol": "trojan",
                    "settings": {"servers": [{"address": host, "port": port, "password": user_info}]}
                })
        elif protocol == 'vmess':
            decoded = safe_b64decode(rest)
            data = json.loads(decoded)
            host, port = data.get('add'), int(data.get('port'))
            if not host or not port:
                return None
            outbound.update({
                "protocol": "vmess",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": data.get('id'), "alterId": int(data.get('aid', 0)), "security": "auto"}]}]}
            })
            query_params = {
                'security': [data.get('tls', '')],
                'sni': [data.get('sni', '') or data.get('host', '')],
                'type': [data.get('net', '')],
                'path': [data.get('path', '/')],
                'host': [data.get('host', '')],
                'alpn': [data.get('alpn', '')]
            }
        else:
            return None

        security = query_params.get('security', [''])[0].lower()
        if protocol == 'trojan' and not security:
            security = 'tls'

        if security in ['tls', 'reality']:
            outbound["streamSettings"]["security"] = security
            sni = query_params.get('sni', [''])[0] or query_params.get('host', [''])[0]
            alpn_raw = query_params.get('alpn', [''])[0]
            alpn_list = [a.strip() for a in alpn_raw.split(',') if a.strip()] if alpn_raw else []

            if security == 'tls':
                tls_obj = {"serverName": sni}
                if alpn_list:
                    tls_obj["alpn"] = alpn_list
                outbound["streamSettings"]["tlsSettings"] = tls_obj
            elif security == 'reality':
                reality_obj = {
                    "serverName": sni,
                    "publicKey": query_params.get('pbk', [''])[0],
                    "shortId": query_params.get('sid', [''])[0],
                    "fingerprint": query_params.get('fp', ['chrome'])[0]
                }
                spx = query_params.get('spx', [''])[0]
                if spx:
                    reality_obj["spiderX"] = spx
                outbound["streamSettings"]["realitySettings"] = reality_obj

        net = query_params.get('type', [''])[0] or query_params.get('net', [''])[0]
        if net:
            net = net.lower()
            outbound["streamSettings"]["network"] = net
            path_val = query_params.get('path', ['/'])[0]
            host_val = query_params.get('host', [''])[0]
            header_type = query_params.get('headerType', ['none'])[0]

            if net == 'ws':
                outbound["streamSettings"]["wsSettings"] = {"path": path_val, "headers": {"Host": host_val} if host_val else {}}
            elif net == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {"serviceName": query_params.get('serviceName', [''])[0] or path_val.lstrip('/')}
            elif net in ['xhttp', 'splithttp']:
                outbound["streamSettings"]["xhttpSettings"] = {"path": path_val, "host": host_val, "mode": query_params.get('mode', ['auto'])[0]}
            elif net == 'httpupgrade':
                outbound["streamSettings"]["httpupgradeSettings"] = {"path": path_val, "host": host_val}
            elif net in ['http', 'h2']:
                outbound["streamSettings"]["httpSettings"] = {"path": path_val, "host": [host_val] if host_val else []}
            elif net in ['kcp', 'mkcp']:
                outbound["streamSettings"]["kcpSettings"] = {"header": {"type": header_type}}

        return outbound
    except Exception:
        return None

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_port(port, timeout=0.6):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.05):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.01)
    return False

def get_xray_cmd():
    exe = "xray.exe" if os.name == 'nt' else "./xray"
    if not os.path.exists(exe):
        exe = "xray"
    return [exe, "run", "-c", "stdin:"]

def check_via_xray_detailed(outbound_obj, timeout=6.0):
    port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound_obj]
    }

    proc = None
    try:
        cmd = get_xray_cmd()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.stdin.write(json.dumps(config).encode('utf-8'))
        proc.stdin.flush()
        proc.stdin.close()

        if not wait_for_port(port):
            return False, None, "Локальный Xray не запустился"

        proxy_handler = urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'})
        opener = urllib.request.build_opener(proxy_handler)

        req_exit_geo = urllib.request.Request("http://ip-api.com/json/?fields=status,countryCode", headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with opener.open(req_exit_geo, timeout=timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode('utf-8'))
                    if data.get('status') == 'success' and data.get('countryCode'):
                        return True, cc_to_flag(data['countryCode']), "OK"
        except Exception:
            pass

        req_204 = urllib.request.Request("https://www.gstatic.com/generate_204", headers={'User-Agent': 'Mozilla/5.0'})
        with opener.open(req_204, timeout=timeout) as resp:
            if resp.status in [200, 204]:
                return True, None, "OK"
            return False, None, f"HTTP Статус {resp.status}"

    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            return False, None, f"Таймаут подключения ({timeout}s)"
        return False, None, f"Ошибка сети: {e.reason}"
    except Exception as e:
        return False, None, f"Ошибка: {str(e)}"
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=0.3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

def check_proxy_alive_detailed(link):
    host, port, orig_name = parse_host_port_and_name(link)
    if not host or not port or not is_valid_public_host(host):
        return False, None, "Некорректный формат хоста/порта"

    if is_cloudflare_or_warp(host):
        return False, None, "Отфильтрован (Cloudflare/WARP)"

    if link.startswith(('hysteria2://', 'hy2://')):
        return False, None, "Hysteria2 не поддерживается стандартным Xray-core"

    outbound = link_to_xray_outbound(link)
    if not outbound:
        return False, None, "Ошибка генерации JSON для Xray"

    is_ok, exit_flag, reason = check_via_xray_detailed(outbound, timeout=6.0)
    if is_ok:
        if exit_flag:
            final_flag = exit_flag
        else:
            orig_flag = extract_clean_flag(orig_name)
            final_flag = get_real_ip_and_flag(host, orig_flag)
        return True, (link, final_flag), "OK"
    return False, None, reason

def fetch_single_url(url):
    try:
        url = url.strip().replace(' ', '%20')
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            raw_data = response.read()
            try:
                content = raw_data.decode('utf-8', errors='ignore')
            except Exception:
                content = raw_data.decode('latin-1', errors='ignore')

            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    decoded = safe_b64decode(content)
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                except Exception:
                    pass
            return [l.strip() for l in content.splitlines() if l.strip()]
    except Exception:
        return []

def fetch_links_parallel_with_source(url_file):
    links_with_source = []
    urls = []
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        print(f"🔗 Загружаем источники из файла {url_file} (всего источников: {len(urls)})...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures):
                source_url = futures[future]
                configs = future.result()
                links_with_source.extend([(config, source_url) for config in configs])
                
        print(f"✅ Из файла {url_file} выкачано всего: {len(links_with_source)} конфигов")
    except FileNotFoundError:
        print(f"⚠️ Файл {url_file} не найден!")
    except Exception as e:
        print(f"⚠️ Ошибка чтения {url_file}: {e}")
    return links_with_source

def process_incoming_queue():
    incoming_proxies = []
    incoming_raw_ips = []
    if os.path.exists(INCOMING_FILE):
        try:
            with open(INCOMING_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

            unique_lines = list(dict.fromkeys(lines))[:MAX_QUEUE_LIMIT]

            for item in unique_lines:
                try:
                    ip_obj = ipaddress.ip_address(item)
                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                        if not is_cloudflare_or_warp(str(ip_obj)):
                            incoming_raw_ips.append(str(ip_obj))
                except ValueError:
                    if item.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
                        incoming_proxies.append(item)

            print(f"📥 Из очереди забрано: {len(incoming_proxies)} прокси-ссылок и {len(incoming_raw_ips)} чистых IP.")
        except Exception as e:
            print(f"⚠️ Ошибка чтения очереди {INCOMING_FILE}: {e}")
    return incoming_proxies, incoming_raw_ips

def clean_and_dedup(tagged_items):
    seen_strings = set()
    seen_keys = set()
    valid_items = []

    for link, source_tag in tagged_items:
        link = link.strip()
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            continue

        if link in seen_strings:
            continue
        seen_strings.add(link)

        host, port, _ = parse_host_port_and_name(link)
        if not host or not port or not is_valid_public_host(host):
            continue

        if not (1 <= port <= 65535):
            continue

        protocol = link.split('://')[0].lower()
        key = (protocol, host.lower().strip('[]'), str(port))

        if key in seen_keys:
            continue
        seen_keys.add(key)

        valid_items.append((link, source_tag))

    return valid_items

def rename_config(link, index, tag, detected_flag):
    new_name = f"{detected_flag} {tag} Сервер {index}"
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            data['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode('utf-8')}"
        except Exception:
            pass
    if "://" in link:
        main_part = link.split('#', 1)[0]
        return f"{main_part}#{urllib.parse.quote(new_name)}"
    return link

def extract_sni_from_link(link):
    try:
        if '?' in link:
            query_part = link.split('?', 1)[1].split('#')[0]
            params = urllib.parse.parse_qs(query_part)
            sni = params.get('sni', [''])[0] or params.get('host', [''])[0]
            if sni:
                return sni.lower().strip()
        if link.startswith("vmess://"):
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            return (data.get('sni') or data.get('host') or '').lower().strip()
    except Exception:
        pass
    return ""

def dedup_advanced(config_list, list_name=""):
    seen_keys = set()
    result = []
    
    for link in config_list:
        host, port, _ = parse_host_port_and_name(link)
        if not host or not port or not is_valid_public_host(host):
            continue
        
        clean_ip = resolve_to_clean_ip(host) or host.strip('[]').lower()
        protocol = link.split('://')[0].lower() if '://' in link else ''
        sni = extract_sni_from_link(link)
        
        key = (clean_ip, str(port), protocol, sni)
        
        if key not in seen_keys:
            seen_keys.add(key)
            result.append(link)
            
    removed = len(config_list) - len(result)
    print(f"🔍 Дедупликация {list_name}: было {len(config_list)}, осталось {len(result)} (выкинуто дубликатов: {removed})")
    return result

def find_matched_ip(host, white_ips):
    if not host or not is_valid_public_host(host):
        return None
    clean_host = host.strip('[]').lower()
    if clean_host in white_ips:
        return clean_host
    resolved_ip = resolve_host_cached(clean_host)
    if resolved_ip and resolved_ip in white_ips:
        return resolved_ip
    return None

def update_trace_status(trace_data, link, matched_ip, status, reason):
    if not matched_ip or matched_ip not in trace_data:
        return
    with TRACE_LOCK:
        for item in trace_data[matched_ip]:
            if item['link'] == link:
                item['status'] = status
                item['xray_reason'] = reason

def main():
    print("🚀 Старт продвинутого Xray-парсера...")
    wl_file = 'sources_wl.txt' if os.path.exists('sources_wl.txt') else 'source_wl.txt'
    bl_file = 'sources_bl.txt' if os.path.exists('sources_bl.txt') else 'source_bl.txt'

    wl_fetched_with_source = fetch_links_parallel_with_source(wl_file)
    bl_fetched_with_source = fetch_links_parallel_with_source(bl_file)

    incoming_proxies, incoming_raw_ips = process_incoming_queue()

    # --- СБОР И ГАРАНТИРОВАННОЕ СОХРАНЕНИЕ WHITE IP В БАЗУ ---
    white_ips = set()
    if os.path.exists(WHITE_IP_FILE):
        with open(WHITE_IP_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ip_obj = ipaddress.ip_address(line)
                        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                            white_ips.add(str(ip_obj))
                    except ValueError:
                        pass

    white_ips.update(incoming_raw_ips)

    def ip_sort_key(ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError:
            return ip

    with open(WHITE_IP_FILE, 'w', encoding='utf-8') as f:
        for ip in sorted(list(white_ips), key=ip_sort_key):
            f.write(f"{ip}\n")
    
    print(f"💾 База {WHITE_IP_FILE} полностью сохранена. Всего IP в базе: {len(white_ips)}")

    trace_data = {target_ip: [] for target_ip in white_ips}

    tagged_items = []
    for link in [l for l, _ in wl_fetched_with_source]:
        tagged_items.append((link, 'WL'))
    for link in [l for l, _ in bl_fetched_with_source]:
        tagged_items.append((link, 'BL'))
    for link in incoming_proxies:
        tagged_items.append((link, 'BL'))

    clean_items = clean_and_dedup(tagged_items)

    all_ips = []
    for link, _ in clean_items:
        host, _, _ = parse_host_port_and_name(link)
        if host:
            clean_ip = resolve_to_clean_ip(host) or resolve_host_cached(host.strip('[]').lower())
            if clean_ip:
                all_ips.append(clean_ip)
    
    bulk_fetch_countries_online(all_ips)

    ping_wl = []
    ping_bl = []
    alive_wl_data = []
    alive_bl_data = []

    for link, _ in clean_items:
        host, port, orig_name = parse_host_port_and_name(link)
        if not host:
            continue

        matched_ip = find_matched_ip(host, white_ips)

        if matched_ip:
            orig_flag = extract_clean_flag(orig_name)
            final_flag = get_real_ip_and_flag(host, orig_flag)
            alive_wl_data.append((link, final_flag))

            protocol = link.split('://')[0] if '://' in link else 'unk'
            trace_data[matched_ip].append({
                'link': link,
                'port': port,
                'protocol': protocol,
                'target_list': 'WL',
                'status': 'ЖИВОЙ_БЕЗ_ТЕСТА',
                'xray_reason': 'Прямой пропуск (IP в white_ip.txt)'
            })
            continue

        if is_wl_by_keywords(link, orig_name):
            orig_flag = extract_clean_flag(orig_name)
            final_flag = get_real_ip_and_flag(host, orig_flag)
            alive_wl_data.append((link, final_flag))
            continue

        target_list = classify_config(link, white_ips, ru_sni_ratio=0.3)
        if target_list == 'WL':
            ping_wl.append(link)
        else:
            ping_bl.append(link)

    print(f"⚡️ Пропущено напрямую в WL (белый IP / ключевые слова): {len(alive_wl_data)} конфигов.")
    print(f"⚡️ Отправлено на Xray-тестирование: {len(ping_wl)} в WL и {len(ping_bl)} в BL.")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        wl_futures = {executor.submit(check_proxy_alive_detailed, link): link for link in ping_wl}
        for future in as_completed(wl_futures):
            is_ok, res, reason = future.result()
            link = wl_futures[future]
            
            host, _, _ = parse_host_port_and_name(link)
            matched_ip = find_matched_ip(host, white_ips)
            update_trace_status(trace_data, link, matched_ip, 'ЖИВОЙ' if is_ok else 'МЕРТВ_XRAY', reason)

            if is_ok:
                alive_wl_data.append(res)

        bl_futures = {executor.submit(check_proxy_alive_detailed, link): link for link in ping_bl}
        for future in as_completed(bl_futures):
            is_ok, res, reason = future.result()
            link = bl_futures[future]
            
            host, _, _ = parse_host_port_and_name(link)
            matched_ip = find_matched_ip(host, white_ips)
            update_trace_status(trace_data, link, matched_ip, 'ЖИВОЙ' if is_ok else 'МЕРТВ_XRAY', reason)

            if is_ok:
                alive_bl_data.append(res)
    
    print(f"✅ Всего итоговых конфигов: {len(alive_wl_data)} WL, {len(alive_bl_data)} BL")

    final_wl = [rename_config(item[0], idx, "[WL]", item[1]) for idx, item in enumerate(alive_wl_data, 1)]
    final_bl = [rename_config(item[0], idx, "[BL]", item[1]) for idx, item in enumerate(alive_bl_data, 1)]
    final_full = final_wl + final_bl

    final_wl = dedup_advanced(final_wl, "WL")
    final_bl = dedup_advanced(final_bl, "BL")
    final_full = dedup_advanced(final_full, "FULL")

    print("\n" + "="*70)
    print("🔍 ПОЛНАЯ ТРАССИРОВКА АДРЕСОВ ИЗ WHITE_IP.TXT")
    print("="*70)

    for target_ip, entries in trace_data.items():
        print(f"\n📌 IP: {target_ip}")
        if not entries:
            print("   ❌ ССЫЛОК НЕ НАЙДЕНО: Ни один из выкачанных источников не содержит данный IP или домен.")
            continue

        print(f"   найдено кандидатов: {len(entries)}")
        for idx, entry in enumerate(entries, 1):
            proto_info = f"Протокол: {entry['protocol']} | Порт: {entry['port']}"
            if entry['status'] == 'ЖИВОЙ_БЕЗ_ТЕСТА':
                print(f"   🟢 #{idx} [{proto_info}] -> УСПЕШНО ДОБАВЛЕН БЕЗ ТЕСТА (Входит в white_ip.txt)")
            elif entry['status'] == 'ЖИВОЙ':
                print(f"   🟢 #{idx} [{proto_info}] -> Успешно прошел Xray HTTP-тест (список {entry['target_list']})")
            else:
                print(f"   🔴 #{idx} [{proto_info}] -> Отклонен Xray: {entry['xray_reason']}")

    print("\n" + "="*70 + "\n")

    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8'))
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8'))
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8'))

    if GEO_READER:
        GEO_READER.close()
    print("✨ Все готово! Результаты обновлены.")

if __name__ == '__main__':
    main()
