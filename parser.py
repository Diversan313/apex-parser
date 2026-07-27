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
MAX_WHITE_IPS = 30000         # Максимум IP в итоговом white_ip.txt
MAX_WORKERS = 15              # Ограничение потоков

# --- БЕЗОПАСНЫЙ КЭШ DNS С БЛОКИРОВКОЙ ПОТОКОВ ---
DNS_CACHE = {}
DNS_LOCK = threading.Lock()

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

def download_geoip_db():
    if not os.path.exists(MMDB_PATH):
        print("📥 Скачиваю базу GeoIP...")
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
    with DNS_LOCK:
        if clean_host in DNS_CACHE:
            return DNS_CACHE[clean_host]

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host) or ':' in clean_host:
        with DNS_LOCK:
            DNS_CACHE[clean_host] = clean_host
        return clean_host

    try:
        socket.setdefaulttimeout(2.0)
        ip = socket.gethostbyname(clean_host)
        with DNS_LOCK:
            DNS_CACHE[clean_host] = ip
        return ip
    except Exception:
        with DNS_LOCK:
            DNS_CACHE[clean_host] = None
        return None

def is_cloudflare_or_warp(host):
    try:
        clean_host = host.strip('[]').lower()
        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
            return True

        ip_str = resolve_host_cached(clean_host)
        if not ip_str:
            return True

        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            for network in CF_NETWORKS:
                if ip_obj in network:
                    return True
        elif ip_obj.version == 6:
            if str(ip_obj).startswith(("2400:cb00:", "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c0:", "2c0f:f248:")):
                return True
    except Exception:
        pass
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
    if not GEO_READER:
        return orig_flag
    try:
        clean_host = host.strip('[]').lower()
        ip_str = resolve_host_cached(clean_host)
        if ip_str:
            record = GEO_READER.get(ip_str)
            if record and 'country' in record and 'iso_code' in record['country']:
                return cc_to_flag(record['country']['iso_code'])
    except Exception:
        pass
    return orig_flag

def parse_host_port(server_part):
    if not server_part:
        return None, None
    server_part = server_part.rstrip('/')
    try:
        if server_part.startswith('['):
            if ']' in server_part:
                host_b, rest = server_part.split(']', 1)
                host = host_b + ']'
                port_str = rest.lstrip(':').split('/')[0]
                return host, int(port_str)
        else:
            if ':' in server_part:
                host, port_str = server_part.rsplit(':', 1)
                port_str = port_str.split('/')[0]
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
    if not host:
        return 'BL'

    clean_host = host.strip('[]').lower()

    if clean_host in white_ips:
        return 'WL'

    resolved_ip = resolve_host_cached(clean_host)
    if resolved_ip and resolved_ip in white_ips:
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
                    method, password = user_info.split(':', 1)
                else:
                    return None
            else:
                user_info, host_port = rest.split('@', 1)
                try:
                    decoded = safe_b64decode(user_info)
                    if ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        method, password = user_info.split(':', 1)
                except Exception:
                    if ':' in user_info:
                        method, password = user_info.split(':', 1)
                    else:
                        return None
            host, port = parse_host_port(host_port)
            if not host or not port:
                return None
            outbound.update({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}
            })
        elif protocol in ['vless', 'trojan', 'hysteria2', 'hy2']:
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
            elif protocol in ['hysteria2', 'hy2']:
                outbound.update({
                    "protocol": "hysteria2",
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
        if protocol in ['trojan', 'hysteria2', 'hy2'] and not security:
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

# ТАЙМАУТ УВЕЛИЧЕН ДО 6.0 секунд
def check_via_xray(outbound_obj, timeout=6.0):
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
            return False

        proxy_handler = urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request("https://www.gstatic.com/generate_204", headers={'User-Agent': 'Mozilla/5.0'})

        with opener.open(req, timeout=timeout) as resp:
            if resp.status in [200, 204]:
                return True
    except Exception:
        pass
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
    return False

def check_proxy_alive(link):
    host, port, orig_name = parse_host_port_and_name(link)
    if not host or not port:
        return None

    if is_cloudflare_or_warp(host):
        return None

    outbound = link_to_xray_outbound(link)
    if outbound and check_via_xray(outbound, timeout=6.0):
        orig_flag = extract_clean_flag(orig_name)
        final_flag = get_real_ip_and_flag(host, orig_flag)
        return (link, final_flag)
    return None

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

def fetch_links_parallel(url_file):
    links = []
    urls = []
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        print(f"🔗 Загружаем источники из файла {url_file} (всего урлов: {len(urls)})...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures):
                links.extend(future.result())
        print(f"✅ Из файла {url_file} выкачано конфигов: {len(links)}")
    except FileNotFoundError:
        print(f"⚠️ Файл {url_file} не найден!")
    except Exception as e:
        print(f"⚠️ Ошибка чтения {url_file}: {e}")
    return links

def process_incoming_queue():
    incoming_proxies = []
    incoming_raw_ips = []
    if os.path.exists(INCOMING_FILE):
        try:
            with open(INCOMING_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

            unique_lines = list(dict.fromkeys(lines))[:MAX_QUEUE_LIMIT]

            for item in unique_lines:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', item):
                    if not is_cloudflare_or_warp(item):
                        incoming_raw_ips.append(item)
                elif item.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
                    incoming_proxies.append(item)

            open(INCOMING_FILE, 'w', encoding='utf-8').close()
            print(f"📥 Из очереди забрано: {len(incoming_proxies)} прокси-ссылок и {len(incoming_raw_ips)} чистых IP.")
        except Exception as e:
            print(f"⚠️ Ошибка чтения очереди {INCOMING_FILE}: {e}")
    return incoming_proxies, incoming_raw_ips

def save_white_ips(white_ips):
    # Теперь IP НИКОГДА не удаляются из файла. Они только пополняются.
    limited_white_ips = sorted(list(white_ips))[:MAX_WHITE_IPS]
    with open(WHITE_IP_FILE, 'w', encoding='utf-8') as f:
        if limited_white_ips:
            f.write('\n'.join(limited_white_ips) + '\n')
    print(f"🛡 Актуальный размер white_ip.txt: {len(limited_white_ips)} IP адресов (без удалений).")

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
        if not host or not port:
            continue

        protocol = link.split('://')[0].lower()
        key = (protocol, host.lower().strip(), str(port))

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

def main():
    print("🚀 Старт продвинутого Xray-парсера...")
    wl_file = 'sources_wl.txt' if os.path.exists('sources_wl.txt') else 'source_wl.txt'
    bl_file = 'sources_bl.txt' if os.path.exists('sources_bl.txt') else 'source_bl.txt'

    wl_fetched = fetch_links_parallel(wl_file)
    bl_fetched = fetch_links_parallel(bl_file)

    incoming_proxies, incoming_raw_ips = process_incoming_queue()

    tagged_items = []
    for link in wl_fetched:
        tagged_items.append((link, 'WL'))
    for link in bl_fetched:
        tagged_items.append((link, 'BL'))
    for link in incoming_proxies:
        tagged_items.append((link, 'BL'))

    clean_items = clean_and_dedup(tagged_items)

    # 1. ЧИТАЕМ WHITE IPs. ОНИ ТЕПЕРЬ ПОСТОЯННЫ.
    white_ips = set()
    if os.path.exists(WHITE_IP_FILE):
        with open(WHITE_IP_FILE, 'r', encoding='utf-8') as f:
            white_ips = {line.strip() for line in f if line.strip() and not line.strip().startswith('#')}
    white_ips.update(incoming_raw_ips)

    trusted_white_data = [] # Идут в финал БЕЗ пинга (спасенные из white_ip.txt)
    ping_wl = []            # WL, которые нужно пинговать (всё содержимое sources_wl)
    ping_bl = []            # Обычный BL на пинг

    for link, source_tag in clean_items:
        host, port, orig_name = parse_host_port_and_name(link)
        if not host:
            continue
            
        clean_host = host.strip('[]').lower()
        resolved_ip = resolve_host_cached(clean_host)
        orig_flag = extract_clean_flag(orig_name)

        # Проверка: есть ли этот сервер в наших сохраненных White IP
        is_white_ip = (clean_host in white_ips) or (resolved_ip and resolved_ip in white_ips)

        # 2. ГЛАВНОЕ ПРАВИЛО: Если конфиг есть в white_ip.txt - БЕРЕМ БЕЗ ПИНГА
        if is_white_ip:
            final_flag = get_real_ip_and_flag(host, orig_flag)
            trusted_white_data.append((link, final_flag))
        else:
            # Если конфига нет в white_ip.txt, он ИДЕТ НА ТЕСТ, даже если он из WL
            if source_tag == 'WL':
                ping_wl.append(link)
            else:
                target_list = classify_config(link, white_ips, ru_sni_ratio=0.3)
                if target_list == 'WL':
                    ping_wl.append(link)
                else:
                    ping_bl.append(link)

    print(f"⚡️ Итого серверов: {len(trusted_white_data)} ДОВЕРЕННЫХ (из white_ip.txt, без пинга), {len(ping_wl)} на пинг(WL) и {len(ping_bl)} на пинг(BL).")
    print(f"⚡️ HTTP-тестирование через Xray (в {MAX_WORKERS} потоков)...")
    
    alive_wl_data = []
    alive_bl_data = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        wl_futures = [executor.submit(check_proxy_alive, link) for link in ping_wl]
        for future in as_completed(wl_futures):
            res = future.result()
            if res:
                alive_wl_data.append(res)

        bl_futures = [executor.submit(check_proxy_alive, link) for link in ping_bl]
        for future in as_completed(bl_futures):
            res = future.result()
            if res:
                alive_bl_data.append(res)

    # Сохраняем White IPs навсегда (добавляем новые живые IP ТОЛЬКО из Белого списка)
    for link, flag in (trusted_white_data + alive_wl_data):
        host, _, _ = parse_host_port_and_name(link)
        if host:
            clean_ip = resolve_to_clean_ip(host)
            if clean_ip:
                white_ips.add(clean_ip)
                
    save_white_ips(white_ips)

    # Объединяем спасенные из white_ip и те, что выжили после теста из WL
    final_wl_raw = trusted_white_data + alive_wl_data

    final_wl = [rename_config(item[0], idx, "[WL]", item[1]) for idx, item in enumerate(final_wl_raw, 1)]
    final_bl = [rename_config(item[0], idx, "[BL]", item[1]) for idx, item in enumerate(alive_bl_data, 1)]
    final_full = final_wl + final_bl

    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8'))
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8'))
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8'))

    if GEO_READER:
        GEO_READER.close()
    print("✨ Все готово! Результаты и базы обновлены.")

if __name__ == '__main__':
    main()
