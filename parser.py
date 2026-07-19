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
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import maxminddb
except ImportError:
    maxminddb = None

FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MMDB_PATH = "GeoLite2-Country.mmdb"

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
            req = urllib.request.Request(MMDB_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response, open(MMDB_PATH, 'wb') as out_file:
                out_file.write(response.read())
            print("✅ База GeoIP загружена!")
        except Exception as e:
            print(f"⚠️ Ошибка GeoIP базы: {e}")

download_geoip_db()
GEO_READER = None
if maxminddb and os.path.exists(MMDB_PATH):
    try: GEO_READER = maxminddb.open_database(MMDB_PATH)
    except: pass

def cc_to_flag(cc):
    if not cc or len(cc) != 2: return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cc.upper())

def extract_clean_flag(text):
    if not text: return "🌐"
    flags = FLAG_REGEX.findall(text)
    return flags[0] if flags else "🌐"

def is_cloudflare_or_warp(host):
    """Жесткий пре-фильтр Cloudflare, WARP и мусорных пулов"""
    try:
        clean_host = host.strip('[]').lower()
        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
            return True
        
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host) and not ':' in clean_host:
            socket.setdefaulttimeout(1.5)
            ip_str = socket.gethostbyname(clean_host)
        else:
            ip_str = clean_host

        # Тотальный бан пулов ВАРПа и Клауда по началу строки
        if ip_str.startswith(('104.', '162.', '172.', '8.39.', '8.35.', '188.114.')):
            return True

        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            for network in CF_NETWORKS:
                if ip_obj in network: return True
        elif ip_obj.version == 6:
            if str(ip_obj).startswith(("2400:cb00:", "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c0:", "2c0f:f248:")):
                return True
    except:
        pass
    return False

def get_real_ip_and_flag(host, orig_flag):
    if not GEO_READER: return orig_flag
    try:
        clean_host = host.strip('[]').lower()
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host) and not ':' in clean_host:
            socket.setdefaulttimeout(1.5)
            ip_str = socket.gethostbyname(clean_host)
        else:
            ip_str = clean_host
        record = GEO_READER.get(ip_str)
        if record and 'country' in record and 'iso_code' in record['country']:
            return cc_to_flag(record['country']['iso_code'])
    except: pass
    return orig_flag

def parse_host_port_and_name(link):
    try:
        orig_name = ""
        if '#' in link: orig_name = urllib.parse.unquote(link.split('#')[1])
        clean_link = link.split('#')[0]
        if clean_link.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            content = clean_link.split('://')[1]
            server_part = content.split('?')[0]
            if '@' in server_part: server_part = server_part.split('@')[1]
            if server_part.startswith('['):
                host = server_part.split(']')[0] + ']'
                port = server_part.split(']:')[1]
            else:
                host, port = server_part.split(':')
            return host, int(port), orig_name
        elif clean_link.startswith('vmess://'):
            b64_data = clean_link.replace('vmess://', '').strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            return data.get('add'), int(data.get('port')), data.get('ps', '')
    except: pass
    return None, None, ""

def link_to_xray_outbound(link):
    """Умная конвертация ссылки подписки в JSON-объект outbound для Xray"""
    try:
        main_part = link.split('#')[0]
        protocol, rest = main_part.split('://', 1)
        query_params = {}
        if '?' in rest:
            rest, query_part = rest.split('?', 1)
            query_params = urllib.parse.parse_qs(query_part)
            
        user_info, host_port = rest.split('@', 1) if '@' in rest else ("", rest)
        if host_port.startswith('['):
            host = host_port.split(']')[0] + ']'
            port = int(host_port.split(']:')[1])
        else:
            host, port = host_port.split(':')
            port = int(port)

        outbound = {"streamSettings": {}}
        
        if protocol == 'vless':
            outbound.update({
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": user_info, "encryption": "none", "flow": query_params.get('flow', [''])[0]}]}]}
            })
        elif protocol == 'trojan':
            outbound.update({
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": user_info}]}
            })
        elif protocol == 'ss':
            try:
                decoded = base64.b64decode(user_info + "=" * ((4 - len(user_info) % 4) % 4)).decode('utf-8')
                method, password = decoded.split(':', 1)
            except:
                if ':' in user_info: method, password = user_info.split(':', 1)
                else: return None
            outbound.update({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}
            })
        elif protocol in ['hysteria2', 'hy2']:
            outbound.update({
                "protocol": "hysteria2",
                "settings": {"servers": [{"address": host, "port": port, "password": user_info}]}
            })
        elif protocol == 'vmess':
            b64_data = rest.strip() + "=" * ((4 - len(rest.strip()) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            host, port = data.get('add'), int(data.get('port'))
            outbound.update({
                "protocol": "vmess",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": data.get('id'), "alterId": int(data.get('aid', 0)), "security": "auto"}]}]}
            })
            query_params = {
                'security': [data.get('tls', '')],
                'sni': [data.get('sni', '') or data.get('host', '')],
                'type': [data.get('net', '')],
                'path': [data.get('path', '/')],
                'host': [data.get('host', '')]
            }
        else:
            return None

        # Обработка TLS / Reality
        security = query_params.get('security', [''])[0]
        if protocol == 'trojan' and not security: security = 'tls'
        if security in ['tls', 'reality']:
            outbound["streamSettings"]["security"] = security
            if security == 'tls':
                outbound["streamSettings"]["tlsSettings"] = {"serverName": query_params.get('sni', [''])[0]}
            elif security == 'reality':
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": query_params.get('sni', [''])[0],
                    "publicKey": query_params.get('pbk', [''])[0],
                    "shortId": query_params.get('sid', [''])[0],
                    "fingerprint": query_params.get('fp', ['chrome'])[0]
                }

        # Обработка транспортов (WS / gRPC)
        net = query_params.get('type', [''])[0]
        if net in ['ws', 'grpc']:
            outbound["streamSettings"]["network"] = net
            if net == 'ws':
                outbound["streamSettings"]["wsSettings"] = {"path": query_params.get('path', ['/'])[0], "headers": {"Host": query_params.get('host', [''])[0]}}
            elif net == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {"serviceName": query_params.get('serviceName', [''])[0] or query_params.get('path', [''])[0]}

        return outbound
    except:
        return None

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def check_via_xray(outbound_obj, timeout=3.5):
    """Запускает изолированный процесс Xray и прогоняет честный HTTP запрос"""
    port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound_obj]
    }
    
    cfg_name = f"tmp_{port}.json"
    with open(cfg_name, 'w') as f: json.dump(config, f)
        
    proc = None
    try:
        cmd = ["./xray", "-c", cfg_name] if os.name != 'nt' else ["xray.exe", "-c", cfg_name]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.35) # Даем ядру подняться
        
        proxy_handler = urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request("http://cp.cloudflare.com/generate_204", headers={'User-Agent': 'Mozilla/5.0'})
        
        with opener.open(req, timeout=timeout) as resp:
            if resp.status in [200, 204]: return True
    except: pass
    finally:
        if proc:
            try: proc.terminate(); proc.wait(timeout=0.5)
            except:
                try: proc.kill()
                except: pass
        if os.path.exists(cfg_name):
            try: os.remove(cfg_name)
            except: pass
    return False

def get_config_identity(link):
    try:
        protocol = link.split('://')[0].lower()
        host, port, _ = parse_host_port_and_name(link)
        if not host: return None
        return (protocol, host.lower().strip(), str(port))
    except: return None

def check_proxy_alive(link):
    host, port, orig_name = parse_host_port_and_name(link)
    if not host or not port: return None
    
    # Шаг 1: Тотальный блок подсетей Cloudflare/WARP
    if is_cloudflare_or_warp(host): return None
        
    # Шаг 2: Честный HTTP-тест через ядро Xray
    outbound = link_to_xray_outbound(link)
    if outbound and check_via_xray(outbound):
        orig_flag = extract_clean_flag(orig_name)
        final_flag = get_real_ip_and_flag(host, orig_flag)
        return (link, final_flag)
    return None

def fetch_single_url(url):
    try:
        url = url.strip().replace(' ', '%20')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            raw_data = response.read()
            try: content = raw_data.decode('utf-8', errors='ignore')
            except: content = raw_data.decode('latin-1', errors='ignore')
            
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    clean_str = "".join(content.split()).replace('-', '+').replace('_', '/')
                    clean_str += "=" * ((4 - len(clean_str) % 4) % 4)
                    decoded = base64.b64decode(clean_str).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                except: pass
            return [l.strip() for l in content.split('\n') if l.strip()]
    except: return []

def fetch_links_parallel(url_file):
    links = []
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures): links.extend(future.result())
    except FileNotFoundError: pass
    return links

def is_ru_sni(link):
    link_low = link.lower()
    if bool(re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link_low)): return True
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            if any(x.endswith(('.ru', '.su')) or '.ru:' in x for x in [data.get('sni',''), data.get('host',''), data.get('add','')] if x): return True
        except: pass
    else:
        host, _, _ = parse_host_port_and_name(link)
        if host and (host.lower().endswith(('.ru', '.su')) or '.ru]' in host.lower()): return True
    return False

def clean_and_dedup(links):
    unique_identities = set()
    valid_links = []
    for link in links:
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')): continue
        identity = get_config_identity(link)
        if identity and identity not in unique_identities:
            unique_identities.add(identity)
            valid_links.append(link)
    return valid_links

def rename_config(link, index, tag, detected_flag):
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip() + "=" * ((4 - len(link.replace("vmess://", "").strip()) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            data['ps'] = f"{detected_flag} {tag} Сервер {index}"
            return f"vmess://{base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')}"
        except: return link
    if "://" in link:
        try:
            main_part = link.split('#', 1)[0]
            return f"{main_part}#{urllib.parse.quote(f'{detected_flag} {tag} Сервер {index}')}"
        except: return link
    return link

def main():
    print("🚀 Старт продвинутого Xray-парсера...")
    wl_file = 'sources_wl.txt' if os.path.exists('sources_wl.txt') else 'source_wl.txt'
    bl_file = 'sources_bl.txt' if os.path.exists('sources_bl.txt') else 'source_bl.txt'

    wl_clean = clean_and_dedup(fetch_links_parallel(wl_file))
    bl_clean = clean_and_dedup(fetch_links_parallel(bl_file))

    real_wl, real_bl = list(wl_clean), []
    wl_identities = {get_config_identity(l) for l in real_wl if get_config_identity(l)}

    for link in bl_clean:
        identity = get_config_identity(link)
        if identity in wl_identities: continue
        if is_ru_sni(link):
            real_wl.append(link)
            if identity: wl_identities.add(identity)
        else:
            real_bl.append(link)

    print(f"⚡️ HTTP-тестирование через Xray: {len(real_wl)} WL и {len(real_bl)} BL...")
    alive_wl_data, alive_bl_data = [], []

    # Уменьшаем число воркеров до 20, чтобы не перегружать CPU процессами Xray
    with ThreadPoolExecutor(max_workers=20) as executor:
        wl_futures = [executor.submit(check_proxy_alive, link) for link in real_wl]
        for future in as_completed(wl_futures):
            res = future.result()
            if res: alive_wl_data.append(res)
            
        bl_futures = [executor.submit(check_proxy_alive, link) for link in real_bl]
        for future in as_completed(bl_futures):
            res = future.result()
            if res: alive_bl_data.append(res)

    final_wl = [rename_config(item[0], idx, "[WL]", item[1]) for idx, item in enumerate(alive_wl_data, 1)]
    final_bl = [rename_config(item[0], idx, "[BL]", item[1]) for idx, item in enumerate(alive_bl_data, 1)]
    final_full = final_wl + final_bl

    with open('alive_bs.txt', 'w', encoding='utf-8') as f: f.write(base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8'))
    with open('alive_bl.txt', 'w', encoding='utf-8') as f: f.write(base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8'))
    with open('alive_full.txt', 'w', encoding='utf-8') as f: f.write(base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8'))

    if GEO_READER: GEO_READER.close()
    print("✨ Все готово! Результаты залиты.")

if __name__ == '__main__':
    main()
