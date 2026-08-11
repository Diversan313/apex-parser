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

# --- НАСТРОЙКИ И ФАЙЛЫ ---
WHITE_IP_FILE = 'white_ip.txt'
INCOMING_FILE = 'incoming_sources.txt'
MMDB_PATH = "GeoLite2-Country.mmdb"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

MAX_QUEUE_LIMIT = 1000
MAX_WORKERS = 15
MAX_CONFIGS_PER_IP_BL = 2      # Жесткий лимит для BL
MAX_CONFIGS_PER_IP_WL = 999999 # Бесконечный лимит для WL (только сортировка по SNI)
MAX_CONFIGS_PER_SUBNET_BL = 5  # Лимит на подсеть /24 в BL

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': '*/*'
}

DNS_CACHE = {}
DNS_LOCK = threading.Lock()
GEO_ONLINE_CACHE = {}
GEO_LOCK = threading.Lock()

WL_KEYWORDS_REGEX = re.compile(
    r'(?i)(?:^|[^a-zA-Zа-яА-Я0-9])(бс|обход|глусилк(?:а|и|ок|ам|ах)?|глушилк(?:а|и|ок|ам|ах)?|whitelist|lte|бел(?:ый|ые|ых)\s*списк(?:и|а|ов|ам|ах)?)(?:$|[^a-zA-Zа-яА-Я0-9])'
)
DOMAIN_REGEX = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$', re.IGNORECASE)

try:
    import maxminddb
except ImportError:
    maxminddb = None

FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

CF_CIDRS = [
    "103.4.160.0/22", "103.5.72.0/22", "103.7.4.0/22", "103.8.4.0/22", "103.8.84.0/22",
    "103.16.0.0/12", "103.24.124.0/22", "103.27.248.0/22", "103.44.96.0/22", "103.252.104.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    "8.39.124.0/22", "8.41.8.0/22", "8.42.120.0/22", "8.44.0.0/22", "8.46.0.0/22", "8.48.0.0/22", "8.50.0.0/22", "8.52.0.0/22"
]
CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CF_CIDRS]

def download_geoip_db():
    if not os.path.exists(MMDB_PATH):
        print("📥 Скачиваю оффлайн базу GeoIP...")
        try:
            req = urllib.request.Request(MMDB_URL, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=30, context=SSL_CONTEXT) as response, open(MMDB_PATH, 'wb') as out_file:
                out_file.write(response.read())
            print("✅ База GeoIP успешно загружена!")
        except Exception as e:
            print(f"⚠️ Ошибка загрузки базы GeoIP: {e}")

download_geoip_db()
GEO_READER = None
if maxminddb and os.path.exists(MMDB_PATH):
    try:
        GEO_READER = maxminddb.open_database(MMDB_PATH)
    except Exception:
        pass

def safe_b64decode(s: str) -> str:
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s).decode('utf-8', errors='ignore')

def sanitize_v2rayng_link(link: str) -> str:
    try:
        if link.startswith("vmess://"):
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            if str(data.get('net', '')).lower() in ['auto', 'none', '']:
                data['net'] = 'tcp'
            if str(data.get('tls', '')).lower() == 'auto':
                data['tls'] = ''
            if str(data.get('type', '')).lower() == 'auto':
                data['type'] = 'none'
            return f"vmess://{base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode('utf-8')}"
        
        main_part, name_part = link, ""
        if '#' in link:
            main_part, name_part = link.split('#', 1)
        
        base, query_part = main_part, ""
        if '?' in main_part:
            base, query_part = main_part.split('?', 1)

        if query_part:
            params = urllib.parse.parse_qs(query_part, keep_blank_values=True)
            changed = False
            
            if base.startswith('vless://'):
                if 'encryption' not in params or params['encryption'][0].lower() in ['auto', '']:
                    params['encryption'] = ['none']
                    changed = True
            
            if 'type' in params and params['type'][0].lower() == 'auto':
                params['type'] = ['tcp']
                changed = True
            if 'net' in params and params['net'][0].lower() == 'auto':
                params['net'] = ['tcp']
                changed = True
            
            if 'security' in params and params['security'][0].lower() == 'auto':
                del params['security']
                changed = True

            if changed:
                new_query = urllib.parse.urlencode(params, doseq=True)
                new_query = new_query.replace('+', '%20')
                new_link = f"{base}?{new_query}"
                if name_part:
                    new_link += f"#{name_part}"
                return new_link
    except:
        pass
    return link

def cc_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cc.upper())

def extract_clean_flag(text: str) -> str:
    if not text:
        return "🌐"
    flags = FLAG_REGEX.findall(text)
    return flags[0] if flags else "🌐"

def is_valid_public_host(host: str) -> bool:
    if not host:
        return False
    clean_host = host.strip('[] \t\r\n\'"').lower()
    if not clean_host or clean_host.isdigit():
        return False
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
    if '.' not in clean_host or clean_host.startswith('.') or clean_host.endswith('.'):
        return False
    if not DOMAIN_REGEX.match(clean_host):
        return False
    if clean_host.endswith(('.local', '.localhost', '.internal', '.lan', '.home', '.arpa', '.invalid', '.test')):
        return False
    return True

def resolve_host_cached(clean_host: str):
    clean_host = clean_host.strip('[] \t\r\n\'"').lower()
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
        resolved_ip = None if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_unspecified) else ip
    except Exception:
        resolved_ip = None
    with DNS_LOCK:
        DNS_CACHE[clean_host] = resolved_ip
    return resolved_ip

def fetch_country_from_ip(ip_str: str) -> str:
    if not ip_str or not is_valid_public_host(ip_str):
        return None
    if GEO_READER:
        try:
            record = GEO_READER.get(ip_str)
            if record and 'country' in record and 'iso_code' in record['country']:
                return record['country']['iso_code']
        except Exception:
            pass
    with GEO_LOCK:
        if ip_str in GEO_ONLINE_CACHE:
            return GEO_ONLINE_CACHE[ip_str]
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode"
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=2.0, context=SSL_CONTEXT) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success' and data.get('countryCode'):
                cc = data['countryCode']
                with GEO_LOCK:
                    GEO_ONLINE_CACHE[ip_str] = cc
                return cc
    except Exception:
        pass
    return None

def is_cloudflare_or_warp(host: str) -> bool:
    try:
        clean_host = host.strip('[] \t\r\n\'"').lower()
        if not is_valid_public_host(clean_host):
            return True
        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
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

def parse_host_port(server_part: str):
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

def parse_host_port_and_name(link: str):
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
                            _, host_port = decoded.rsplit('@', 1)
                            host, port = parse_host_port(host_port)
                            return host, port, orig_name
                    except Exception:
                        pass
                else:
                    _, host_port = rest.rsplit('@', 1)
                    host, port = parse_host_port(host_port)
                    return host, port, orig_name
            else:
                if '@' in rest:
                    rest = rest.rsplit('@', 1)[1]
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

def extract_sni_from_link(link: str) -> str:
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

def extract_all_hosts_and_ips_from_link(link: str) -> list:
    hosts = set()
    main_host, _, _ = parse_host_port_and_name(link)
    if main_host:
        hosts.add(main_host.strip('[] \t\r\n\'"').lower())

    sni = extract_sni_from_link(link)
    if sni:
        hosts.add(sni.strip('[] \t\r\n\'"').lower())

    if '?' in link:
        try:
            query_part = link.split('?', 1)[1].split('#')[0]
            params = urllib.parse.parse_qs(query_part)
            h_param = params.get('host', [''])[0]
            if h_param:
                hosts.add(h_param.strip('[] \t\r\n\'"').lower())
        except Exception:
            pass

    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', link)
    for ip_cand in ip_matches:
        try:
            ip_obj = ipaddress.ip_address(ip_cand)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                hosts.add(ip_cand)
        except ValueError:
            pass
    return list(hosts)

def parse_ip_or_resolve(item: str) -> set:
    if not item:
        return set()
    item = item.strip()
    if not item or item.startswith('#'):
        return set()
    if '://' in item:
        try:
            item = urllib.parse.urlparse(item).netloc or item.split('://', 1)[1]
        except Exception:
            pass
    item = item.split('/')[0].split('?')[0].split('#')[0].strip()
    host, _ = parse_host_port(item)
    if not host:
        host = item
    clean_host = host.strip('[] \t\r\n\'"').lower()
    if not is_valid_public_host(clean_host):
        return set()
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_unspecified):
            return {str(ip_obj)}
    except ValueError:
        pass
    resolved_ip = resolve_host_cached(clean_host)
    if resolved_ip:
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_unspecified):
                return {resolved_ip}
        except ValueError:
            pass
    return set()

def find_matched_ip_for_link(link: str, white_ips: set):
    if not white_ips:
        return None
    all_hosts = extract_all_hosts_and_ips_from_link(link)
    for host in all_hosts:
        if not host:
            continue
        clean_host = host.strip('[] \t\r\n\'"').lower()
        if not is_valid_public_host(clean_host):
            continue
        if clean_host in white_ips:
            return clean_host
        resolved_ip = resolve_host_cached(clean_host)
        if resolved_ip and resolved_ip in white_ips:
            return resolved_ip
    return None

def is_wl_by_keywords(link: str, orig_name: str = "") -> bool:
    full_text = f"{link} {orig_name}"
    try:
        full_text = urllib.parse.unquote(full_text)
    except Exception:
        pass
    return bool(WL_KEYWORDS_REGEX.search(full_text))

RU_SNI_LIST = [
    'www.vk.com', 'vk.com', 'm.vk.com', 'm1.vk.ru', 'st.vk.ru', 'id.vk.com', 'sun1-93.userapi.com',
    'yandex.ru', 'api-maps.yandex.ru', 'wap.yandex.ru', '360.yandex.ru', 'smartcaptcha.yandexcloud.net',
    'max.ru', 'web.max.ru', 'rutube.ru', 'storage.yandex.net', 'ads.x5.ru', '5post-gate.x5.ru',
    '28.img.avito.st', 'cdn.tracker.yandex.net', 'id.pervye.ru', 'ya.ru', 'rzd.ru', 'live.ok.ru', 'id.ok.ru',
    'qq.utiltools.ru', 'ru.muzgrape.space', 'flypobeda.ru', 'shopping-api-gateway.cdek.shopping',
    'api.acquisition-gwe.plus.yandex.ru'
]

def is_ru_sni(link: str) -> bool:
    link_low = link.lower()
    if bool(re.search(r'sni=[^&]*\.(ru|su|рф)(?:&|$)', link_low)):
        return True
    for ru_sni in RU_SNI_LIST:
        if f'sni={ru_sni}' in link_low:
            return True
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            sni_val = str(data.get('sni', '') or data.get('host', '') or data.get('add', '')).lower()
            if any(s in sni_val for s in RU_SNI_LIST) or sni_val.endswith(('.ru', '.su', '.рф')):
                return True
        except Exception:
            pass
    else:
        host, _, _ = parse_host_port_and_name(link)
        if host and (host.lower().endswith(('.ru', '.su', '.рф')) or '.ru]' in host.lower()):
            return True
    return False

def is_wl_for_bl_source(link: str, white_ips: set) -> bool:
    if find_matched_ip_for_link(link, white_ips):
        return True
    host, _, orig_name = parse_host_port_and_name(link)
    if not host or not is_valid_public_host(host):
        return False
    if is_wl_by_keywords(link, orig_name):
        return True
    if is_ru_sni(link):
        return True
    clean_ip = resolve_host_cached(host.strip('[] \t\r\n\'"').lower())
    if clean_ip:
        cc = fetch_country_from_ip(clean_ip)
        if cc and cc.upper() == 'RU':
            return True
    return False

def link_to_xray_outbound(link: str):
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
                    user_info, host_port = decoded.rsplit('@', 1)
                else:
                    return None
            else:
                user_info, host_port = rest.rsplit('@', 1)
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
            user_info, host_port = rest.rsplit('@', 1) if '@' in rest else ("", rest)
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
            
            # Парсинг параметра extra для сложных XHTTP конфигов
            extra_raw = query_params.get('extra', [''])[0]
            extra_data = {}
            if extra_raw:
                try:
                    extra_data = json.loads(extra_raw)
                except:
                    pass

            if net == 'ws':
                ws_settings = {"path": path_val, "headers": {"Host": host_val} if host_val else {}}
                ws_settings.update(extra_data)
                outbound["streamSettings"]["wsSettings"] = ws_settings
            elif net == 'grpc':
                grpc_settings = {"serviceName": query_params.get('serviceName', [''])[0] or path_val.lstrip('/')}
                grpc_settings.update(extra_data)
                outbound["streamSettings"]["grpcSettings"] = grpc_settings
            elif net in ['xhttp', 'splithttp']:
                xhttp_settings = {
                    "path": path_val,
                    "host": host_val,
                    "mode": query_params.get('mode', ['auto'])[0]
                }
                xhttp_settings.update(extra_data)
                if not xhttp_settings.get('path'):
                    xhttp_settings['path'] = path_val or "/"
                if not xhttp_settings.get('host'):
                    xhttp_settings['host'] = host_val
                outbound["streamSettings"]["xhttpSettings"] = xhttp_settings
            elif net == 'httpupgrade':
                httpupgrade_settings = {"path": path_val, "host": host_val}
                httpupgrade_settings.update(extra_data)
                outbound["streamSettings"]["httpupgradeSettings"] = httpupgrade_settings
            elif net in ['http', 'h2']:
                http_settings = {"path": path_val, "host": [host_val] if host_val else []}
                http_settings.update(extra_data)
                outbound["streamSettings"]["httpSettings"] = http_settings
            elif net in ['kcp', 'mkcp']:
                kcp_settings = {"header": {"type": header_type}}
                kcp_settings.update(extra_data)
                outbound["streamSettings"]["kcpSettings"] = kcp_settings

        return outbound
    except Exception:
        return None

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_port(port: int, timeout: float = 0.6) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.05):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.01)
    return False

def get_xray_cmd() -> list:
    exe = "xray.exe" if os.name == 'nt' else "./xray"
    if not os.path.exists(exe):
        exe = "xray"
    return [exe, "run", "-c", "stdin:"]

def get_exit_country_via_proxy(opener, timeout):
    results = []
    try:
        req = urllib.request.Request("http://ip-api.com/json?fields=countryCode", headers=HEADERS)
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success' and data.get('countryCode'):
                results.append(('ip-api', data['countryCode'].upper()))
    except:
        pass
    try:
        req = urllib.request.Request("https://api.ip2location.io/", headers=HEADERS)
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('country_code'):
                results.append(('ip2location', data['country_code'].upper()))
    except:
        pass
    try:
        req = urllib.request.Request("https://api.ip.sb/geoip", headers=HEADERS)
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            cc = data.get('country_code') or data.get('country')
            if cc:
                results.append(('ip.sb', cc.upper()))
    except:
        pass
    if not results:
        return None
    cc_counts = {}
    for _, cc in results:
        cc_counts[cc] = cc_counts.get(cc, 0) + 1
    for cc, count in cc_counts.items():
        if count >= 2:
            return cc
    for name, cc in results:
        if name == 'ip-api':
            return cc
    return results[0][1]

def check_via_xray_detailed(outbound_obj: dict, timeout: float = 6.0, min_success_count: int = 2):
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

        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.microsoft.com/connecttest.txt"
        ]

        success_count = 0
        cc = None

        for url in test_urls:
            try:
                req = urllib.request.Request(url, headers=HEADERS)
                with opener.open(req, timeout=timeout) as resp:
                    if resp.status in [200, 204]:
                        success_count += 1
            except Exception:
                pass

        if success_count >= min_success_count:
            cc = get_exit_country_via_proxy(opener, timeout)
            return True, cc, f"OK ({success_count}/3)"

        return False, None, f"Тест провален ({success_count}/3)"

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

def check_proxy_alive_detailed(link: str, min_success_count: int = 2):
    host, port, orig_name = parse_host_port_and_name(link)
    if not host or not port or not is_valid_public_host(host):
        return False, None, "Некорректный формат хоста/порта", None

    if is_cloudflare_or_warp(host):
        return False, None, "Отфильтрован (Cloudflare/WARP)", None

    if link.startswith(('hysteria2://', 'hy2://')):
        return False, None, "Hysteria2 не поддерживается Xray", None

    outbound = link_to_xray_outbound(link)
    if not outbound:
        return False, None, "Ошибка генерации JSON для Xray", None

    is_ok, cc, reason = check_via_xray_detailed(outbound, timeout=6.0, min_success_count=min_success_count)
    if is_ok:
        if cc:
            final_flag = cc_to_flag(cc)
        else:
            final_flag = extract_clean_flag(orig_name)
        return True, (link, final_flag), "OK", cc
    return False, None, "Ошибка", None

def fetch_single_url_with_details(url: str) -> dict:
    url_clean = url.strip().replace(' ', '%20')
    info = {'url': url, 'http_status': None, 'size_bytes': 0, 'is_base64': False, 'total_lines': 0, 'configs': [], 'error': None}
    try:
        req = urllib.request.Request(url_clean, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=12, context=SSL_CONTEXT) as response:
            info['http_status'] = response.status
            raw_data = response.read()
            info['size_bytes'] = len(raw_data)
            try:
                content = raw_data.decode('utf-8', errors='ignore')
            except Exception:
                content = raw_data.decode('latin-1', errors='ignore')

            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    decoded = safe_b64decode(content)
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                        info['is_base64'] = True
                except Exception:
                    pass

            raw_lines = [l.strip() for l in content.splitlines() if l.strip()]
            info['total_lines'] = len(raw_lines)
            valid_configs = [sanitize_v2rayng_link(l) for l in raw_lines if l.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://'))]
            info['configs'] = valid_configs
    except Exception as e:
        info['error'] = str(e)
    return info

def fetch_links_parallel_with_source(url_file: str) -> list:
    links_with_source = []
    if not os.path.exists(url_file):
        print(f"⚠️ Файл источников {url_file} не найден!")
        return links_with_source
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        print(f"\n📡 [{url_file}] Скачивание источников ({len(urls)} шт.)...")
        successful_sources = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fetch_single_url_with_details, url): idx for idx, url in enumerate(urls, 1)}
            for future in as_completed(futures):
                idx = futures[future]
                res = future.result()
                configs = res['configs']
                status_str = f"HTTP {res['http_status']}" if res['http_status'] else "ОШИБКА"
                b64_str = " [Base64]" if res['is_base64'] else ""
                err_str = f" (Ошибка: {res['error']})" if res['error'] else ""
                if res['http_status'] in [200, 204] or configs:
                    successful_sources += 1
                print(f"  ├─ 🔗 Источник #{idx:<3} | Статус: {status_str:<10} | Размер: {res['size_bytes']}B | Найдено конфигов: {len(configs)}{b64_str}{err_str}")
                for cfg in configs:
                    links_with_source.append((cfg, res['url']))
        print(f"✅ Успешно получено {len(links_with_source)} конфигов из {successful_sources}/{len(urls)} источников.")
    except Exception as e:
        print(f"⚠️ Ошибка чтения {url_file}: {e}")
    return links_with_source

# Очередь ТГ берет ТОЛЬКО IP-адреса
def process_incoming_queue():
    incoming_raw_ips = []
    if os.path.exists(INCOMING_FILE):
        try:
            with open(INCOMING_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            unique_lines = list(dict.fromkeys(lines))[:MAX_QUEUE_LIMIT]
            for item in unique_lines:
                extracted = parse_ip_or_resolve(item)
                for ip in extracted:
                    incoming_raw_ips.append(ip)
            print(f"📥 Из очереди забрано {len(incoming_raw_ips)} чистых IP (ссылки на конфиги игнорируются).")
        except Exception as e:
            print(f"⚠️ Ошибка чтения очереди {INCOMING_FILE}: {e}")
    return incoming_raw_ips

def load_previous_alives():
    prev_wl = []
    prev_bl = []
    if os.path.exists('alive_bs.txt'):
        try:
            with open('alive_bs.txt', 'r', encoding='utf-8') as f:
                decoded = safe_b64decode(f.read())
                prev_wl = [sanitize_v2rayng_link(l.strip()) for l in decoded.splitlines() if l.strip().startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://'))]
        except Exception:
            pass
    if os.path.exists('alive_bl.txt'):
        try:
            with open('alive_bl.txt', 'r', encoding='utf-8') as f:
                decoded = safe_b64decode(f.read())
                prev_bl = [sanitize_v2rayng_link(l.strip()) for l in decoded.splitlines() if l.strip().startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://'))]
        except Exception:
            pass
    print(f"📂 Загружено из прошлых файлов: WL={len(prev_wl)}, BL={len(prev_bl)}")
    return prev_wl, prev_bl

def get_config_dedup_key(link: str) -> tuple:
    host, port, _ = parse_host_port_and_name(link)
    if not host or not port:
        return None
    clean_host = host.strip('[] \t\r\n\'"').lower()
    clean_ip = resolve_host_cached(clean_host) or clean_host
    protocol = link.split('://')[0].lower() if '://' in link else ''
    sni = extract_sni_from_link(link)
    
    net, path, pbk, uuid, security = "", "", "", "", ""
    flow, sid, mode = "", "", ""
    try:
        if link.startswith("vmess://"):
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            uuid = str(data.get('id', ''))
            net = str(data.get('net', 'raw')).lower()
            path = str(data.get('path', ''))
            security = str(data.get('tls', ''))
        else:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username or ''
            query_params = urllib.parse.parse_qs(parsed.query)
            net = query_params.get('type', query_params.get('net', ['raw']))[0].lower()
            path = query_params.get('path', [''])[0]
            pbk = query_params.get('pbk', [''])[0]
            security = query_params.get('security', [''])[0].lower()
            flow = query_params.get('flow', [''])[0].lower()
            sid = query_params.get('sid', [''])[0]
            mode = query_params.get('mode', [''])[0].lower()
    except Exception:
        pass
    
    path = urllib.parse.unquote(path) or "/"
    return (protocol, clean_ip, str(port), sni, net, path, pbk, uuid, security, flow, sid, mode)

def get_final_dedup_key(link: str) -> tuple:
    host, port, _ = parse_host_port_and_name(link)
    if not host or not port:
        return None
    clean_host = host.strip('[] \t\r\n\'"').lower()
    clean_ip = resolve_host_cached(clean_host) or clean_host
    protocol = link.split('://')[0].lower() if '://' in link else ''
    sni = extract_sni_from_link(link)
    
    net, path, security = "", "/", ""
    try:
        if link.startswith("vmess://"):
            b64_data = link.replace("vmess://", "").strip()
            decoded = safe_b64decode(b64_data)
            data = json.loads(decoded)
            net = str(data.get('net', 'raw')).lower()
            path = str(data.get('path', '')) or "/"
            security = str(data.get('tls', '')).lower()
        else:
            parsed = urllib.parse.urlparse(link)
            query_params = urllib.parse.parse_qs(parsed.query)
            net = query_params.get('type', query_params.get('net', ['raw']))[0].lower()
            path = query_params.get('path', [''])[0] or "/"
            security = query_params.get('security', [''])[0].lower()
    except Exception:
        pass
    
    path = urllib.parse.unquote(path) or "/"
    return (protocol, clean_ip, str(port), sni, net, path, security)

def clean_and_dedup(tagged_items: list) -> list:
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
        key = get_config_dedup_key(link)
        if not key:
            continue
        if key in seen_keys:
            continue
        seen_keys.add(key)
        valid_items.append((link, source_tag))
    return valid_items

def limit_configs_per_ip(items_list: list, white_ips: set, is_wl_list: bool = False, max_per_ip_bl: int = 2, max_per_ip_wl: int = 30, max_per_subnet_bl: int = 5) -> list:
    ip_counter = defaultdict(int)
    subnet_counter = defaultdict(int)
    filtered = []
    
    grouped_by_ip = defaultdict(list)
    for item in items_list:
        link = item[0] if isinstance(item, (tuple, list)) else item
        host, _, _ = parse_host_port_and_name(link)
        if not host: continue
        clean_host = host.strip('[] \t\r\n\'"').lower()
        ip_str = resolve_host_cached(clean_host) or clean_host
        grouped_by_ip[ip_str].append(item)
        
    for ip_str, items in grouped_by_ip.items():
        is_wl = is_wl_list or (ip_str in white_ips)
        limit = 999999 if is_wl else max_per_ip_bl
        
        if is_wl:
            seen_snis = set()
            unique_sni_items = []
            other_items = []
            for item in items:
                link = item[0] if isinstance(item, (tuple, list)) else item
                sni = extract_sni_from_link(link)
                if sni not in seen_snis:
                    seen_snis.add(sni)
                    unique_sni_items.append(item)
                else:
                    other_items.append(item)
            items = unique_sni_items + other_items
            
        for item in items:
            if ip_counter[ip_str] >= limit:
                break
                
            if not is_wl:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.version == 4:
                        subnet_key = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                    else:
                        subnet_key = str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
                        
                    if subnet_counter[subnet_key] >= max_per_subnet_bl:
                        continue
                    subnet_counter[subnet_key] += 1
                except:
                    pass
                    
            ip_counter[ip_str] += 1
            filtered.append(item)

    print(f"✂️ Ограничение на IP (BL:{max_per_ip_bl}, WL: {'Бесконечно' if is_wl_list else max_per_ip_wl}, Subnet BL:{max_per_subnet_bl}): было {len(items_list)}, осталось {len(filtered)}.")
    return filtered

def dedup_advanced(config_list: list, list_name: str = "") -> list:
    seen_keys = set()
    result = []
    for item in config_list:
        link = item[0] if isinstance(item, (tuple, list)) else item
        key = get_final_dedup_key(link)
        if key and key not in seen_keys:
            seen_keys.add(key)
            result.append(item)
    removed = len(config_list) - len(result)
    print(f"🔍 Финальная дедупликация {list_name}: было {len(config_list)}, осталось {len(result)} (удалено дубликатов: {removed})")
    return result

def rename_config(link: str, index: int, tag: str, detected_flag: str) -> str:
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

def filter_protocols_bl(alive_configs, minority_ratio=0.10):
    priority = []
    minority = []
    for item in alive_configs:
        link = item[0] if isinstance(item, (tuple, list)) else item
        proto = link.split('://')[0].lower()
        if proto in ['vless', 'hysteria2', 'hy2']:
            priority.append(item)
        else:
            minority.append(item)
    
    max_minority = max(10, int(len(priority) * (minority_ratio / (1 - minority_ratio))))
    if len(minority) > max_minority:
        minority = minority[:max_minority]
        
    print(f"🎯 Фильтр BL протоколов: VLESS/Hy2: {len(priority)} шт. | Старые (SS/VMess/Trojan): {len(minority)} шт. (лимит {minority_ratio*100}%)")
    return priority + minority

def main():
    print("🚀 Старт продвинутого Xray-парсера...")
    wl_file = 'sources_wl.txt' if os.path.exists('sources_wl.txt') else 'source_wl.txt'
    bl_file = 'sources_bl.txt' if os.path.exists('sources_bl.txt') else 'source_bl.txt'

    wl_fetched_with_source = fetch_links_parallel_with_source(wl_file)
    bl_fetched_with_source = fetch_links_parallel_with_source(bl_file)
    incoming_raw_ips = process_incoming_queue()

    white_ips = set()
    if os.path.exists(WHITE_IP_FILE):
        with open(WHITE_IP_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                extracted = parse_ip_or_resolve(line)
                white_ips.update(extracted)

    for item in incoming_raw_ips:
        extracted = parse_ip_or_resolve(item)
        white_ips.update(extracted)

    def ip_sort_key(ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError:
            return ip

    with open(WHITE_IP_FILE, 'w', encoding='utf-8') as f:
        for ip in sorted(list(white_ips), key=ip_sort_key):
            f.write(f"{ip}\n")
    print(f"💾 База {WHITE_IP_FILE} сохранена. Всего IP: {len(white_ips)}")

    ping_wl = []
    ping_bl = []
    alive_wl_data = []
    alive_bl_data = []

    seen_links_for_ping = set()

    # 1. Источники WL -> ВСЕГДА идут в WL
    for link, src in wl_fetched_with_source:
        link = sanitize_v2rayng_link(link)
        if link in seen_links_for_ping: continue
        
        if find_matched_ip_for_link(link, white_ips):
            orig_flag = extract_clean_flag(parse_host_port_and_name(link)[2])
            alive_wl_data.append((link, orig_flag))
            seen_links_for_ping.add(link)
        else:
            ping_wl.append((link, src))
            seen_links_for_ping.add(link)

    # 2. Источники BL -> Проверка на RU SNI / RU IP
    for link, src in bl_fetched_with_source:
        link = sanitize_v2rayng_link(link)
        if link in seen_links_for_ping: continue
        
        host, _, orig_name = parse_host_port_and_name(link)
        if not host or not is_valid_public_host(host): continue

        if find_matched_ip_for_link(link, white_ips):
            orig_flag = extract_clean_flag(orig_name)
            alive_wl_data.append((link, orig_flag))
            seen_links_for_ping.add(link)
        elif is_wl_for_bl_source(link, white_ips):
            ping_wl.append((link, src))
            seen_links_for_ping.add(link)
        else:
            ping_bl.append((link, src))
            seen_links_for_ping.add(link)

    # 3. Загрузка прошлых живых конфигов
    prev_wl_links, prev_bl_links = load_previous_alives()
    for link in prev_wl_links:
        if link not in seen_links_for_ping:
            ping_wl.append((link, 'PREV_WL'))
            seen_links_for_ping.add(link)
    for link in prev_bl_links:
        if link not in seen_links_for_ping:
            ping_bl.append((link, 'PREV_BL'))
            seen_links_for_ping.add(link)

    # Для WL: НИКАКИХ лимитов до пинга! Только базовая очистка от полных дублей.
    clean_ping_wl = clean_and_dedup(ping_wl)
    
    # Для BL: лимиты до пинга
    clean_ping_bl = clean_and_dedup(ping_bl)
    clean_ping_bl = limit_configs_per_ip(clean_ping_bl, white_ips, is_wl_list=False, max_per_ip_bl=MAX_CONFIGS_PER_IP_BL, max_per_ip_wl=MAX_CONFIGS_PER_IP_WL, max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL)

    print(f"\n📡 Отправка на проверку Xray: WL конфигов (1/3): {len(clean_ping_wl)} | BL конфигов (2/3): {len(clean_ping_bl)}")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # WL пинг: 1 из 3
        wl_futures = {executor.submit(check_proxy_alive_detailed, link, 1): (link, src) for link, src in clean_ping_wl}
        for future in as_completed(wl_futures):
            is_ok, res, reason, cc = future.result()
            if is_ok:
                alive_wl_data.append(res)

        # BL пинг: 2 из 3
        bl_futures = {executor.submit(check_proxy_alive_detailed, link, 2): (link, src) for link, src in clean_ping_bl}
        for future in as_completed(bl_futures):
            is_ok, res, reason, cc = future.result()
            if is_ok:
                if cc and cc.upper() == 'RU':
                    alive_wl_data.append(res)
                else:
                    alive_bl_data.append(res)

    # 4. Дедупликация ПОСЛЕ пинга
    alive_wl_data = dedup_advanced(alive_wl_data, "WL (предварительно)")
    alive_bl_data = dedup_advanced(alive_bl_data, "BL (предварительно)")

    # 5. Применяем лимиты к уже очищенным от дублей данным (для WL - бесконечно, только сортировка по SNI)
    alive_wl_clean = limit_configs_per_ip(alive_wl_data, white_ips, is_wl_list=True, max_per_ip_bl=MAX_CONFIGS_PER_IP_BL, max_per_ip_wl=999999, max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL)
    
    alive_bl_limited = limit_configs_per_ip(alive_bl_data, white_ips, is_wl_list=False, max_per_ip_bl=MAX_CONFIGS_PER_IP_BL, max_per_ip_wl=999999, max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL)
    alive_bl_clean = filter_protocols_bl(alive_bl_limited, minority_ratio=0.10)

    # 6. Финальная сборка
    wl_set = set(alive_wl_clean)
    alive_full_raw = alive_wl_clean + alive_bl_clean
    alive_full_clean = limit_configs_per_ip(dedup_advanced(alive_full_raw, "FULL"), white_ips, is_wl_list=True, max_per_ip_bl=MAX_CONFIGS_PER_IP_BL, max_per_ip_wl=999999, max_per_subnet_bl=MAX_CONFIGS_PER_SUBNET_BL)

    final_wl = [rename_config(item[0], idx, "[WL]", item[1]) for idx, item in enumerate(alive_wl_clean, 1)]
    final_bl = [rename_config(item[0], idx, "[BL]", item[1]) for idx, item in enumerate(alive_bl_clean, 1)]
    final_full = [rename_config(item[0], idx, "[WL]" if item in wl_set else "[BL]", item[1]) for idx, item in enumerate(alive_full_clean, 1)]

    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8'))
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8'))
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8'))

    if GEO_READER:
        GEO_READER.close()
    print("✨ Все готово! Результаты записаны в alive_bs.txt, alive_bl.txt и alive_full.txt.")

if __name__ == '__main__':
    main()