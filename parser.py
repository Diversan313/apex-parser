import os
import urllib.request
import urllib.parse
import re
import base64
import socket
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Пытаемся импортировать maxminddb для работы с GeoIP
try:
    import maxminddb
except ImportError:
    maxminddb = None

# Регулярка для поиска СТРОГО флагов стран (региональные индикаторы)
FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

# Ссылка на авторитетное и легкое зеркало базы GeoIP Country
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MMDB_PATH = "GeoLite2-Country.mmdb"

def download_geoip_db():
    """Автоматически скачивает базу GeoIP, если её нет"""
    if not os.path.exists(MMDB_PATH):
        print("📥 База GeoIP не найдена. Скачиваю актуальную версию...")
        try:
            req = urllib.request.Request(MMDB_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response, open(MMDB_PATH, 'wb') as out_file:
                out_file.write(response.read())
            print("✅ База GeoIP успешно загружена!")
        except Exception as e:
            print(f"⚠️ Не удалось скачать GeoIP базу: {e}. Скрипт продолжит работу по старому методу.")

# Инициализируем глобальный ридер для базы, чтобы не открывать файл каждую секунду
download_geoip_db()
GEO_READER = None
if maxminddb and os.path.exists(MMDB_PATH):
    try:
        GEO_READER = maxminddb.open_database(MMDB_PATH)
    except Exception as e:
        print(f"⚠️ Ошибка открытия базы GeoIP: {e}")

def cc_to_flag(cc):
    """Конвертирует двухбуквенный код страны (SSh, RU, US) в эмодзи флаг"""
    if not cc or len(cc) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cc.upper())

def extract_clean_flag(text):
    if not text:
        return "🌐"
    flags = FLAG_REGEX.findall(text)
    if flags:
        return flags[0]
    return "🌐"

def check_tcp(host, port, timeout=2.0):
    try:
        clean_host = host.strip('[]').lower()
        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
            return False
        with socket.create_connection((clean_host, int(port)), timeout=timeout):
            return True
    except:
        return False

def get_real_ip_and_flag(host, orig_flag):
    """Умный поиск страны по IP через локальную базу GeoIP"""
    if not GEO_READER:
        return orig_flag
    
    try:
        clean_host = host.strip('[]').lower()
        # Если это домен, резолвим его в IP-адрес
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host) and not ':' in clean_host:
            socket.setdefaulttimeout(1.5)
            ip_str = socket.gethostbyname(clean_host)
        else:
            ip_str = clean_host

        # Ищем IP в базе данных MaxMind
        record = GEO_READER.get(ip_str)
        if record and 'country' in record and 'iso_code' in record['country']:
            country_code = record['country']['iso_code']
            return cc_to_flag(country_code) # Возвращаем точный флаг из базы
    except:
        pass
    
    # Если IP не определился, скрытый или базы нет — возвращаем оригинальный флаг
    return orig_flag

def parse_host_port_and_name(link):
    """Парсит хост, порт и оригинальное имя конфига для извлечения старого флага"""
    try:
        orig_name = ""
        if '#' in link:
            orig_name = urllib.parse.unquote(link.split('#')[1])
            
        clean_link = link.split('#')[0]
        if clean_link.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            content = clean_link.split('://')[1]
            server_part = content.split('?')[0]
            if '@' in server_part:
                server_part = server_part.split('@')[1]
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
    except:
        pass
    return None, None, ""

def get_config_identity(link):
    try:
        protocol = link.split('://')[0].lower()
        if protocol == 'vmess':
            b64_data = link.replace('vmess://', '').strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            host = data.get('add', '').lower().strip()
            port = str(data.get('port', '')).strip()
            sni = data.get('sni', '').lower().strip() or data.get('host', '').lower().strip()
            return (protocol, host, port, sni)
        else:
            clean_link = link.split('#')[0]
            parsed_url = urllib.parse.urlparse(clean_link)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            host, port, _ = parse_host_port_and_name(link)
            if not host:
                return None
            
            host = host.lower().strip()
            port = str(port).strip()
            
            sni = ""
            if 'sni' in query_params:
                sni = query_params['sni'][0].lower().strip()
            elif 'host' in query_params:
                sni = query_params['host'][0].lower().strip()
                
            return (protocol, host, port, sni)
    except:
        return None

def check_proxy_alive(link):
    host, port, orig_name = parse_host_port_and_name(link)
    if host and port:
        if check_tcp(host, port):
            # Извлекаем старый флаг из названия
            orig_flag = extract_clean_flag(orig_name)
            # Запускаем умную проверку: база данных vs оригинальный флаг
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
                    clean_str = "".join(content.split())
                    clean_str = clean_str.replace('-', '+').replace('_', '/')
                    clean_str += "=" * ((4 - len(clean_str) % 4) % 4)
                    decoded = base64.b64decode(clean_str).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                except: pass
            return [l.strip() for l in content.split('\n') if l.strip()]
    except:
        return []

def fetch_links_parallel(url_file):
    links = []
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        print(f"📖 Читаем файл {url_file}, найдено источников: {len(urls)}")
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures): 
                links.extend(future.result())
    except FileNotFoundError:
        print(f"⚠️ Файл {url_file} отсутствует!")
    return links

def is_ru_sni(link):
    link_low = link.lower()
    if bool(re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link_low)):
        return True
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            sni = data.get('sni', '').lower()
            host = data.get('host', '').lower()
            add = data.get('add', '').lower()
            if any(x.endswith(('.ru', '.su')) or '.ru:' in x or '.su:' in x for x in [sni, host, add] if x):
                return True
        except: pass
    else:
        host, _, _ = parse_host_port_and_name(link)
        if host:
            host_low = host.lower()
            if host_low.endswith(('.ru', '.su')) or '.ru]' in host_low or '.su]' in host_low:
                return True
    return False

def clean_and_dedup(links):
    unique_identities = set()
    valid_links = []
    for link in links:
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')): 
            continue
        
        identity = get_config_identity(link)
        if identity:
            if identity not in unique_identities:
                unique_identities.add(identity)
                valid_links.append(link)
        else:
            core = link.split('#')[0]
            if core not in unique_identities:
                unique_identities.add(core)
                valid_links.append(link)
    return valid_links

def rename_config(link, index, tag, detected_flag):
    """Переименовывает конфиг, используя умный флаг, полученный при тесте"""
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            data['ps'] = f"{detected_flag} {tag} Сервер {index}"
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            return link
            
    if "://" in link:
        try:
            parts = link.split('#', 1)
            main_part = parts[0]
            new_name = f"{detected_flag} {tag} Сервер {index}"
            return f"{main_part}#{urllib.parse.quote(new_name)}"
        except:
            return link
    return link

def main():
    print("🚀 Запуск парсера с умным GeoIP...")
    
    wl_file = 'sources_wl.txt' if os.path.exists('sources_wl.txt') else 'source_wl.txt'
    bl_file = 'sources_bl.txt' if os.path.exists('sources_bl.txt') else 'source_bl.txt'

    wl_raw = fetch_links_parallel(wl_file)
    bl_raw = fetch_links_parallel(bl_file)

    wl_clean = clean_and_dedup(wl_raw)
    bl_clean = clean_and_dedup(bl_raw)

    real_wl = list(wl_clean)
    real_bl = []

    wl_identities = set()
    for link in real_wl:
        identity = get_config_identity(link)
        if identity:
            wl_identities.add(identity)

    for link in bl_clean:
        identity = get_config_identity(link)
        if identity and identity in wl_identities:
            continue
        
        if is_ru_sni(link):
            real_wl.append(link)
            if identity:
                wl_identities.add(identity)
        else:
            real_bl.append(link)

    print(f"⚡️ Проверяем {len(real_wl)} WL и {len(real_bl)} BL...")
    
    alive_wl_data = []
    alive_bl_data = []

    # Тестируем серверы параллельно
    with ThreadPoolExecutor(max_workers=45) as executor:
        wl_futures = [executor.submit(check_proxy_alive, link) for link in real_wl]
        for future in as_completed(wl_futures):
            res = future.result() # Возвращает кортеж (link, final_flag) или None
            if res: alive_wl_data.append(res)
            
        bl_futures = [executor.submit(check_proxy_alive, link) for link in real_bl]
        for future in as_completed(bl_futures):
            res = future.result()
            if res: alive_bl_data.append(res)

    print(f"📈 Найдено живых серверов: WL = {len(alive_wl_data)}, BL = {len(alive_bl_data)}")

    # Собираем финальные списки с правильными флагами
    final_wl = [rename_config(item[0], idx, "[WL]", item[1]) for idx, item in enumerate(alive_wl_data, 1)]
    final_bl = [rename_config(item[0], idx, "[BL]", item[1]) for idx, item in enumerate(alive_bl_data, 1)]
    final_full = final_wl + final_bl

    wl_b64 = base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8') if final_wl else ""
    bl_b64 = base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8') if final_bl else ""
    full_b64 = base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8') if final_full else ""

    with open('alive_bs.txt', 'w', encoding='utf-8') as f: f.write(wl_b64)
    with open('alive_bl.txt', 'w', encoding='utf-8') as f: f.write(bl_b64)
    with open('alive_full.txt', 'w', encoding='utf-8') as f: f.write(full_b64)

    # Закрываем ридер базы данных в конце
    if GEO_READER:
        GEO_READER.close()

if __name__ == '__main__':
    main()