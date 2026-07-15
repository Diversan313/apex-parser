import urllib.request
import urllib.parse
import re
import base64
import random
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Регулярка для поиска СТРОГО флагов стран (региональные индикаторы)
FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

def extract_clean_flag(text):
    if not text:
        return "🌐"
    flags = FLAG_REGEX.findall(text)
    if flags:
        return flags[0]  # Берем строго первый найденный флаг страны
    return "🌐"  # Если флага страны нет, возвращаем синий шарик

def check_tcp(host, port, timeout=2.0):
    try:
        if any(bad in host.lower() for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):
            return False
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except:
        return False

def parse_host_port(link):
    try:
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
            return host, int(port)
        elif clean_link.startswith('vmess://'):
            b64_data = clean_link.replace('vmess://', '').strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            return data.get('add'), int(data.get('port'))
    except:
        pass
    return None, None

def get_config_identity(link):
    """
    Создает уникальный 'паспорт' для конфига на основе реальных параметров:
    (Протокол, Хост/IP, Порт, SNI/Host)
    """
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
            
            host, port = parse_host_port(link)
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
    host, port = parse_host_port(link)
    if host and port:
        if check_tcp(host, port):
            return link
    return None

def fetch_single_url(url):
    try:
        url = url.strip().replace(' ', '%20')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req, timeout=5) as response:
            raw_data = response.read()
            try: content = raw_data.decode('utf-8', errors='ignore')
            except: content = raw_data.decode('latin-1', errors='ignore')
            
            # Умное декодирование Base64 (вырезает любые переносы строк и пробелы внутри)
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    clean_str = "".join(content.split())  # Убирает ВСЕ пробелы и переносы (\n, \r, \t)
                    clean_str = clean_str.replace('-', '+').replace('_', '/')
                    clean_str += "=" * ((4 - len(clean_str) % 4) % 4)
                    decoded = base64.b64decode(clean_str).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                except: pass
            return [l.strip() for l in content.split('\n') if l.strip()]
    except Exception as e:
        print(f"❌ Ошибка скачивания источника {url}: {e}")
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
        print(f"⚠️ Файл {url_file} отсутствует в репозитории!")
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
        host, _ = parse_host_port(link)
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

def rename_config(link, index, tag):
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            
            orig_name = data.get('ps', '')
            flag = extract_clean_flag(orig_name)
            
            data['ps'] = f"{flag} {tag} Сервер {index}"
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            return link
            
    if "://" in link:
        try:
            parts = link.split('#', 1)
            main_part = parts[0]
            orig_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            flag = extract_clean_flag(orig_name)
            
            new_name = f"{flag} {tag} Сервер {index}"
            return f"{main_part}#{urllib.parse.quote(new_name)}"
        except:
            return link
            
    return link

def main():
    print("🚀 Запуск парсера с поддержкой Base64 вывода...")
    
    wl_raw = fetch_links_parallel('sources_wl.txt')
    bl_raw = fetch_links_parallel('sources_bl.txt')

    print(f"📥 Из WL скачано сырых строк: {len(wl_raw)}")
    print(f"📥 Из BL скачано сырых строк: {len(bl_raw)}")

    wl_clean = clean_and_dedup(wl_raw)
    bl_clean = clean_and_dedup(bl_raw)

    print(f"🧹 После удаления дубликатов: WL = {len(wl_clean)}, BL = {len(bl_clean)}")

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

    print(f"⚡️ Начинаем проверку {len(real_wl)} уникальных конфигов для БС и {len(real_bl)} для ЧС...")
    
    alive_wl = []
    alive_bl = []

    with ThreadPoolExecutor(max_workers=80) as executor:
        wl_futures = [executor.submit(check_proxy_alive, link) for link in real_wl]
        for future in as_completed(wl_futures):
            res = future.result()
            if res: alive_wl.append(res)
            
        bl_futures = [executor.submit(check_proxy_alive, link) for link in real_bl]
        for future in as_completed(bl_futures):
            res = future.result()
            if res: alive_bl.append(res)

    print(f"📈 Найдено живых серверов: БС (WL) = {len(alive_wl)}, ЧС (BL) = {len(alive_bl)}")

    final_wl = [rename_config(link, idx, "[WL]") for idx, link in enumerate(alive_wl, 1)]
    final_bl = [rename_config(link, idx, "[BL]") for idx, link in enumerate(alive_bl, 1)]
    final_full = final_wl + final_bl

    # Кодируем результаты в BASE64 для совместимости со всеми клиентами
    wl_b64 = base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8') if final_wl else ""
    bl_b64 = base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8') if final_bl else ""
    full_b64 = base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8') if final_full else ""

    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write(wl_b64)
        
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:
        f.write(bl_b64)
        
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write(full_b64)

    print(f"\n📊 Успешно сохранено и закодировано в Base64:")
    print(f"🛡️ Только БС (alive_bs.txt) — {len(final_wl)} серверов")
    print(f"🛑 Только ЧС (alive_bl.txt) — {len(final_bl)} серверов")
    print(f"🌍 Полный список (alive_full.txt) — {len(final_full)} серверов")

if __name__ == '__main__':
    main()
