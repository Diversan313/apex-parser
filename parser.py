import urllib.request
import urllib.parse
import re
import base64
import random
import socket
import json
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Регулярка для поиска СТРОГО флагов стран (региональные индикаторы)
FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')[cite: 3]

# Кэш DNS для защиты от банов со стороны DNS-серверов и ускорения работы
DNS_CACHE = {}
dns_lock = threading.Lock()

# Раздельные списки подсетей Cloudflare для IPv4 и IPv6 во избежание TypeError
CF_IPV4 = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("162.159.0.0/16")  # Сюда же улетает весь WARP
]

CF_IPV6 = [
    ipaddress.ip_network("2400:cb00::/32"),
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2803:f800::/32"),
    ipaddress.ip_network("2405:b500::/32"),
    ipaddress.ip_network("2405:8100::/32"),
    ipaddress.ip_network("2a06:98c0::/29"),
    ipaddress.ip_network("2c0f:f248::/32")
]

def cached_resolve(host):
    """Потокобезопасный резолв домена с кэшированием результатов"""
    with dns_lock:
        if host in DNS_CACHE:
            return DNS_CACHE[host]
    
    result = None
    try:
        # Пробуем получить IPv4 (быстрее и стабильнее)
        try:
            ip_str = socket.gethostbyname(host)
        except socket.gaierror:
            # Если не вышло, резолвим getaddrinfo для поддержки IPv6
            addr_info = socket.getaddrinfo(host, None)
            ip_str = addr_info[0][4][0]
            
        result = ipaddress.ip_address(ip_str)
    except Exception:
        pass
        
    with dns_lock:
        DNS_CACHE[host] = result
    return result

def extract_clean_flag(text):
    if not text:
        return "🌐"
    flags = FLAG_REGEX.findall(text)[cite: 3]
    if flags:
        return flags[0]  # Берем строго первый найденный флаг страны[cite: 3]
    return "🌐"  # Если флага страны нет, возвращаем синий шарик[cite: 3]

def check_tcp(host, port, timeout=2.0):
    try:
        # Очищаем скобки IPv6 во избежание падения socket.create_connection
        clean_host = host.strip('[]').lower()
        if any(bad in clean_host for bad in ['localhost', '127.0.0.1', 'github.com', '.ir', '.cn', '.cf', '.ga', '.gq', '.ml', '.tk']):[cite: 3]
            return False
        with socket.create_connection((clean_host, int(port)), timeout=timeout):[cite: 3]
            return True
    except:
        return False

def is_cloudflare_or_blocked(host):
    """Проверяет, принадлежит ли хост/IP Клаудфлейру"""
    try:
        clean_host = host.strip('[]').lower()
        
        # Быстрый отсев локалхоста
        if clean_host in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return True

        # Проверяем, является ли хост уже готовым IP-адресом
        try:
            ip_obj = ipaddress.ip_address(clean_host)
        except ValueError:
            # Если это домен, резолвим его с использованием кэша
            ip_obj = cached_resolve(clean_host)

        # Если DNS не смог зарезолвить домен — даем ему шанс пройти через check_tcp
        if ip_obj is None:
            return False

        # Проверяем IP на принадлежность к Cloudflare подсетям
        if ip_obj.version == 4:
            # Специфический бан (если требуется)
            if str(ip_obj).startswith("8.39."):
                return True
            for network in CF_IPV4:
                if ip_obj in network:
                    return True
        elif ip_obj.version == 6:
            for network in CF_IPV6:
                if ip_obj in network:
                    return True

    except Exception:
        # В случае любой ошибки не блокируем намертво, пусть решает обычный TCP-пинг
        return False

    return False

def parse_host_port(link):
    try:
        clean_link = link.split('#')[0][cite: 3]
        if clean_link.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):[cite: 3]
            content = clean_link.split('://')[1][cite: 3]
            server_part = content.split('?')[0][cite: 3]
            if '@' in server_part:[cite: 3]
                server_part = server_part.split('@')[1][cite: 3]
            if server_part.startswith('['):[cite: 3]
                host = server_part.split(']')[0] + ']'[cite: 3]
                port = server_part.split(']:')[1][cite: 3]
            else:
                host, port = server_part.split(':')[cite: 3]
            return host, int(port)[cite: 3]
        elif clean_link.startswith('vmess://'):[cite: 3]
            b64_data = clean_link.replace('vmess://', '').strip()[cite: 3]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)[cite: 3]
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))[cite: 3]
            return data.get('add'), int(data.get('port'))[cite: 3]
    except:
        pass
    return None, None[cite: 3]

def get_config_identity(link):
    """
    Создает уникальный 'паспорт' для конфига на основе реальных параметров:
    (Протокол, Host/IP, Порт, SNI/Host)
    """
    try:
        protocol = link.split('://')[0].lower()[cite: 3]
        if protocol == 'vmess':[cite: 3]
            b64_data = link.replace('vmess://', '').strip()[cite: 3]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)[cite: 3]
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))[cite: 3]
            host = data.get('add', '').lower().strip()[cite: 3]
            port = str(data.get('port', '')).strip()[cite: 3]
            sni = data.get('sni', '').lower().strip() or data.get('host', '').lower().strip()[cite: 3]
            return (protocol, host, port, sni)[cite: 3]
        else:
            clean_link = link.split('#')[0][cite: 3]
            parsed_url = urllib.parse.urlparse(clean_link)[cite: 3]
            query_params = urllib.parse.parse_qs(parsed_url.query)[cite: 3]
            
            host, port = parse_host_port(link)[cite: 3]
            if not host:[cite: 3]
                return None
            
            host = host.lower().strip()[cite: 3]
            port = str(port).strip()[cite: 3]
            
            sni = ""[cite: 3]
            if 'sni' in query_params:[cite: 3]
                sni = query_params['sni'][0].lower().strip()[cite: 3]
            elif 'host' in query_params:[cite: 3]
                sni = query_params['host'][0].lower().strip()[cite: 3]
                
            return (protocol, host, port, sni)[cite: 3]
    except:
        return None[cite: 3]

def check_proxy_alive(link):
    host, port = parse_host_port(link)[cite: 3]
    if host and port:[cite: 3]
        # 1. Если это Cloudflare или WARP — мгновенно выбрасываем
        if is_cloudflare_or_blocked(host):
            return None
        # 2. Пингуем только чистые VPS порты
        if check_tcp(host, port):[cite: 3]
            return link[cite: 3]
    return None[cite: 3]

def fetch_single_url(url):
    try:
        url = url.strip().replace(' ', '%20')[cite: 3]
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})[cite: 3]
        with urllib.request.urlopen(req, timeout=5) as response:[cite: 3]
            raw_data = response.read()[cite: 3]
            try: content = raw_data.decode('utf-8', errors='ignore')[cite: 3]
            except: content = raw_data.decode('latin-1', errors='ignore')[cite: 3]
            
            # Умное декодирование Base64 (вырезает любые переносы строк и пробелы внутри)
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):[cite: 3]
                try:
                    clean_str = "".join(content.split())  # Убирает ВСЕ пробелы и переносы (\n, \r, \t)[cite: 3]
                    clean_str = clean_str.replace('-', '+').replace('_', '/')[cite: 3]
                    clean_str += "=" * ((4 - len(clean_str) % 4) % 4)[cite: 3]
                    decoded = base64.b64decode(clean_str).decode('utf-8', errors='ignore')[cite: 3]
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):[cite: 3]
                        content = decoded[cite: 3]
                except: pass[cite: 3]
            return [l.strip() for l in content.split('\n') if l.strip()][cite: 3]
    except Exception as e:
        print(f"❌ Ошибка скачивания источника {url}: {e}")[cite: 3]
        return [][cite: 3]

def fetch_links_parallel(url_file):
    links = [][cite: 3]
    try:
        with open(url_file, 'r', encoding='utf-8') as f:[cite: 3]
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')][cite: 3]
        print(f"📖 Читаем файл {url_file}, найдено источников: {len(urls)}")[cite: 3]
        with ThreadPoolExecutor(max_workers=30) as executor:[cite: 3]
            futures = {executor.submit(fetch_single_url, url): url for url in urls}[cite: 3]
            for future in as_completed(futures):[cite: 3]
                links.extend(future.result())[cite: 3]
    except FileNotFoundError:[cite: 3]
        print(f"⚠️ Файл {url_file} отсутствует в репозитории!")[cite: 3]
    return links[cite: 3]

def is_ru_sni(link):
    link_low = link.lower()[cite: 3]
    if bool(re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link_low)):[cite: 3]
        return True[cite: 3]
    if link.startswith("vmess://"):[cite: 3]
        try:
            b64_data = link.replace("vmess://", "").strip()[cite: 3]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)[cite: 3]
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))[cite: 3]
            sni = data.get('sni', '').lower()[cite: 3]
            host = data.get('host', '').lower()[cite: 3]
            add = data.get('add', '').lower()[cite: 3]
            if any(x.endswith(('.ru', '.su')) or '.ru:' in x or '.su:' in x for x in [sni, host, add] if x):[cite: 3]
                return True[cite: 3]
        except: pass[cite: 3]
    else:
        host, _ = parse_host_port(link)[cite: 3]
        if host:[cite: 3]
            host_low = host.lower()[cite: 3]
            if host_low.endswith(('.ru', '.su')) or '.ru]' in host_low or '.su]' in host_low:[cite: 3]
                return True[cite: 3]
    return False[cite: 3]

def clean_and_dedup(links):
    unique_identities = set()[cite: 3]
    valid_links = [][cite: 3]
    for link in links:[cite: 3]
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):[cite: 3]
            continue[cite: 3]
        
        identity = get_config_identity(link)[cite: 3]
        if identity:[cite: 3]
            if identity not in unique_identities:[cite: 3]
                unique_identities.add(identity)[cite: 3]
                valid_links.append(link)[cite: 3]
        else:
            core = link.split('#')[0][cite: 3]
            if core not in unique_identities:[cite: 3]
                unique_identities.add(core)[cite: 3]
                valid_links.append(link)[cite: 3]
    return valid_links[cite: 3]

def rename_config(link, index, tag):
    if link.startswith("vmess://"):[cite: 3]
        try:
            b64_data = link.replace("vmess://", "").strip()[cite: 3]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)[cite: 3]
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))[cite: 3]
            
            orig_name = data.get('ps', '')[cite: 3]
            flag = extract_clean_flag(orig_name)[cite: 3]
            
            data['ps'] = f"{flag} {tag} Сервер {index}"[cite: 3]
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')[cite: 3]
            return f"vmess://{new_b64}"[cite: 3]
        except:
            return link[cite: 3]
            
    if "://" in link:[cite: 3]
        try:
            parts = link.split('#', 1)[cite: 3]
            main_part = parts[0][cite: 3]
            orig_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""[cite: 3]
            
            flag = extract_clean_flag(orig_name)[cite: 3]
            
            new_name = f"{flag} {tag} Сервер {index}"[cite: 3]
            return f"{main_part}#{urllib.parse.quote(new_name)}"[cite: 3]
        except:
            return link[cite: 3]
            
    return link[cite: 3]

def main():
    print("🚀 Запуск парсера с поддержкой Base64 вывода...")[cite: 3]
    
    wl_raw = fetch_links_parallel('sources_wl.txt')[cite: 3]
    bl_raw = fetch_links_parallel('sources_bl.txt')[cite: 3]

    print(f"📥 Из WL скачано сырых строк: {len(wl_raw)}")[cite: 3]
    print(f"📥 Из BL скачано сырых строк: {len(bl_raw)}")[cite: 3]

    wl_clean = clean_and_dedup(wl_raw)[cite: 3]
    bl_clean = clean_and_dedup(bl_raw)[cite: 3]

    print(f"🧹 После удаления дубликатов: WL = {len(wl_clean)}, BL = {len(bl_clean)}")[cite: 3]

    real_wl = list(wl_clean)[cite: 3]
    real_bl = [][cite: 3]

    wl_identities = set()[cite: 3]
    for link in real_wl:[cite: 3]
        identity = get_config_identity(link)[cite: 3]
        if identity:[cite: 3]
            wl_identities.add(identity)[cite: 3]

    for link in bl_clean:[cite: 3]
        identity = get_config_identity(link)[cite: 3]
        if identity and identity in wl_identities:[cite: 3]
            continue[cite: 3]
        
        if is_ru_sni(link):[cite: 3]
            real_wl.append(link)[cite: 3]
            if identity:[cite: 3]
                wl_identities.add(identity)[cite: 3]
        else:
            real_bl.append(link)[cite: 3]

    print(f"⚡️ Начинаем проверку {len(real_wl)} уникальных конфигов для БС и {len(real_bl)} для ЧС...")[cite: 3]
    
    alive_wl = [][cite: 3]
    alive_bl = [][cite: 3]

    with ThreadPoolExecutor(max_workers=80) as executor:[cite: 3]
        wl_futures = [executor.submit(check_proxy_alive, link) for link in real_wl][cite: 3]
        for future in as_completed(wl_futures):[cite: 3]
            res = future.result()[cite: 3]
            if res: alive_wl.append(res)[cite: 3]
            
        bl_futures = [executor.submit(check_proxy_alive, link) for link in real_bl][cite: 3]
        for future in as_completed(bl_futures):[cite: 3]
            res = future.result()[cite: 3]
            if res: alive_bl.append(res)[cite: 3]

    print(f"📈 Найдено живых серверов: БС (WL) = {len(alive_wl)}, ЧС (BL) = {len(alive_bl)}")[cite: 3]

    final_wl = [rename_config(link, idx, "[WL]") for idx, link in enumerate(alive_wl, 1)][cite: 3]
    final_bl = [rename_config(link, idx, "[BL]") for idx, link in enumerate(alive_bl, 1)][cite: 3]
    final_full = final_wl + final_bl[cite: 3]

    # Кодируем результаты в BASE64 для совместимости со всеми клиентами
    wl_b64 = base64.b64encode('\n'.join(final_wl).encode('utf-8')).decode('utf-8') if final_wl else ""[cite: 3]
    bl_b64 = base64.b64encode('\n'.join(final_bl).encode('utf-8')).decode('utf-8') if final_bl else ""[cite: 3]
    full_b64 = base64.b64encode('\n'.join(final_full).encode('utf-8')).decode('utf-8') if final_full else ""[cite: 3]

    with open('alive_bs.txt', 'w', encoding='utf-8') as f:[cite: 3]
        f.write(wl_b64)[cite: 3]
        
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:[cite: 3]
        f.write(bl_b64)[cite: 3]
        
    with open('alive_full.txt', 'w', encoding='utf-8') as f:[cite: 3]
        f.write(full_b64)[cite: 3]

    print(f"\n📊 Успешно сохранено и закодировано в Base64:")[cite: 3]
    print(f"🛡️ Только БС (alive_bs.txt) — {len(final_wl)} серверов")[cite: 3]
    print(f"🛑 Только ЧС (alive_bl.txt) — {len(final_bl)} серверов")[cite: 3]
    print(f"🌍 Полный список (alive_full.txt) — {len(final_full)} серверов")[cite: 3]

if __name__ == '__main__':
    main()[cite: 3]
