import urllib.request
import urllib.parse
import re
import base64
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

success_count = 0
fail_count = 0

VIP_URLS = [
    "https://mifa.world/vless",
    "https://sub.aska.lol/Ux7lmK0xkIl2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
]

def check_tcp(host, port, timeout=2.5):
    """Быстрая проверка доступности IP:PORT сервера"""
    try:
        # Если домен в SNI или адресе содержит явные заглушки, отсекаем сразу
        if any(fake in host.lower() for fake in ['localhost', '127.0.0.1', 'github.com']):
            return False
        
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except:
        return False

def parse_host_port(link):
    """Вытаскивает host и port из различных типов прокси-ссылок"""
    try:
        # Убираем имя сервера для чистоты парсинга
        clean_link = link.split('#')[0]
        
        if clean_link.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            # Формат: протокол://uuid@host:port?параметры
            content = clean_link.split('://')[1]
            server_part = content.split('?')[0]
            if '@' in server_part:
                server_part = server_part.split('@')[1]
            
            # Обработка IPv6 адресов [2001:...]:port
            if server_part.startswith('['):
                host = server_part.split(']')[0] + ']'
                port = server_part.split(']:')[1]
            else:
                host, port = server_part.split(':')
            return host, int(port)
            
        elif clean_link.startswith('vmess://'):
            # Vmess зашит в base64
            b64_data = clean_link.replace('vmess://', '').strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            import json
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            return data.get('add'), int(data.get('port'))
    except:
        pass
    return None, None

def check_proxy_alive(link):
    """Парсит ссылку и проверяет, живой ли сервер"""
    host, port = parse_host_port(link)
    if host and port:
        if check_tcp(host, port):
            return link
    return None

def fetch_single_url(url):
    global success_count, fail_count
    try:
        url = url.strip().replace(' ', '%20')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req, timeout=5) as response:
            raw_data = response.read()
            try:
                content = raw_data.decode('utf-8', errors='ignore')
            except:
                content = raw_data.decode('latin-1', errors='ignore')
            
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    b64_str = content.strip().replace('-', '+').replace('_', '/')
                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                        content = decoded
                except:
                    pass
            
            success_count += 1
            return [l.strip() for l in content.split('\n') if l.strip()]
    except:
        fail_count += 1
        return []

def fetch_links_parallel(url_file):
    links = []
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures):
                links.extend(future.result())
    except FileNotFoundError:
        print(f"Файл {url_file} не найден.")
    return links

def is_ru_sni(link):
    match = re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link.lower())
    return bool(match)

def clean_and_dedup(links):
    unique = set()
    valid_links = []
    for link in links:
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')): 
            continue
        
        core = link.split('#')[0]
        if core not in unique:
            unique.add(core)
            valid_links.append(link)
    return valid_links

def filter_by_protocol_priority(links, max_total):
    vless_hy = []
    trojan_ss = []
    
    for link in links:
        if link.startswith(('vless://', 'hysteria2://', 'hy2://', 'vmess://')):
            vless_hy.append(link)
        elif link.startswith(('trojan://', 'ss://')):
            trojan_ss.append(link)
            
    random.shuffle(vless_hy)
    random.shuffle(trojan_ss)
    
    trojan_limit = int(max_total * 0.05)
    allowed_trojan_ss = trojan_ss[:trojan_limit]
    remaining_slots = max_total - len(allowed_trojan_ss)
    
    return vless_hy[:remaining_slots] + allowed_trojan_ss

def main():
    global success_count, fail_count
    print("🚀 Сбор источников и жесткая валидация портов (TCP-Check)...")
    
    # VIP-подписки качаем и добавляем СРАЗУ (их порты не пингуем, чтобы не замедлять и не терять их)
    vip_raw = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_single_url, url) for url in VIP_URLS]
        for future in as_completed(futures):
            vip_raw.extend(future.result())
    vip_clean = clean_and_dedup(vip_raw)
    vip_cores = {link.split('#')[0] for link in vip_clean}
    
    # Сбор обычных баз
    full_raw = fetch_links_parallel('sources_full.txt')
    bs_raw = fetch_links_parallel('sources_bs.txt')

    full_clean = clean_and_dedup(full_raw)
    bs_clean = clean_and_dedup(bs_raw)

    # Исключаем VIP из общего пула проверки
    full_clean = [l for l in full_clean if l.split('#')[0] not in vip_cores]
    bs_clean = [l for l in bs_clean if l.split('#')[0] not in vip_cores]

    # Сортировка по SNI до чека
    for link in full_clean:
        if is_ru_sni(link) and link.split('#')[0] not in vip_cores:
            bs_clean.append(link)
    bs_clean = clean_and_dedup(bs_clean)

    # Приоритет протоколов (сначала отбираем потенциально лучшие, чтобы не пинговать лишние трояны)
    pre_filtered_full = filter_by_protocol_priority(full_clean, 15000)
    pre_filtered_bs = filter_by_protocol_priority(bs_clean, 15000)

    # ⚡️ ПАРАЛЛЕЛЬНЫЙ TCP ЧЕК (100 потоков) для обычных серверов
    print("⚡️ Проверяем порты серверов на доступность...")
    alive_full_pool = []
    alive_bs_pool = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        # Проверяем FULL
        full_futures = [executor.submit(check_proxy_alive, link) for link in pre_filtered_full]
        for future in as_completed(full_futures):
            res = future.result()
            if res: alive_full_pool.append(res)
            
        # Проверяем BS
        bs_futures = [executor.submit(check_proxy_alive, link) for link in pre_filtered_bs]
        for future in as_completed(bs_futures):
            res = future.result()
            if res: alive_bs_pool.append(res)

    # Ограничиваем финальный размер до 3000 (VIP на первом месте)
    free_slots_full = max(0, 3000 - len(vip_clean))
    free_slots_bs = max(0, 3000 - len(vip_clean))

    final_full = vip_clean + alive_full_pool[:free_slots_full]
    final_bs = vip_clean + alive_bs_pool[:free_slots_bs]

    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_full))
        
    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_bs))

    print("\n📊 ИТОГИ ВАЛИДАЦИИ:")
    print(f"💎 Всего ЖИВЫХ серверов в FULL: {len(final_full)} (включая VIP)")
    print(f"🛡️ Всего ЖИВЫХ серверов в BS: {len(final_bs)} (включая VIP)")

if __name__ == '__main__':
    main()
