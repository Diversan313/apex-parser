import urllib.request
import urllib.parse
import re
import base64
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

success_count = 0
fail_count = 0

# 🔴 СЮДА ДУБЛИРУЕМ ТВОИ VIP-ПОДПИСКИ ИЗ ВОРКЕРА ДЛЯ УМНОЙ СОРТИРОВКИ
VIP_URLS = [
    "https://mifa.world/vless",
    "https://sub.aska.lol/Ux7lmK0xkIl2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
]

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
        if '127.0.0.1' in link or 'localhost' in link: 
            continue
        
        core = link.split('#')[0]
        if core not in unique:
            unique.add(core)
            valid_links.append(link)
    return valid_links

def filter_by_protocol_priority(links, max_total):
    """Умный фильтр: разделяет по протоколам и жестко душит трояны/ss до 5%"""
    vless_hy = []
    trojan_ss = []
    
    for link in links:
        if link.startswith(('vless://', 'hysteria2://', 'hy2://', 'vmess://')):
            vless_hy.append(link)
        elif link.startswith(('trojan://', 'ss://')):
            trojan_ss.append(link)
            
    # Перемешиваем обе кучи независимо
    random.shuffle(vless_hy)
    random.shuffle(trojan_ss)
    
    # Считаем лимит для шлака (5% от общей свободной квоты)
    trojan_limit = int(max_total * 0.05)
    
    # Собираем пачку: берем чуток троянов, а всё остальное место забиваем VLESS/Hysteria
    allowed_trojan_ss = trojan_ss[:trojan_limit]
    remaining_slots = max_total - len(allowed_trojan_ss)
    
    return vless_hy[:remaining_slots] + allowed_trojan_ss

def main():
    global success_count, fail_count
    print("🚀 Начинаем сбор источников с жестким приоритетом на VLESS/Hysteria...")
    
    # Скачиваем VIP подписки
    print("💎 Скачиваем неприкасаемые VIP подписки...")
    vip_raw = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_single_url, url) for url in VIP_URLS]
        for future in as_completed(futures):
            vip_raw.extend(future.result())
    vip_clean = clean_and_dedup(vip_raw)
    vip_cores = {link.split('#')[0] for link in vip_clean}
    
    # Качаем обычные базы
    full_raw = fetch_links_parallel('sources_full.txt')
    bs_raw = fetch_links_parallel('sources_bs.txt')

    full_clean = clean_and_dedup(full_raw)
    bs_clean = clean_and_dedup(bs_raw)

    full_clean = [l for l in full_clean if l.split('#')[0] not in vip_cores]
    bs_clean = [l for l in bs_clean if l.split('#')[0] not in vip_cores]

    # Сортируем .ru из общей массы в Белый Список (BS)
    for link in full_clean:
        if is_ru_sni(link) and link.split('#')[0] not in vip_cores:
            bs_clean.append(link)
            
    bs_clean = clean_and_dedup(bs_clean)

    # Высчитываем сколько мест осталось до 3000
    free_slots_full = max(0, 3000 - len(vip_clean))
    free_slots_bs = max(0, 3000 - len(vip_clean))

    # Фильтруем с приоритетом протоколов
    random_full = filter_by_protocol_priority(full_clean, free_slots_full)
    random_bs = filter_by_protocol_priority(bs_clean, free_slots_bs)

    # Собираем финальные пачки
    final_full = vip_clean + random_full
    final_bs = vip_clean + random_bs

    # На всякий случай еще раз перемешаем именно вырезанную случайную часть, чтобы они шли вперемешку
    # (но VIP останутся в начале или будут разбавлены)
    
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_full))
        
    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_bs))

    print("\n📊 ИТОГИ УМНОЙ ФИЛЬТРАЦИИ ПО ПРОТОКОЛАМ:")
    print(f"✅ Успешно скачано источников: {success_count}")
    print(f"💎 Всего в FULL (VIP + Топ-протоколы): {len(final_full)}")
    print(f"🛡️ Всего в Белом Списке BS (VIP + Топ-протоколы): {len(final_bs)}")

if __name__ == '__main__':
    main()
