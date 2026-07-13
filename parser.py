import urllib.request
import urllib.parse
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# Глобальные счетчики для красивой статистики
success_count = 0
fail_count = 0

def fetch_single_url(url):
    global success_count, fail_count
    try:
        # Чистим пробелы в ссылке, если они случайно затесались
        url = url.strip().replace(' ', '%20')
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req, timeout=5) as response:
            # Читаем с игнорированием кривых символов в кодировке
            raw_data = response.read()
            
            # Пробуем декодировать аккуратно
            try:
                content = raw_data.decode('utf-8', errors='ignore')
            except:
                content = raw_data.decode('latin-1', errors='ignore')
            
            # Проверяем на Base64
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://']):
                try:
                    b64_str = content.strip().replace('-', '+').replace('_', '/')
                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://']):
                        content = decoded
                except:
                    pass
            
            success_count += 1
            return [l.strip() for l in content.split('\n') if l.strip()]
    except:
        # Полный саунд-дизайн: никаких принтов ошибок в консоль
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
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://')): 
            continue
        if '127.0.0.1' in link or 'localhost' in link: 
            continue
        
        core = link.split('#')[0]
        if core not in unique:
            unique.add(core)
            valid_links.append(link)
    return valid_links

def main():
    global success_count, fail_count
    print("🚀 Начинаем умную фильтрацию базы подписок...")
    
    full_raw = fetch_links_parallel('sources_full.txt')
    bs_raw = fetch_links_parallel('sources_bs.txt')

    final_full = []
    final_bs = []

    final_bs.extend(bs_raw)
    final_full.extend(bs_raw)

    for link in full_raw:
        final_full.append(link)
        if is_ru_sni(link):
            final_bs.append(link)

    final_full = clean_and_dedup(final_full)
    final_bs = clean_and_dedup(final_bs)

    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_full))
        
    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_bs))

    print("\n📊 ИТОГИ РАБОТЫ ПАРСЕРА:")
    print(f"✅ Успешно скачано источников: {success_count}")
    print(f"❌ Сдохло/заблокировано источников: {fail_count}")
    print(f"💎 Уникальных серверов в FULL списке: {len(final_full)}")
    print(f"🛡️ Уникальных серверов в Белом Списке (BS): {len(final_bs)}")

if __name__ == '__main__':
    main()
