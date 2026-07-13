import urllib.request
import urllib.parse
import re

def fetch_links(url_file):
    links = []
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        content = response.read().decode('utf-8')
                        # Если это base64 (нет явных протоколов в тексте)
                        if 'vless://' not in content and 'vmess://' not in content:
                            import base64
                            try:
                                content = base64.b64decode(content).decode('utf-8')
                            except:
                                pass
                        links.extend([l.strip() for l in content.split('\n') if l.strip()])
                except Exception as e:
                    print(f"Ошибка загрузки {url}: {e}")
    except FileNotFoundError:
        print(f"Файл {url_file} не найден. Пропускаем.")
    return links

def is_ru_sni(link):
    # Простая регулярка для поиска sni=*.ru или sni=*.su
    match = re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link.lower())
    return bool(match)

def clean_and_dedup(links):
    unique = set()
    valid_links = []
    for link in links:
        # Пропускаем совсем мусор и локалхосты
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://')): continue
        if '127.0.0.1' in link or 'localhost' in link: continue
        
        # Отсекаем старое имя (#) для проверки уникальности 
        core = link.split('#')[0]
        if core not in unique:
            unique.add(core)
            valid_links.append(link)
    return valid_links

def main():
    print("Собираем источники...")
    full_raw = fetch_links('sources_full.txt')
    bs_raw = fetch_links('sources_bs.txt')

    final_full = []
    final_bs = []

    # 1. Все проверенные BS-источники идут и в BS, и в Full
    final_bs.extend(bs_raw)
    final_full.extend(bs_raw)

    # 2. Обрабатываем общую мусорку
    for link in full_raw:
        final_full.append(link)
        # Умный фильтр: если нашли .ru в общем списке, забираем его в BS
        if is_ru_sni(link):
            final_bs.append(link)

    # Очистка и удаление дублей
    final_full = clean_and_dedup(final_full)
    final_bs = clean_and_dedup(final_bs)

    # Сохраняем результаты
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_full))
        
    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_bs))

    print(f"Готово! Собрано для FULL: {len(final_full)}, для BS: {len(final_bs)}")

if __name__ == '__main__':
    main()
