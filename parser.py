import urllib.request
import urllib.parse
import re
import base64
import random
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Регулярка для вытаскивания флагов стран (эмодзи) и других смайликов
EMOJI_REGEX = re.compile(
    r'[\U0001F1E6-\U0001F1FF]{2}|'  # Флаги стран
    r'[\u2600-\u27BF]|'             # Различные символы
    r'[\U0001F300-\U0001F5FF]|'     # Пиктограммы
    r'[\U0001F600-\U0001F64F]|'     # Смайлики
    r'[\U0001F680-\U0001F6FF]|'     # Транспорт/карты
    r'[\U0001F900-\U0001F9FF]|'     # Доп. символы
    r'[\U0001FA70-\U0001FAFF]'      # Новые эмодзи
)

def extract_emojis(text):
    if not text:
        return ""
    return "".join(EMOJI_REGEX.findall(text)).strip()

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
            
            if not any(p in content for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://']):
                try:
                    b64_str = content.strip().replace('-', '+').replace('_', '/')
                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
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
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(fetch_single_url, url): url for url in urls}
            for future in as_completed(futures): links.extend(future.result())
    except FileNotFoundError:
        print(f"⚠️ Файл {url_file} не найден!")
    return links

def is_ru_sni(link):
    """Глубокая проверка на наличие .ru / .su в SNI или хосте"""
    link_low = link.lower()
    # 1. Ищем sni= в параметрах строки
    if bool(re.search(r'sni=[^&]*\.(ru|su)(?:&|$)', link_low)):
        return True
    # 2. Если это VMess, парсим JSON внутри Base64
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
        # 3. Для остальных проверяем основной хост/порт
        host, _ = parse_host_port(link)
        if host:
            host_low = host.lower()
            if host_low.endswith(('.ru', '.su')) or '.ru]' in host_low or '.su]' in host_low:
                return True
    return False

def clean_and_dedup(links):
    unique = set()
    valid_links = []
    for link in links:
        if not link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')): continue
        core = link.split('#')[0]
        if core not in unique:
            unique.add(core)
            valid_links.append(link)
    return valid_links

def rename_config(link, index, tag):
    """Переименовывает конфиг: вытаскивает флаг страны и вешает тег [WL] или [BL]"""
    if link.startswith("vmess://"):
        try:
            b64_data = link.replace("vmess://", "").strip()
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            
            orig_name = data.get('ps', '')
            emojis = extract_emojis(orig_name)
            prefix = f"{emojis} " if emojis else "🌐 "
            
            data['ps'] = f"{prefix}{tag} Сервер {index}"
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            return link
            
    if "://" in link:
        try:
            parts = link.split('#', 1)
            main_part = parts[0]
            orig_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            emojis = extract_emojis(orig_name)
            prefix = f"{emojis} " if emojis else "🌐 "
            
            new_name = f"{prefix}{tag} Сервер {index}"
            return f"{main_part}#{urllib.parse.quote(new_name)}"
        except:
            return link
            
    return link

def main():
    print("🚀 Запуск точечного парсера (WL / BL с авто-сортировкой)...")
    
    # Шаг 1. Собираем пулы из файлов
    wl_raw = fetch_links_parallel('sources_wl.txt')
    bl_raw = fetch_links_parallel('sources_bl.txt')

    wl_clean = clean_and_dedup(wl_raw)
    bl_clean = clean_and_dedup(bl_raw)

    # Шаг 2. Умное распределение: если в ЧС затесался .ru/.su SNI, переносим в БС (WL)
    real_wl = list(wl_clean)
    real_bl = []

    wl_cores = {link.split('#')[0] for link in real_wl}

    for link in bl_clean:
        core = link.split('#')[0]
        if core in wl_cores:
            continue  # Пропускаем дубликат, если он уже есть в БС
        
        if is_ru_sni(link):
            real_wl.append(link)
            wl_cores.add(core)
        else:
            real_bl.append(link)

    # Шаг 3. Проверяем порты на доступность
    print(f"⚡️ Проверяем {len(real_wl)} конфигов из БС (WL) и {len(real_bl)} из ЧС (BL)...")
    
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

    # Шаг 4. Красиво переименовываем с сохранением оригинальных эмодзи/флагов
    final_wl = [rename_config(link, idx, "[WL]") for idx, link in enumerate(alive_wl, 1)]
    final_bl = [rename_config(link, idx, "[BL]") for idx, link in enumerate(alive_bl, 1)]

    # Шаг 5. Записываем файлы на выход
    # 1. alive_bs.txt — строго Белый Список (WL)
    with open('alive_bs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_wl))
        
    # 2. alive_bl.txt — строго Черный Список (BL)
    with open('alive_bl.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_bl))
        
    # 3. alive_full.txt — Полный список (сначала все WL, потом все BL)
    final_full = final_wl + final_bl
    with open('alive_full.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_full))

    print(f"\n📊 Успешно сохранено три подписки:")
    print(f"🛡️ Только БС (alive_bs.txt): {len(final_wl)} серверов [WL]")
    print(f"🛑 Только ЧС (alive_bl.txt): {len(final_bl)} серверов [BL]")
    print(f"🌍 Полный список (alive_full.txt): {len(final_full)} серверов")

if __name__ == '__main__':
    main()
