import asyncio
import base64
import json
import urllib.parse
import time
import re
import aiohttp

URLS = [
    "https://mifa.world/vless",
    "https://sub.aska.lol/Ux7lmK0xkIl2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
]

LIMIT_PER_SUB = 250 
CONCURRENT_LIMIT = 500 

# Твой эксклюзивный список рабочих SNI, которые не на .ru
SPECIFIC_WL_SNI = [
    'first.eurocast.work', 
    's76276.cdn.ngenix.net', 
    'third.spaniolo.site', 
    'gate.esimpson.org'
]

def decode_base64(data):
    try:
        normalized = data.replace('-', '+').replace('_', '/').replace(b'\s', b'').strip()
        while len(normalized) % 4: normalized += b'='
        return base64.b64decode(normalized).decode('utf-8', errors='ignore')
    except:
        return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data)

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def get_emoji_flag(country_code):
    if not country_code or len(country_code) != 2: return "🌐"
    try: return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except: return "🌐"

def get_original_name(line):
    try:
        if line.startswith(("vless://", "trojan://", "ss://")):
            parts = line.split('#')
            if len(parts) > 1: return urllib.parse.unquote(parts[1].strip())
        elif line.startswith("vmess://"):
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            return data.get('ps', '')
    except: pass
    return ""

def is_wl_by_sni(line):
    """Вытаскивает SNI/Host и проверяет по твоему правилу .ru + секретный список"""
    line_low = line.lower()
    sni_targets = []
    
    # Извлекаем sni или host из параметров VLESS/Trojan/SS
    sni_match = re.search(r'[?&](sni|host)=([^&#\s]+)', line_low)
    if sni_match:
        sni_targets.append(urllib.parse.unquote(sni_match.group(2)))
        
    # Извлекаем из VMess
    if line.startswith("vmess://"):
        try:
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            if data.get('sni'): sni_targets.append(str(data['sni']).lower())
            if data.get('host'): sni_targets.append(str(data['host']).lower())
        except: pass
        
    # Проверяем цели
    for sni in sni_targets:
        sni = sni.strip().split(':')[0] # отсекаем порт, если он есть
        if not sni: continue
        
        # Правило 1: Любой домен на .ru — это железно БС
        if sni.endswith('.ru'):
            return True
            
        # Правило 2: Совпадение со скрытыми доменами из твоего списка
        if any(wl_sni in sni for wl_sni in SPECIFIC_WL_SNI):
            return True
            
    return False

def parse_proxy(line):
    try:
        if line.startswith(("vless://", "trojan://", "ss://")):
            parts = line.split("@")
            if len(parts) < 2: return None
            target = parts[1].split("?")[0].split("#")[0]
            if ":" in target:
                ip, port = target.split(":")
                return ip, int(port), line
        elif line.startswith("vmess://"):
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            return data.get('add'), int(data.get('port')), line
    except: pass
    return None

async def check_server(semaphore, ip, port, line, source_url, timeout=2.5):
    async with semaphore:
        start_time = time.time()
        try:
            coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(coro, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            latency = int((time.time() - start_time) * 1000)
            return {"ip": ip, "port": port, "line": line, "source": source_url, "latency": latency}
        except:
            return None

async def get_real_countries(nodes):
    if not nodes: return nodes
    ips = [node["ip"] for node in nodes]
    chunks = [ips[i:i + 100] for i in range(0, len(ips), 100)]
    ip_to_country = {}
    
    async with aiohttp.ClientSession() as session:
        for chunk in chunks:
            try:
                async with session.post("http://ip-api.com/batch?fields=status,countryCode,query", json=chunk) as resp:
                    if resp.status == 200:
                        results = await resp.json()
                        for res in results:
                            if res.get("status") == "success":
                                ip_to_country[res["query"]] = res["countryCode"]
            except: pass
            await asyncio.sleep(0.4)

    for node in nodes:
        node["country_code"] = ip_to_country.get(node["ip"], "GL")
    return nodes

async def main():
    print("ApexParser: Сканирование всемирной сети...")
    all_tasks_data = []
    
    async with aiohttp.ClientSession() as session:
        for url in URLS:
            try:
                async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as resp:
                    raw_data = await resp.read()
                    text = decode_base64(raw_data)
                    for line in text.splitlines():
                        line = line.strip()
                        if not line: continue
                        if any(x in line.lower() for x in ['t.me', 'tg://', 'хуй', 'бля', 'еба', 'пизд']): continue
                        all_tasks_data.append((line, url))
            except Exception as e:
                print(f"Ошибка загрузки базы {url}: {e}")

    tasks = []
    seen = set()
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    
    for line, url in all_tasks_data:
        parsed = parse_proxy(line)
        if parsed:
            ip, port, original_line = parsed
            if f"{ip}:{port}" not in seen:
                seen.add(f"{ip}:{port}")
                tasks.append(check_server(semaphore, ip, port, original_line, url))

    print(f"Уникальных серверов на тесте: {len(tasks)}...")
    results = await asyncio.gather(*tasks)
    alive_nodes = [res for res in results if res is not None]
    
    print(f"Ответило серверов: {len(alive_nodes)}. Сбор GeoIP локаций...")
    nodes_with_geo = await get_real_countries(alive_nodes)

    # Сортировка по пингу (быстрые — первые)
    nodes_with_geo.sort(key=lambda x: x["latency"])

    wl_configs = []
    bl_configs = []
    mixed_configs = []

    wl_counter = 1
    bl_counter = 1
    mix_counter = 1

    for node in nodes_with_geo:
        line = node["line"]
        source = node["source"]
        cc = node["country_code"]
        flag = get_emoji_flag(cc)
        ms = node["latency"]

        orig_name = get_original_name(line).lower()
        
        # ФИНАЛЬНАЯ СВЕРХТОЧНАЯ ЛОГИКА ДЛЯ БС:
        is_wl = ("/wl/" in source) or \
                any(tag in orig_name for tag in ['wl', 'whitelist', 'бс', 'вл', 'белый']) or \
                is_wl_by_sni(line)

        # Твои новые названия тегов для v2rayNG
        tag = "БС / WL" if is_wl else "ЧС / BL"
        idx = wl_counter if is_wl else bl_counter

        new_name = f"[{tag}] {flag} {cc} · {ms}ms · №{idx}"
        
        renamed_line = line
        if line.startswith(("vless://", "ss://", "trojan://")):
            renamed_line = f"{line.split('#')[0]}#{urllib.parse.quote(new_name)}"
        elif line.startswith("vmess://"):
            try:
                raw = line.replace("vmess://", "").strip()
                data = json.loads(decode_base64(raw.encode()))
                data['ps'] = new_name
                renamed_line = "vmess://" + encode_base64(json.dumps(data))
            except: pass

        if is_wl:
            wl_configs.append(renamed_line)
            wl_counter += 1
        else:
            bl_configs.append(renamed_line)
            bl_counter += 1

        # Обычная смешанная подписка (MIX)
        mix_name = f"[Обычная / MIX] {flag} {cc} · {ms}ms · №{mix_counter}"
        mixed_line = line
        if line.startswith(("vless://", "ss://", "trojan://")):
            mixed_line = f"{line.split('#')[0]}#{urllib.parse.quote(mix_name)}"
        elif line.startswith("vmess://"):
            try:
                raw = line.replace("vmess://", "").strip()
                data = json.loads(decode_base64(raw.encode()))
                data['ps'] = mix_name
                mixed_line = "vmess://" + encode_base64(json.dumps(data))
            except: pass
        mixed_configs.append(mixed_line)
        mix_counter += 1

    # Нарезка лучших по лимитам
    top_wl = wl_configs[:LIMIT_PER_SUB]
    top_bl = bl_configs[:LIMIT_PER_SUB]
    top_mixed = mixed_configs[:300]

    with open("alive_bs.txt", "w") as f: f.write(encode_base64("\n".join(top_wl)))
    with open("alive_cs.txt", "w") as f: f.write(encode_base64("\n".join(top_bl)))
    with open("alive_mixed.txt", "w") as f: f.write(encode_base64("\n".join(top_mixed)))

    print(f"Сборка ApexParser завершена! БС (WL): {len(top_wl)}, ЧС (BL): {len(top_bl)}, MIX: {len(top_mixed)}")

if __name__ == "__main__":
    asyncio.run(main())
