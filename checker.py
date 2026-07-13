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
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/vfarid/v2ray-worker-sub/main/sub/shadowrocket",
    "https://raw.githubusercontent.com/Alvin9999/new-pac/master/v2ray/sub"
]

LIMIT_WL_BL = 500 
LIMIT_MIXED = 750  
LIMIT_FULL = 2000  # Поднимаем планку для Мега-подписки
CONCURRENT_LIMIT = 500 

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
    line_low = line.lower()
    sni_targets = []
    
    sni_match = re.search(r'[?&](sni|host)=([^&#\s]+)', line_low)
    if sni_match:
        sni_targets.append(urllib.parse.unquote(sni_match.group(2)))
        
    if line.startswith("vmess://"):
        try:
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            if data.get('sni'): sni_targets.append(str(data['sni']).lower())
            if data.get('host'): sni_targets.append(str(data['host']).lower())
        except: pass
        
    for sni in sni_targets:
        sni = sni.strip().split(':')[0]
        if not sni: continue
        if sni.endswith('.ru') or any(wl_sni in sni for wl_sni in SPECIFIC_WL_SNI):
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

def rebuild_line_with_name(line, new_name):
    if line.startswith(("vless://", "ss://", "trojan://")):
        return f"{line.split('#')[0]}#{urllib.parse.quote(new_name)}"
    elif line.startswith("vmess://"):
        try:
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            data['ps'] = new_name
            return "vmess://" + encode_base64(json.dumps(data))
        except: pass
    return line

async def main():
    print("ApexParser: Сбор всех доступных баз...")
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

    print(f"Запуск TCP-теста для {len(tasks)} уникальных нод...")
    results = await asyncio.gather(*tasks)
    alive_nodes = [res for res in results if res is not None]
    
    print(f"Живых портов: {len(alive_nodes)}. Запуск GeoIP...")
    nodes_with_geo = await get_real_countries(alive_nodes)
    nodes_with_geo.sort(key=lambda x: x["latency"])

    wl_configs = []
    bl_configs = []
    mixed_configs = []
    full_configs = []

    wl_counter = 1
    bl_counter = 1
    mix_counter = 1
    fl_counter = 1

    for node in nodes_with_geo:
        line = node["line"]
        source = node["source"]
        cc = node["country_code"]
        flag = get_emoji_flag(cc)
        ms = node["latency"]
        orig_name = get_original_name(line).lower()
        
        is_wl = ("/wl/" in source) or \
                any(tag in orig_name for tag in ['wl', 'whitelist', 'бс', 'вл', 'белый']) or \
                is_wl_by_sni(line)

        # 1. Формируем списки БС и ЧС отдельно
        if is_wl:
            name_wl = f"[БС] {flag} {cc} · {ms}ms · №{wl_counter}"
            wl_configs.append(rebuild_line_with_name(line, name_wl))
            wl_counter += 1
        else:
            name_bl = f"[ЧС] {flag} {cc} · {ms}ms · №{bl_counter}"
            bl_configs.append(rebuild_line_with_name(line, name_bl))
            bl_counter += 1

        # 2. Формируем MIX подписку (ограниченная пачка)
        name_mix = f"[MIX] {flag} {cc} · {ms}ms · №{mix_counter}"
        mixed_configs.append(rebuild_line_with_name(line, name_mix))
        mix_counter += 1

        # 3. Формируем МЕГА-ПОДПИСКУ [FL] (вообще всё подряд без ограничений)
        name_fl = f"[FL] {flag} {cc} · {ms}ms · №{fl_counter}"
        full_configs.append(rebuild_line_with_name(line, name_fl))
        fl_counter += 1

    top_wl = wl_configs[:LIMIT_WL_BL]
    top_bl = bl_configs[:LIMIT_WL_BL]
    top_mixed = mixed_configs[:LIMIT_MIXED]
    top_full = full_configs[:LIMIT_FULL]

    with open("alive_bs.txt", "w") as f: f.write(encode_base64("\n".join(top_wl)))
    with open("alive_cs.txt", "w") as f: f.write(encode_base64("\n".join(top_bl)))
    with open("alive_mixed.txt", "w") as f: f.write(encode_base64("\n".join(top_mixed)))
    with open("alive_full.txt", "w") as f: f.write(encode_base64("\n".join(top_full)))

    print(f"Успех! БС: {len(top_wl)}, ЧС: {len(top_bl)}, MIX: {len(top_mixed)}, FL (Фулл): {len(top_full)}")

if __name__ == "__main__":
    asyncio.run(main())
