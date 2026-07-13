import asyncio
import base64
import json
import urllib.parse
import time
import re
import aiohttp
from collections import defaultdict

URLS = [
    "https://mifa.world/vless",
    "https://sub.aska.lol/Ux7lmK0xkIl2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/vfarid/v2ray-worker-sub/main/sub/shadowrocket",
    "https://raw.githubusercontent.com/Alvin9999/new-pac/master/v2ray/sub",
    "https://raw.githubusercontent.com/Borders-freedom/freedom/master/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/LonUp/NodeList/main/Active/All.txt",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/Distribute/v2ray.txt"
]

LIMIT_WL_BL = 1000 
LIMIT_MIXED = 1500  
LIMIT_FULL = 4000  # Поднимаем лимит для полной базы
CONCURRENT_LIMIT = 300 

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

async def check_server_group(semaphore, ip, port, nodes_list, timeout=3.0):
    async with semaphore:
        start_time = time.time()
        try:
            coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(coro, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            latency = int((time.time() - start_time) * 1000)
            return {"ip": ip, "port": port, "nodes": nodes_list, "latency": latency}
        except:
            return None

async def get_real_countries(groups):
    if not groups: return groups
    ips = [g["ip"] for g in groups]
    chunks = [ips[i:i + 100] for i in range(0, len(ips), 100)]
    ip_to_country = {}
    
    async with aiohttp.ClientSession() as session:
        for chunk in chunks:
            try:
                async with session.post("http://ip-api.com/batch?fields=status,countryCode,query", json=chunk, timeout=5) as resp:
                    if resp.status == 200:
                        results = await resp.json()
                        if isinstance(results, list):
                            for res in results:
                                if isinstance(res, dict) and res.get("status") == "success":
                                    ip_to_country[res["query"]] = res["countryCode"]
            except:
                pass
            await asyncio.sleep(0.4)

    for g in groups:
        g["country_code"] = ip_to_country.get(g["ip"], "GL")
    return groups

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
    print("ApexParser: Сканирование мега-сборников...")
    all_tasks_data = []
    
    async with aiohttp.ClientSession() as session:
        for url in URLS:
            try:
                async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10) as resp:
                    raw_data = await resp.read()
                    text = decode_base64(raw_data)
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or len(line) < 10: continue
                        if any(x in line.lower() for x in ['t.me', 'tg://', 'хуй', 'бля', 'еба', 'пизд']): continue
                        all_tasks_data.append((line, url))
            except:
                print(f"Пропуск базы: {url}")

    # Группируем по IP и Порту, чтобы не терять уникальные UUID и SNI
    ip_port_groups = defaultdict(list)
    unique_lines_check = set()
    
    for line, url in all_tasks_data:
        parsed = parse_proxy(line)
        if parsed:
            ip, port, original_line = parsed
            # Убираем полные дубликаты строк, но сохраняем разные настройки на одном IP
            if original_line not in unique_lines_check:
                unique_lines_check.add(original_line)
                ip_port_groups[(ip, port)].append((original_line, url))

    tasks = []
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    
    for (ip, port), nodes_list in ip_port_groups.items():
        tasks.append(check_server_group(semaphore, ip, port, nodes_list))

    print(f"Запуск умного TCP-теста для {len(tasks)} серверов...")
    results = await asyncio.gather(*tasks)
    alive_groups = [res for res in results if res is not None]
    
    print(f"Живых серверов найдено: {len(alive_groups)}. Привязываем Гео-локацию...")
    groups_with_geo = await get_real_countries(alive_groups)
    groups_with_geo.sort(key=lambda x: x["latency"])

    wl_configs, bl_configs, mixed_configs, full_configs = [], [], [], []
    wl_c, bl_c, mix_c, fl_c = 1, 1, 1, 1

    for g in groups_with_geo:
        cc = g["country_code"]
        flag = get_emoji_flag(cc)
        ms = g["latency"]
        
        for line, source in g["nodes"]:
            orig_name = get_original_name(line).lower()
            is_wl = ("/wl/" in source) or \
                    any(tag in orig_name for tag in ['wl', 'whitelist', 'бс', 'вл', 'белый']) or \
                    is_wl_by_sni(line)

            if is_wl:
                wl_configs.append(rebuild_line_with_name(line, f"[БС] {flag} {cc} · {ms}ms · №{wl_c}"))
                wl_c += 1
            else:
                bl_configs.append(rebuild_line_with_name(line, f"[ЧС] {flag} {cc} · {ms}ms · №{bl_c}"))
                bl_c += 1

            mixed_configs.append(rebuild_line_with_name(line, f"[MIX] {flag} {cc} · {ms}ms · №{mix_c}"))
            mix_c += 1

            full_configs.append(rebuild_line_with_name(line, f"[FL] {flag} {cc} · {ms}ms · №{fl_c}"))
            fl_c += 1

    top_wl = wl_configs[:LIMIT_WL_BL]
    top_bl = bl_configs[:LIMIT_WL_BL]
    top_mixed = mixed_configs[:LIMIT_MIXED]
    top_full = full_configs[:LIMIT_FULL]

    with open("alive_bs.txt", "w") as f: f.write(encode_base64("\n".join(top_wl)))
    with open("alive_cs.txt", "w") as f: f.write(encode_base64("\n".join(top_bl)))
    with open("alive_mixed.txt", "w") as f: f.write(encode_base64("\n".join(top_mixed)))
    with open("alive_full.txt", "w") as f: f.write(encode_base64("\n".join(top_full)))

    print(f"Готово! Выдано в FL: {len(top_full)} конфигов из всех доступных вариантов.")

if __name__ == "__main__":
    asyncio.run(main())
