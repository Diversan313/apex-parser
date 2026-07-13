import asyncio
import base64
import json
import urllib.parse
import re
import aiohttp

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

LIMIT_WL_BL = 600 
LIMIT_MIXED = 800  
# Для FULL убираем ограничения совсем (ставим заведомо огромное число)
LIMIT_FULL = 999999  

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

def extract_just_flag(text):
    # Ищем оригинальный флаг-эмодзи (пары региональных индикаторов юникода A-Z)
    flags = re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', text)
    if flags:
        return flags[0]
    # Если флага-страны нет, но есть глобус
    if "🌐" in text: 
        return "🌐"
    return "🌐"

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

def rebuild_line_with_name(line, new_name):
    if line.startswith(("vless://", "ss://", "trojan://")):
        base = line.split('#')[0]
        return f"{base}#{new_name}"
    elif line.startswith("vmess://"):
        try:
            raw = line.replace("vmess://", "").strip()
            data = json.loads(decode_base64(raw.encode()))
            data['ps'] = new_name
            # Убираем пробелы из json структуры vmess, чтобы строгие парсеры не ругались
            return "vmess://" + encode_base64(json.dumps(data, separators=(',', ':')))
        except: pass
    return line

async def main():
    print("ApexParser: Сбор всех баз...")
    unique_lines = []
    seen_lines = set()
    
    async with aiohttp.ClientSession() as session:
        for url in URLS:
            try:
                async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=12) as resp:
                    raw_data = await resp.read()
                    text = decode_base64(raw_data)
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or len(line) < 15: continue
                        if any(x in line.lower() for x in ['t.me', 'tg://', 'хуй', 'бля', 'еба', 'пизд']): continue
                        
                        if line not in seen_lines:
                            seen_lines.add(line)
                            unique_lines.append((line, url))
            except:
                pass

    wl_configs, bl_configs, mixed_configs, full_configs = [], [], [], []
    wl_c, bl_c, mix_c, fl_c = 1, 1, 1, 1

    for line, source in unique_lines:
        orig_name = get_original_name(line)
        flag = extract_just_flag(orig_name)

        is_wl = ("/wl/" in source) or \
                any(tag in orig_name.lower() for tag in ['wl', 'whitelist', 'бс', 'вл', 'белый']) or \
                is_wl_by_sni(line)

        # Создаем ультра-безопасные имена БЕЗ пробелов и спецсимволов, чтобы парсер Throne не спотыкался
        if is_wl:
            wl_configs.append(rebuild_line_with_name(line, f"[БС]{flag}№{wl_c}"))
            wl_c += 1
        else:
            bl_configs.append(rebuild_line_with_name(line, f"[ЧС]{flag}№{bl_c}"))
            bl_c += 1

        mixed_configs.append(rebuild_line_with_name(line, f"[MIX]{flag}№{mix_c}"))
        mix_c += 1

        full_configs.append(rebuild_line_with_name(line, f"[FL]{flag}№{fl_c}"))
        fl_c += 1

    with open("alive_bs.txt", "w") as f: f.write(encode_base64("\n".join(wl_configs[:LIMIT_WL_BL])))
    with open("alive_cs.txt", "w") as f: f.write(encode_base64("\n".join(bl_configs[:LIMIT_WL_BL])))
    with open("alive_mixed.txt", "w") as f: f.write(encode_base64("\n".join(mixed_configs[:LIMIT_MIXED])))
    # Сюда улетает абсолютно ВСЁ без лимитов
    with open("alive_full.txt", "w") as f: f.write(encode_base64("\n".join(full_configs[:LIMIT_FULL])))

    print(f"Парсинг окончен. Всего в FULL ушло: {len(full_configs)} конфигов.")

if __name__ == "__main__":
    asyncio.run(main())
