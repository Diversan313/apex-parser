import os
import re
import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession

# Берем секреты из переменных окружения
API_ID = int(os.environ.get('TG_API_ID', 0))
API_HASH = os.environ.get('TG_API_HASH', '')
SESSION_STRING = os.environ.get('TG_SESSION_STRING', '')

CONFIG_FILE = 'sources_tg.txt'

async def get_latest_link(client, chat, topic_id, keyword):
    try:
        async for message in client.iter_messages(chat, reply_to=topic_id, limit=5):
            if message and message.text:
                # Ищем все ссылки в сообщении
                urls = re.findall(r'https?://[^\s]+', message.text)
                for url in urls:
                    # Очищаем ссылку от форматирования Telegram (кавычки, звездочки и т.д.)
                    clean_url = url.strip('`*~_|>)]}')
                    if keyword in clean_url:
                        return clean_url
    except Exception as e:
        # Логируем без указания каналов и топиков
        print(f"warn: tg: чтение источника: {e}")
    return None

def update_source_file(target_file, tag_line, new_url):
    lines = []
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

    tag_found = False
    updated = False
    new_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        if line.strip() == tag_line:
            tag_found = True
            new_lines.append(line)
            
            if i + 1 < len(lines):
                next_line = lines[i+1]
                if next_line.strip() == "" or not next_line.strip().startswith("#"):
                    new_lines.append(f"{new_url}\n")
                    i += 2
                else:
                    new_lines.append(f"{new_url}\n")
                    i += 1
            else:
                new_lines.append(f"{new_url}\n")
                i += 1
            
            updated = True
            continue
        else:
            new_lines.append(line)
            i += 1

    if not tag_found:
        if new_lines and not new_lines[-1].endswith('\n'):
            new_lines.append('\n')
        new_lines.append(f"{tag_line}\n")
        new_lines.append(f"{new_url}\n")
        updated = True

    with open(target_file, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    # Логируем без указания файла и самой ссылки
    if updated:
        print("tg: файл источников обновлён")
    else:
        print("warn: tg: файл источников не обновлён")

async def main():
    try:
        from apex.config import (
            ENABLE_TG_SOURCES,
            SPLIT_SOURCES,
            SECURE_SOURCES_GITHUB,
            SOURCES_DIR,
        )
        if not ENABLE_TG_SOURCES:
            return
    except ImportError:
        # модуль запущен вне пакета apex — ориентируемся только на env:
        # прежнее поведение с раздельными sources_wl/bl
        SPLIT_SOURCES = True
        SECURE_SOURCES_GITHUB = True
        SOURCES_DIR = ""

    if not SESSION_STRING:
        print("warn: tg: TG_SESSION_STRING не задан, обновление пропущено")
        return

    if not os.path.exists(CONFIG_FILE):
        print("warn: tg: конфиг не найден, нечего обновлять")
        return

    # база путей — та же, по которой основной прогон ищет файлы источников
    base = "" if SECURE_SOURCES_GITHUB else SOURCES_DIR

    async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        for config in configs:
            parts = config.split()
            if len(parts) < 4:
                print("warn: tg: неверный формат в конфиге, пропущено")
                continue

            topic_link = parts[0]
            target_list = parts[1].upper()
            tag = parts[2]
            keyword = parts[3]

            tag_line = f"# TG:{tag}"
            if SPLIT_SOURCES:
                target_file = os.path.join(base, f"sources_{target_list.lower()}.txt")
            else:
                # общий пул прогонов: метка и ссылка должны лежать в нём,
                # иначе свежие TG-ссылки в прогон не попадают
                target_file = os.path.join(base, "sources.txt")

            match = re.search(r't\.me/([a-zA-Z0-9_]+)/(\d+)', topic_link)
            if not match:
                print("warn: tg: ссылка из конфига не разобрана, пропущено")
                continue
            
            chat = match.group(1)
            topic_id = int(match.group(2))

            # Скрываем, что именно мы ищем и где
            new_url = await get_latest_link(client, chat, topic_id, keyword)
            
            if new_url:
                print("tg: свежая ссылка найдена")
                update_source_file(target_file, tag_line, new_url)
            else:
                print("tg: свежая ссылка не найдена")

if __name__ == "__main__":
    asyncio.run(main())
