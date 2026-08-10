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
                urls = re.findall(r'https?://[^\s]+', message.text)
                for url in urls:
                    if keyword in url:
                        return url
    except Exception as e:
        print(f"⚠️ Ошибка при чтении {chat} (топик {topic_id}): {e}")
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
            new_lines.append(line) # Сохраняем сам тег
            
            # Если под тегом пустая строка или старая ссылка - заменяем/вставляем новую
            if i + 1 < len(lines):
                next_line = lines[i+1]
                if next_line.strip() == "" or not next_line.strip().startswith("#"):
                    # Заменяем старую ссылку или пустоту на новую ссылку
                    new_lines.append(f"{new_url}\n")
                    i += 2
                else:
                    # Если под тегом сразу другой коммент, просто вставляем ссылку
                    new_lines.append(f"{new_url}\n")
                    i += 1
            else:
                # Если тег в самом конце файла, просто дописываем ссылку
                new_lines.append(f"{new_url}\n")
                i += 1
            
            updated = True
            continue
        else:
            new_lines.append(line)
            i += 1

    # Если тега в файле вообще не было, добавляем его и ссылку в конец
    if not tag_found:
        if new_lines and not new_lines[-1].endswith('\n'):
            new_lines.append('\n')
        new_lines.append(f"{tag_line}\n")
        new_lines.append(f"{new_url}\n")
        updated = True

    with open(target_file, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    if updated:
        print(f"🔄 В {target_file} ссылка под тегом {tag_line} обновлена на {new_url}")
    else:
        print(f"❌ Не удалось обновить {target_file} для {tag_line}")

async def main():
    if not SESSION_STRING:
        print("⚠️ Переменная TG_SESSION_STRING не задана. Обновление отменено.")
        return

    if not os.path.exists(CONFIG_FILE):
        print(f"⚠️ Файл {CONFIG_FILE} не найден. Нечего обновлять.")
        return

    print("🕵️ Подключаемся к Telegram...")
    async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        for config in configs:
            parts = config.split()
            if len(parts) < 4:
                print(f"❌ Неверный формат: {config}. Нужно 4 параметра.")
                continue
            
            topic_link = parts[0]
            target_list = parts[1].upper()
            tag = parts[2]
            keyword = parts[3]
            
            tag_line = f"# TG:{tag}"
            target_file = f"sources_{target_list.lower()}.txt"

            match = re.search(r't\.me/([a-zA-Z0-9_]+)/(\d+)', topic_link)
            if not match:
                print(f"❌ Не удалось извлечь канал и топик из: {topic_link}")
                continue
            
            chat = match.group(1)
            topic_id = int(match.group(2))

            print(f"🔎 Ищем ссылку со словом '{keyword}' в {chat} (топик {topic_id})...")
            new_url = await get_latest_link(client, chat, topic_id, keyword)
            
            if new_url:
                print(f"✅ Найдено: {new_url}")
                update_source_file(target_file, tag_line, new_url)
            else:
                print(f"❌ Ссылка со словом '{keyword}' не найдена в последних сообщениях.")

if __name__ == "__main__":
    asyncio.run(main())
