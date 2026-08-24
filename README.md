<div align="center">

# apex-parser

**Warrior of Internet Freedom**

[![Telegram Bot](https://img.shields.io/badge/Telegram_Bot-@Sent1nel0__bot-2CA5E0?style=for-the-badge&logo=telegram)](https://t.me/Sent1nel0_bot)
[![License](https://img.shields.io/badge/Status-FREE_FOR_USE-brightgreen?style=for-the-badge)](#)

---

### 🔗 Ссылки на подписки

</div>

#### 🛡 WhiteList (Белые списки)

**GitHub**
```text
https://raw.githubusercontent.com/Diversan313/apex-parser/main/alive_bs.txt
```

**GitVerse**
```text
https://gitverse.ru/api/repos/bikinitw22/apelsintel/raw/branch/main/alive_bs.txt
```

#### 🌐 BlackList (Wi-Fi)

**GitHub**
```text
https://raw.githubusercontent.com/Diversan313/apex-parser/main/alive_bl.txt
```

**GitVerse**
```text
https://gitverse.ru/api/repos/bikinitw22/apelsintel/raw/branch/main/alive_bl.txt
```

#### 🚀 Full List (All-in-One)

**GitHub**
```text
https://raw.githubusercontent.com/Diversan313/apex-parser/main/alive_full.txt
```

**GitVerse**
```text
https://gitverse.ru/api/repos/bikinitw22/apelsintel/raw/branch/main/alive_full.txt
```

---

## О проекте

**apex-parser** — открытый проект, созданный с нуля для автоматического сбора, фильтрации, проверки и публикации рабочих конфигураций.

Цель проекта — обеспечить стабильный доступ к свободному интернету в условиях ограничений, предоставляя актуальные решения для мобильного интернета (белые списки) и глобального Wi-Fi использования.

Весь код, представленный в данном репозитории (за исключением закрытых уникальных частей проекта в **apex-sources**), полностью открыт для использования, изучения, доработки и распространения.

Это один из немногих проектов, который действительно открыл уникальный код и свои наработки для сообщества. В отличие от большинства аналогичных решений, которые работают исключительно на закрытых машинах авторов, здесь логика доступна каждому.

Проект написан полностью с нуля. Никаких заимствований чужих или готовых решений — только собственная разработка, прошедшая через ошибки и баги, ведущая к постоянным улучшениям, адаптированная под реальные задачи.

### Основные возможности

- Сбор конфигураций из нескольких источников (sources файлы с отобранными источниками, Telegram модуль).
- Разделение на WhiteList (для белых списков) и BlackList (для Wi-Fi использования).
- Проверка живости конфигураций, дедупликация, геофильтрация, ограничение по IP и подсетям для уникальности.
- Автоматическое формирование итоговых списков: `alive_bs.txt`, `alive_bl.txt`, `alive_full.txt`.
- Поддержка как наиболее устойчивых протоколов (например VLESS и Hysteria2), так и других (VMess, Trojan, Shadowsocks и др.).
- Интеграция с Telegram-ботом [@Sent1nel0_bot](https://t.me/Sent1nel0_bot) для удобного доступа, статистики и работы с закрытым apex-sources.

### Проверенные приложения (кроме iOS / macOS)

\* — не рекомендуется

| Клиент | Платформы | Источник для скачивания |
|--------|-----------|-------------------------|
| **Exclave** | Android | [GitHub (Релизы)](https://github.com/dyhkwong/Exclave/releases) |
| **v2rayNG** | Android | [GitHub (Релизы)](https://github.com/2dust/v2rayNG/releases) |
| **v2rayN** | Windows, macOS, Linux | [GitHub (Релизы)](https://github.com/2dust/v2rayN/releases) |
| **INCY** | Android, iOS, macOS | [GitHub](https://github.com/INCY-DEV/incy-platforms) |
| **Karing** | Android, iOS, Windows, macOS, Linux | [Официальный сайт](https://karing.app) · [GitHub](https://github.com/KaringX/karing) |
| **Streisand** | iOS, macOS | [App Store](https://apps.apple.com/app/streisand/id6450534064) |
| **V2Box** | Android, iOS, macOS | [App Store](https://apps.apple.com/app/v2box-v2ray-client/id6446814690) · [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |
| **Throne** | Windows, Linux, macOS | [GitHub](https://github.com/throneproj/Throne) |
| **NekoBox** * | Android, Windows, Linux | [GitHub Android](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) · [GitHub Desktop](https://github.com/qr243vbi/nekobox) |
| **Hiddify** * | Android, iOS, Windows, macOS, Linux | [Официальный сайт](https://hiddify.com) · [GitHub](https://github.com/hiddify/hiddify-app) |

### Что и для чего?

- `parser.py` — основной открытый код парсера.
- `parser_tg.py` — модуль обновления источников через Telegram.
- `white_ip.txt` — список белых IP-адресов для белых списков.
- `alive_*.txt` — публикуемые готовые списки рабочих конфигураций.
- `arch/` — архив, вспомогательные данные.
- `.github/workflows/` — автоматизация обновлений.

Весь этот код можно свободно использовать, модифицировать и запускать у себя.

Если вы разработчик и хотите подробнее разобрать логику и правила работы, то вам в [Инструкция и логика](https://github.com/Diversan313/apex-parser/wiki/%D0%98%D0%BD%D1%81%D1%82%D1%80%D1%83%D0%BA%D1%86%D0%B8%D1%8F-%D0%B8-%D0%BB%D0%BE%D0%B3%D0%B8%D0%BA%D0%B0).


### Закрытый репозиторий apex-sources

Для стабильной и защищённой работы основной логики используется закрытый репозиторий **apex-sources**.  
Он содержит уникальные части бэкенда, которые намеренно не публикуются в открытом доступе.

Ключевые файлы и их назначение:

- **sources_wl.txt** — перечень источников для WhiteList (белые списки). Источники, оптимизированные под мобильный интернет.
- **sources_bl.txt** — перечень источников для BlackList (Wi-Fi). Источники, используемые для Wi-Fi с зарубежными локациями.
- **sources_tg.txt** — конфигурация Telegram-источников. Указывает, из каких топиков и каналов автоматически подтягиваются свежие ссылки.
- **incoming_sources.txt** / **incoming_subs.txt** — файлы для работы и связи бота с apex-sources.

Остальные файлы в закрытом репозитории носят вспомогательный характер (резервные копии, временные данные) и иногда могут использоваться как среда для тестирования.  
Основная публичная логика и готовые результаты всегда находятся в открытом репозитории **apex-parser**.

Закрытый репозиторий обеспечивает защиту уникальных источников и настроек, при этом результаты работы регулярно публикуются в открытый доступ.

### Лицензия и использование (MIT)

Код открытого репозитория доступен свободно по лицензии **MIT**.  
Вы можете использовать его в личных и коммерческих целях, дорабатывать, запускать на своих серверах и делиться улучшениями.  
Уникальные части бэкенда (закрытый репозиторий) остаются приватными и не предназначены для публичного распространения.

### Спасибо

Благодарность проектам, инструментам и источникам, которые используются или вдохновили **apex-parser**:

- [Xray-core (Project X)](https://github.com/XTLS/Xray-core) — ядро для проверки живости конфигураций
- [ip-api.com](https://ip-api.com/), [ip.sb](https://ip.sb/), [ip2location.io](https://www.ip2location.io/) — онлайн GeoIP-сервисы
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) / [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) — оффлайн база GeoIP
- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — SNI-список для мобильного интернета
- [RKP_bypass_configs](https://github.com/RKPchannel/RKP_bypass_configs) (RKP)
- [zieng2/wl](https://github.com/zieng2/wl) (zieng)
- [goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs) (Avencores)
- [MIFA](https://t.me/mifa_world)

---

*Проект создан и поддерживается в интересах свободы интернета. Код написан с нуля, через собственные ошибки и решения. Если вы используете или дорабатываете проект — будет приятно узнать об этом.*
