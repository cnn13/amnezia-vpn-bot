# amnezia-vpn-bot

Самохостимый VPN на базе **AmneziaWG** с умным Telegram-ботом для админа и семьи.

## Что внутри

| Компонент | Назначение |
|---|---|
| **AmneziaWG** (ставится через Amnezia-клиент) | VPN-протокол с обфускацией, пробивает TSPU DPI |
| **Telegram-бот** | Админ управляет пирами из бота; родственники пишут боту — после одобрения получают готовые .conf с инструкциями под их устройство |
| **AdGuard Home** | Блок рекламы и трекеров через DNS; работает прозрачно для всех VPN-клиентов |
| **RU-обход** на уровне `AllowedIPs` | Российские сайты (Яндекс, Сбер, Госуслуги) идут мимо VPN — не ловят капчу, видят ваш реальный IP |
| **Monitoring + alerts** | Крон следит за сервером, пишет вам в TG если что-то упало; оповещает юзеров когда VPN лежит/поднялся |
| **Автоудаление** | Пиры без handshake 30+ дней удаляются автоматом с уведомлением юзера |
| **Детектор тяжёлого трафика** | Если юзер качает >2 ГБ за 10 мин — мягкое напоминание не грузить VPN |

## Установка на свежий VPS (Ubuntu 24.04)

```bash
sudo apt install -y git
git clone https://github.com/YOU/amnezia-vpn-bot /opt/amnezia-vpn-bot
cd /opt/amnezia-vpn-bot
sudo bash install.sh
```

Установщик спросит:
1. **Telegram bot token** — создаётся у [@BotFather](https://t.me/BotFather) командой `/newbot`
2. **Admin Telegram ID** — ваш ID из [@userinfobot](https://t.me/userinfobot)
3. **Public IP** — автоопределится

Затем он сам поставит Docker, модуль ядра `amneziawg-dkms`, Python-зависимости, бот, крон, AdGuard Home, hardening (UFW, fail2ban, auto-updates).

### Шаг 2: Подключить AmneziaVPN клиент

- На ПК открыть **AmneziaVPN** → «Добавить сервер» → ввести IP сервера + root/пароль → выбрать протокол **AmneziaWG** → установить.
- Клиент сам создаст контейнер `amnezia-awg2` и выдаст вам первый .conf.

### Шаг 3: Повторный запуск установщика

```bash
sudo bash /opt/amnezia-vpn-bot/install.sh
```

Второй запуск увидит контейнер Amnezia и:
- Переподключит AdGuard в его network namespace
- Добавит alias IP `10.8.1.254` на `awg0`
- Поставит DNAT iptables чтобы весь DNS шёл в AdGuard

Готово. Бот активен, родные могут писать `@your_bot_name` → жать «Хочу VPN» → ваш бот присылает вам запрос на одобрение.

## Миграция на другой сервер

На старом сервере:
```bash
sudo tar czf /tmp/awgbot-backup.tgz \
    /etc/awgbot \
    /opt/awgbot/*.json \
    /opt/awgbot/ru_bypass*.txt \
    /opt/adguard/conf \
    /opt/adguard/work
# scp /tmp/awgbot-backup.tgz newserver:/tmp/
```

Внутри Amnezia-контейнера:
```bash
docker exec amnezia-awg2 tar czf /tmp/awg-state.tgz /opt/amnezia/awg
docker cp amnezia-awg2:/tmp/awg-state.tgz /tmp/
# scp /tmp/awg-state.tgz newserver:/tmp/
```

На новом сервере — повторите установку сверху, а на шаге «Подключить AmneziaVPN клиент» вместо нового протокола:
1. Распакуйте бэкапы в правильные места:
```bash
sudo tar xzf /tmp/awgbot-backup.tgz -C /
```
2. Пересоберите все .conf клиентам с новым Endpoint — быстрый способ в боте: при следующем «Скачать конфиг» юзеру отдастся .conf уже с новым IP (т.к. `SERVER_IP` в config.env новый).

Всем родным разошлите «📣 Сообщение всем» в стиле «VPN переехал, скачайте новый конфиг кнопкой 📥 Мои конфиги в боте».

## Структура файлов

```
amnezia-vpn-bot/
├── install.sh                      — установщик
├── config.example.env              — шаблон /etc/awgbot/config.env
├── bot/
│   ├── bot.py                      — основной бот (многопользовательский с модерацией)
│   └── requirements.txt
├── scripts/
│   ├── alerts.sh                   — мониторинг → алерты в TG
│   ├── broadcast.py                — бродкаст всем юзерам при VPN down
│   ├── cleanup_abandoned.py        — удаление забытых пиров (30+ дней)
│   ├── traffic_watch.py            — детектор тяжёлого трафика
│   ├── healthcheck.sh              — поднимает awg0 если упал
│   ├── rkn_notify.sh               — раз в 2 дня — проверка блок РКН
│   ├── update_rulist.py            — обновление полного списка RU-подсетей
│   └── update_mobile_rulist.py     — компактный список для мобилок
├── systemd/
│   ├── awgbot.service              — сам бот
│   ├── awg0-alias.service          — добавляет 10.8.1.254 alias
│   └── awg-dns-redirect.service    — iptables DNAT 53→AdGuard
├── adguard/
│   └── AdGuardHome.yaml.template   — конфиг с 5 фильтр-листами из коробки
└── cron/
    └── awg-crons                   — крон-таблица
```

## Нет в репе (gitignored)

- `/etc/awgbot/config.env` — секреты
- `/opt/awgbot/*.json` — state (ключи пиров, запросы, баны)
- Приватные ключи, .conf файлы

## Полезные команды на сервере

```bash
systemctl status awgbot              # статус бота
journalctl -u awgbot -f              # логи бота в реалтайме
docker logs adguardhome -f           # логи AdGuard
docker exec amnezia-awg2 wg show awg0  # кто подключён, трафик
/usr/local/bin/awg-cleanup.py --dry-run  # посмотреть кого удалит (TBD)
```
