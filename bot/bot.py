#!/usr/bin/env python3
# AmneziaWG Telegram bot — in-container config mode
import os, re, io, json, base64, subprocess, tempfile, datetime as dt, urllib.request, urllib.parse, time, html, logging
import telebot
from telebot import types
import qrcode

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("awgbot")

def esc(s):
    """HTML-escape user-provided string for safe injection into parse_mode=HTML messages."""
    return html.escape(str(s or ""), quote=False)

# Config via environment (set in /etc/awgbot/config.env, loaded by systemd)
BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = [int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()]
SERVER_IP = os.environ["SERVER_IP"]
ADGUARD_USER = os.getenv("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ["ADGUARD_PASS"]
AWG_DIR_IN_CT = os.getenv("AWG_DIR_IN_CT", "/opt/amnezia/awg")
AWG_CONF = f"{AWG_DIR_IN_CT}/awg0.conf"
CLIENTS_TABLE = f"{AWG_DIR_IN_CT}/clientsTable"
PSK_FILE = f"{AWG_DIR_IN_CT}/wireguard_psk.key"
SRV_PUB = f"{AWG_DIR_IN_CT}/wireguard_server_public_key.key"
DNS = os.getenv("CLIENT_DNS", "10.8.1.254")   # awg0 alias → AdGuard
ADGUARD_URL = os.getenv("ADGUARD_URL", "http://127.0.0.1:3000")

# auto-discover container and port at runtime
def discover_container():
    r = subprocess.run(["docker","ps","--format","{{.Names}}"], capture_output=True, timeout=5)
    for n in r.stdout.decode().split():
        if n.startswith("amnezia-awg"): return n
    return None

def discover_port():
    ct = discover_container()
    if not ct: return None
    r = subprocess.run(["docker","exec",ct,"wg","show","awg0","listen-port"], capture_output=True, timeout=5)
    try: return int(r.stdout.decode().strip())
    except: return None

def _ct_name():
    n = discover_container()
    if not n: raise RuntimeError("Amnezia-контейнер не найден. Поставьте AmneziaWG через клиент.")
    return n

def _port():
    p = discover_port()
    if not p: raise RuntimeError("Порт не определён (контейнер есть, но awg0 не поднят?)")
    return p

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

def is_admin(uid): return uid in ADMIN_IDS

# ---------- auto-clean helpers (in-memory, non-admin chats only) ----------
_last_bot_msg = {}  # chat_id -> message_id of last ephemeral bot msg

def try_del(chat_id, message_id):
    try: bot.delete_message(chat_id, message_id)
    except Exception: pass

def send_eph(chat_id, text, reply_markup=None, **kw):
    """Send an ephemeral message that replaces the previous one in this chat."""
    old = _last_bot_msg.pop(chat_id, None)
    if old: try_del(chat_id, old)
    m = bot.send_message(chat_id, text, reply_markup=reply_markup, **kw)
    _last_bot_msg[chat_id] = m.message_id
    return m

def clear_eph(chat_id):
    old = _last_bot_msg.pop(chat_id, None)
    if old: try_del(chat_id, old)

def eat_user_msg(m):
    """Delete the user's own message that triggered this handler (keeps chat clean)."""
    if is_admin(m.from_user.id): return
    try_del(m.chat.id, m.message_id)

# ---------------- docker exec helpers ----------------
def dx(cmd, input_bytes=None, timeout=30):
    full = ["docker", "exec", "-i", _ct_name(), "sh", "-c", cmd]
    r = subprocess.run(full, input=input_bytes, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr

def read_ct(path):
    rc, out, err = dx(f"cat {path}")
    if rc != 0: raise RuntimeError(f"read {path}: {err.decode(errors='replace')}")
    return out.decode()

def write_ct(path, content):
    # safe write via tee
    rc, out, err = dx(f"tee {path} >/dev/null", input_bytes=content.encode())
    if rc != 0: raise RuntimeError(f"write {path}: {err.decode(errors='replace')}")

def gen_keypair():
    rc, priv, err = dx("wg genkey")
    if rc != 0: raise RuntimeError(err.decode())
    priv = priv.decode().strip()
    rc, pub, err = dx(f"echo {priv} | wg pubkey")
    if rc != 0: raise RuntimeError(err.decode())
    return priv, pub.decode().strip()

def server_pubkey():
    return read_ct(SRV_PUB).strip()

def psk():
    return read_ct(PSK_FILE).strip()

def amnezia_params():
    """Return client-side obfuscation params from server awg0.conf [Interface].
    Only reads ACTIVE (uncommented) lines — commented params aren't applied to live wg."""
    conf = read_ct(AWG_CONF)
    iface, _, _ = conf.partition("[Peer]")
    want = ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4",
            "I1","I2","I3","I4","I5",
            "HeaderProtectionKey",
            "RekeyAfterTime","RekeyTimeout","RejectAfterTime",
            "KeepaliveTimeout","MaxHandshakeAttempts",
            "RandomTrailers","DisableCookies")
    out = {}
    for line in iface.splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue  # skip comments/empty
        m = re.match(r"([A-Za-z0-9]+)\s*=\s*(.+?)\s*$", s)
        if not m: continue
        k, v = m.group(1), m.group(2)
        if k in want:
            out[k] = v
    return out

def read_clients():
    try:
        return json.loads(read_ct(CLIENTS_TABLE))
    except Exception:
        return []

def write_clients(data):
    write_ct(CLIENTS_TABLE, json.dumps(data, indent=4))

def find_free_ip(conf, taken):
    used = set(taken)
    for ln in conf.splitlines():
        m = re.match(r"\s*AllowedIPs\s*=\s*10\.8\.1\.(\d+)/32", ln)
        if m: used.add(int(m.group(1)))
    for i in range(2, 254):
        if i not in used:
            return i
    raise RuntimeError("no free IPs")

def add_peer(name):
    priv, pub = gen_keypair()
    conf = read_ct(AWG_CONF)
    clients = read_clients()
    taken = []
    for c in clients:
        ip = c.get("userData",{}).get("allowed_ips","")
        m = re.match(r"10\.8\.1\.(\d+)/32", ip)
        if m: taken.append(int(m.group(1)))
    octet = find_free_ip(conf, taken)
    ip = f"10.8.1.{octet}/32"
    psk_val = psk()
    peer_block = f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk_val}\nAllowedIPs = {ip}\n"
    write_ct(AWG_CONF, conf.rstrip()+"\n"+peer_block)
    clients.append({
        "clientId": pub,
        "userData": {
            "allowed_ips": ip,
            "clientName": name,
            "creationDate": dt.datetime.utcnow().strftime("%a %b %d %H:%M:%S %Y"),
        },
    })
    write_clients(clients)
    # live-add to kernel interface
    dx(f"echo {psk_val} > /tmp/psk && awg set awg0 peer {pub} preshared-key /tmp/psk allowed-ips {ip} && rm -f /tmp/psk")
    # store priv so bot can re-send conf later
    privs = load_privs()
    privs[pub] = {"priv": priv, "address": ip, "name": name}
    save_privs(privs)
    return priv, pub, ip

def remove_peer(pub):
    conf = read_ct(AWG_CONF)
    parts = conf.split("[Peer]")
    head = parts[0]
    kept = []
    for p in parts[1:]:
        if f"PublicKey = {pub}" in p: continue
        kept.append("[Peer]"+p)
    write_ct(AWG_CONF, head+"".join(kept))
    clients = [c for c in read_clients() if c.get("clientId") != pub]
    write_clients(clients)
    # live-remove from kernel interface
    dx(f"awg set awg0 peer {pub} remove")
    # drop stored priv
    privs = load_privs()
    privs.pop(pub, None)
    save_privs(privs)

def wg_show():
    rc, out, err = dx("wg show awg0 dump")
    if rc != 0: return []
    rows = []
    lines = out.decode().strip().splitlines()
    if not lines: return rows
    # first line: iface, following: peers
    for ln in lines[1:]:
        f = ln.split("\t")
        if len(f) < 5: continue
        pub, psk_, endpoint, allowed, last_hs = f[0], f[1], f[2], f[3], int(f[4])
        rx = int(f[5]) if len(f)>5 else 0
        tx = int(f[6]) if len(f)>6 else 0
        rows.append({"pub":pub,"endpoint":endpoint,"allowed":allowed,"last_hs":last_hs,"rx":rx,"tx":tx})
    return rows

RU_BYPASS_FILE = "/opt/awgbot/ru_bypass_allowed.txt"
RU_BYPASS_MOBILE_FILE = "/opt/awgbot/ru_bypass_mobile.txt"
PRIV_STORE = "/opt/awgbot/peer_privs.json"
PENDING_FILE = "/opt/awgbot/pending.json"
BANS_FILE = "/opt/awgbot/bans.json"
USER_PEERS_FILE = "/opt/awgbot/user_peers.json"  # user_id -> [pub, pub, ...]
MAX_CONFIGS_PER_REQUEST = 5
MAX_CONFIGS_TOTAL_PER_USER = 10

def load_bans():
    try:
        with open(BANS_FILE) as f: return json.load(f)
    except Exception: return {}

def save_bans(data):
    with open(BANS_FILE, "w") as f: json.dump(data, f, indent=2)

def is_banned(uid):
    bans = load_bans()
    rec = bans.get(str(uid))
    if not rec: return False
    until = rec.get("until", 0)
    if until == 0: return True  # permanent
    if time.time() < until: return True
    # expired — remove
    bans.pop(str(uid), None)
    save_bans(bans)
    return False

def load_user_peers():
    try:
        with open(USER_PEERS_FILE) as f: return json.load(f)
    except Exception: return {}

def save_user_peers(data):
    with open(USER_PEERS_FILE, "w") as f: json.dump(data, f, indent=2)

def user_has_pending(uid):
    pending = load_pending()
    return any(r.get("user_id")==uid and r.get("status")=="pending" for r in pending.values())

INSTRUCTIONS_IPHONE = (
    "<b>📱 Как подключить VPN на iPhone</b>\n\n"
    "<b>1.</b> Поставь <b>AmneziaVPN</b> из App Store.\n\n"
    "<b>2. Импортировать конфиг (самый простой способ):</b>\n"
    "• Открой этот чат с ботом в Telegram\n"
    "• Нажми на присланный файл <code>.conf</code>\n"
    "• «Поделиться» → «Открыть в AmneziaVPN»\n"
    "• «Импорт» → «Подключить»\n\n"
    "<b>Если первый способ не сработал:</b>\n"
    "• Открой AmneziaVPN → «+» внизу\n"
    "• «Файл конфигурации»\n"
    "• Выбери файл в «Файлах» → «Импорт»\n\n"
    "Если несколько конфигов — <b>каждый на своё устройство</b>. "
    "Один конфиг на двух устройствах одновременно не работает."
)
INSTRUCTIONS_ANDROID = (
    "<b>🤖 Как подключить VPN на Android</b>\n\n"
    "<b>1. Поставь AmneziaVPN</b>\n"
    "Качай APK с официального GitHub:\n"
    "<a href=\"https://github.com/amnezia-vpn/amnezia-client/releases\">github.com/amnezia-vpn/amnezia-client/releases</a>\n\n"
    "• Открой ссылку в браузере телефона\n"
    "• В самом верхнем релизе → «Assets» → файл <code>…android.apk</code>\n"
    "• Скачай → открой через «Загрузки»\n"
    "• Если спросит «Разрешить установку из этого источника» → настройки → "
    "включи для браузера → «Установить»\n\n"
    "<b>2. Импортировать конфиг:</b>\n"
    "• Открой этот чат, нажми на файл <code>.conf</code>\n"
    "• «Открыть через…» → «AmneziaVPN»\n"
    "• «Импорт» → «Подключить»\n\n"
    "Если несколько конфигов — каждый на своё устройство."
)
INSTRUCTIONS_WIN = (
    "<b>💻 Как подключить VPN на Windows</b>\n\n"
    "<b>1.</b> Скачай AmneziaVPN с <b>amnezia.org</b> (есть установщик для Windows).\n\n"
    "<b>2. Импортировать конфиг:</b>\n"
    "• Сохрани файл <code>.conf</code> на компьютер (например в Загрузки)\n"
    "• Открой AmneziaVPN\n"
    "• «<b>+</b>» снизу → «<b>Файл конфигурации</b>»\n"
    "• Выбери <code>.conf</code> → «Импорт»\n"
    "• «Подключить»\n\n"
    "⚠️ <b>На Windows:</b> если «подключается» бесконечно — "
    "закрой AmneziaVPN, выйди из любого другого VPN (Happ, "
    "торрент-клиент с VPN и т.д.), попробуй снова."
)
INSTRUCTIONS_MAC = (
    "<b>🖥 Как подключить VPN на Mac</b>\n\n"
    "<b>1.</b> Скачай AmneziaVPN с <b>amnezia.org</b> (есть .dmg для Mac).\n\n"
    "<b>2. Импортировать конфиг:</b>\n"
    "• Открой AmneziaVPN\n"
    "• «<b>+</b>» снизу → «<b>Файл конфигурации</b>»\n"
    "• Выбери <code>.conf</code> → «Импорт»\n"
    "• «Подключить»\n\n"
    "Если Mac попросит разрешение в Системных настройках → разреши."
)

def instructions_for(device):
    return {
        "iphone": INSTRUCTIONS_IPHONE,
        "android": INSTRUCTIONS_ANDROID,
        "win": INSTRUCTIONS_WIN,
        "mac": INSTRUCTIONS_MAC,
    }.get(device, INSTRUCTIONS)

INSTRUCTIONS = (
    "<b>📱 Как подключить VPN</b>\n\n"
    "<b>1. Поставь приложение AmneziaVPN</b>\n"
    "• iPhone — в App Store (ищи «AmneziaVPN»)\n"
    "• Windows / Mac / Linux — скачать с <b>amnezia.org</b>\n"
    "• <b>Android</b> — скачай APK с официального GitHub:\n"
    "  <a href=\"https://github.com/amnezia-vpn/amnezia-client/releases\">github.com/amnezia-vpn/amnezia-client/releases</a>\n\n"
    "<b>Как скачать и поставить APK (Android):</b>\n"
    "• Открой ссылку выше в браузере телефона\n"
    "• В самом первом (верхнем) релизе найди файл с названием "
    "типа <code>AmneziaVPN-X.Y.Z-android.apk</code> (нажми «Assets» если скрыто)\n"
    "• Нажми на имя файла — скачается в «Загрузки»\n"
    "• Открой «Загрузки», нажми на apk\n"
    "• Если Android спросит «Разрешить установку из этого источника» — "
    "жми «Настройки» → включи переключатель для браузера → назад → «Установить»\n"
    "• Готово, иконка AmneziaVPN в меню\n\n"
    "<b>2. Импортируй .conf файл одним из способов:</b>\n"
    "<b>Способ А (легче, если .conf прислали в телеге):</b>\n"
    "• Открой этот чат с ботом\n"
    "• Нажми на присланный файл .conf\n"
    "• Выбери «Открыть в AmneziaVPN»\n"
    "• Жми «Импорт» → «Подключить»\n\n"
    "<b>Способ Б (все платформы):</b>\n"
    "• Сохрани файл .conf в телефон/комп\n"
    "• Открой AmneziaVPN\n"
    "• Жми «<b>+</b>» (или «Добавить сервер») внизу\n"
    "• Выбери «<b>Файл конфигурации</b>» / «Config file»\n"
    "• Найди свой .conf файл → открой\n"
    "• Готово — жми «Подключить»\n\n"
    "<b>3. Если прислали несколько файлов</b> — это <b>на разные устройства</b> "
    "(например один на телефон, второй на планшет, третий на ноутбук). "
    "Один .conf = одно устройство. Два устройства на одном .conf параллельно НЕ работают.\n\n"
    "Если что-то не работает — напиши админу."
)

def load_pending():
    try:
        with open(PENDING_FILE) as f: return json.load(f)
    except Exception: return {}

def save_pending(data):
    with open(PENDING_FILE, "w") as f: json.dump(data, f, indent=2)

def load_privs():
    try:
        with open(PRIV_STORE) as f: return json.load(f)
    except Exception: return {}

def save_privs(data):
    with open(PRIV_STORE, "w") as f: json.dump(data, f, indent=2)
    os.chmod(PRIV_STORE, 0o600)

def allowed_ips(mode="full"):
    """mode: 'full' | 'ru_desktop' | 'ru_mobile'"""
    if mode == "ru_desktop":
        try:
            with open(RU_BYPASS_FILE) as f: return f.read().strip()
        except Exception: pass
    elif mode == "ru_mobile":
        try:
            with open(RU_BYPASS_MOBILE_FILE) as f: return f.read().strip()
        except Exception: pass
    return "0.0.0.0/0, ::/0"

def client_conf(priv, ip, mode="full"):
    p = amnezia_params()
    lines = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {ip}",
        f"DNS = {DNS}",
    ]
    # order matches what Amnezia 3.1 writes
    for k in ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4",
              "HeaderProtectionKey",
              "I1","I2","I3","I4","I5",
              "RekeyAfterTime","RekeyTimeout","RejectAfterTime",
              "KeepaliveTimeout","MaxHandshakeAttempts",
              "RandomTrailers","DisableCookies"):
        if k in p: lines.append(f"{k} = {p[k]}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey()}",
        f"PresharedKey = {psk()}",
        f"AllowedIPs = {allowed_ips(mode)}",
        f"Endpoint = {SERVER_IP}:{_port()}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines)+"\n"

def make_qr_png(text):
    img = qrcode.make(text)
    buf = io.BytesIO(); img.save(buf, format="PNG"); buf.seek(0); return buf

# ---------------- HTTP (RKN check) ----------------
def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0", "Accept":"application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

# ---------------- UI ----------------
def menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    kb.row("➕ Юзер (всё в тоннеле)")
    kb.row("💻 Юзер (RU-обход, ПК)","📱 Юзер (RU-обход, моб.)")
    kb.row("📥 Скачать конфиг","➖ Удалить юзера")
    kb.row("📋 Список юзеров","📊 Статистика")
    kb.row("🌍 Проверить блок РКН","⚙️ Статус сервера")
    kb.row("⏸ Пауза AdGuard 5 мин","▶️ Включить AdGuard")
    kb.row("📣 Сообщение всем")
    return kb

def user_menu(uid):
    """Build keyboard for non-admin user based on state."""
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    user_peers = load_user_peers().get(str(uid), [])
    if user_has_pending(uid):
        kb.row("⏳ Запрос в обработке")
    else:
        kb.row("➕ Хочу VPN" if not user_peers else "➕ Хочу ещё VPN")
    if user_peers:
        kb.row("📥 Мои конфиги","❌ Не работает")
    kb.row("ℹ️ Как подключить")
    return kb

@bot.message_handler(commands=["start"])
def cmd_start(m):
    if is_admin(m.from_user.id):
        bot.send_message(m.chat.id, "👋 AmneziaWG бот готов", reply_markup=menu())
        return
    if is_banned(m.from_user.id):
        eat_user_msg(m)
        send_eph(m.chat.id, "⛔ Вы заблокированы администратором.")
        return
    eat_user_msg(m); clear_eph(m.chat.id)
    bot.send_message(m.chat.id,
        "👋 Привет! Это VPN-бот.\n\n"
        "Нужен VPN — жми кнопку ниже. Админ одобрит и бот пришлёт сюда готовый конфиг.",
        reply_markup=user_menu(m.from_user.id))

@bot.message_handler(func=lambda m: m.text in ("➕ Хочу VPN","➕ Хочу ещё VPN") and not is_admin(m.from_user.id))
def cmd_request_start(m):
    eat_user_msg(m)
    if is_banned(m.from_user.id):
        send_eph(m.chat.id, "⛔ Вы заблокированы."); return
    if user_has_pending(m.from_user.id):
        send_eph(m.chat.id, "⏳ Уже есть ожидающий запрос."); return
    user_peers = load_user_peers().get(str(m.from_user.id), [])
    remaining = MAX_CONFIGS_TOTAL_PER_USER - len(user_peers)
    if remaining <= 0:
        send_eph(m.chat.id, f"❌ Лимит: {MAX_CONFIGS_TOTAL_PER_USER} конфигов на человека. У вас уже столько."); return
    # Step 1: ask for device (shapes which .conf mode we'll generate + which instruction to send)
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🍏 iPhone", callback_data="dev:iphone"),
        types.InlineKeyboardButton("🤖 Android", callback_data="dev:android"),
    )
    kb.row(
        types.InlineKeyboardButton("💻 Windows", callback_data="dev:win"),
        types.InlineKeyboardButton("🖥 Mac", callback_data="dev:mac"),
    )
    kb.row(types.InlineKeyboardButton("Разные / не знаю", callback_data="dev:mixed"))
    send_eph(m.chat.id,
        "На каком <b>устройстве</b> будешь пользоваться?\n\n"
        "(нужно чтобы прислать правильный конфиг и инструкцию)",
        reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("dev:"))
def cb_device(c):
    if is_admin(c.from_user.id): return
    if is_banned(c.from_user.id): return
    device = c.data[4:]
    bot.answer_callback_query(c.id)
    user_peers = load_user_peers().get(str(c.from_user.id), [])
    remaining = MAX_CONFIGS_TOTAL_PER_USER - len(user_peers)
    max_now = min(MAX_CONFIGS_PER_REQUEST, remaining)
    kb = types.InlineKeyboardMarkup()
    row = []
    for n in [1,2,3,5]:
        if n > max_now: break
        row.append(types.InlineKeyboardButton(str(n), callback_data=f"wantn:{n}:{device}"))
    kb.row(*row)
    send_eph(c.message.chat.id,
        f"<b>Сколько конфигов нужно?</b>\n\n"
        f"<i>1 конфиг = 1 устройство</i>. Запускать один конфиг на двух устройствах "
        f"одновременно НЕ получится.\n\n"
        f"Максимум {max_now} за раз (у тебя уже {len(user_peers)} из {MAX_CONFIGS_TOTAL_PER_USER}).",
        reply_markup=kb)

@bot.message_handler(func=lambda m: m.text=="ℹ️ Как подключить" and not is_admin(m.from_user.id))
def cmd_howto(m):
    eat_user_msg(m)
    if is_banned(m.from_user.id): return
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🍏 iPhone", callback_data="howto:iphone"),
        types.InlineKeyboardButton("🤖 Android", callback_data="howto:android"),
    )
    kb.row(
        types.InlineKeyboardButton("💻 Windows", callback_data="howto:win"),
        types.InlineKeyboardButton("🖥 Mac", callback_data="howto:mac"),
    )
    send_eph(m.chat.id, "Выбери устройство:", reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("howto:"))
def cb_howto(c):
    if is_admin(c.from_user.id): return
    device = c.data[6:]
    bot.answer_callback_query(c.id)
    send_eph(c.message.chat.id, instructions_for(device), disable_web_page_preview=True)

@bot.message_handler(func=lambda m: m.text=="❌ Не работает" and not is_admin(m.from_user.id))
def cmd_not_working(m):
    eat_user_msg(m)
    if is_banned(m.from_user.id): return
    uid = m.from_user.id
    user_peers = load_user_peers().get(str(uid), [])
    if not user_peers:
        send_eph(m.chat.id, "У тебя нет конфигов. Нажми «Хочу VPN»."); return
    # Check latest handshake across all his peers
    try:
        dump = subprocess.run(["docker","exec",_ct_name(),"wg","show","awg0","dump"],
                              capture_output=True, timeout=10).stdout.decode()
    except Exception as e:
        send_eph(m.chat.id, f"⚠️ Не могу проверить состояние сервера. Напиши админу: он разберётся.\n(детали: {esc(str(e))})")
        _notify_admin_user_broken(m.from_user, user_peers, "server unreachable")
        return
    best_hs = 0
    now = int(time.time())
    for line in dump.strip().splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 5: continue
        pub, hs = f[0], int(f[4])
        if pub in user_peers and hs > best_hs:
            best_hs = hs
    if best_hs == 0:
        txt = ("❌ Ни один из твоих конфигов <b>никогда не подключался</b>.\n\n"
               "Проверь:\n"
               "1. В AmneziaVPN импортирован правильный конфиг?\n"
               "2. Нажата кнопка «Подключить»?\n"
               "3. На устройстве есть интернет?\n"
               "4. Напиши админу — скажет что делать.")
        _notify_admin_user_broken(m.from_user, user_peers, "никогда не подключался")
    else:
        age = now - best_hs
        if age < 300:
            txt = ("✅ По нашим данным — ты сейчас <b>подключён</b> и всё работает.\n\n"
                   "Если какой-то сайт не грузится — попробуй:\n"
                   "• Переоткрыть вкладку в браузере\n"
                   "• Проверить, тот ли сайт заблочен (попробуй <b>whatismyipaddress.com</b> — "
                   "должен показать парижский IP, не твой РФ-ный)\n"
                   "• Если 2ip.ru показывает твой РФ-IP — это <b>нормально</b> (RU-обход работает "
                   "как надо, Яндекс/Ozon видят твой реальный IP)\n\n"
                   "Если всё равно не работает — напиши админу что именно не грузится.")
        elif age < 86400:
            mins = age // 60
            txt = (f"⚠️ Последний раз ты подключался <b>{mins} мин назад</b>.\n\n"
                   "Открой AmneziaVPN → нажми «Подключить». Если крутится и не подключается:\n"
                   "• Проверь интернет на устройстве\n"
                   "• Перезапусти AmneziaVPN\n"
                   "• Проверь что ты не в другом VPN одновременно (Happ, другой клиент)")
            _notify_admin_user_broken(m.from_user, user_peers, f"last HS {mins} мин назад")
        else:
            days = age // 86400
            txt = (f"⚠️ Ты не подключался <b>{days} дн.</b>\n\n"
                   "Возможные причины:\n"
                   "• Удалил приложение AmneziaVPN → поставь заново\n"
                   "• Поменял устройство → надо импортировать конфиг на новое "
                   "(кнопка «📥 Мои конфиги»)\n"
                   "• Приложение не стартует → проверь обновления\n\n"
                   "Если ничего не помогает — админу напиши.")
            _notify_admin_user_broken(m.from_user, user_peers, f"last HS {days} дн.")
    send_eph(m.chat.id, txt)

def _notify_admin_user_broken(user, user_peers, status):
    display = (user.first_name or "") + (" " + user.last_name if user.last_name else "")
    display = display.strip() or (user.username or f"id{user.id}")
    uname = f"@{esc(user.username)}" if user.username else f"id{user.id}"
    for aid in ADMIN_IDS:
        try:
            bot.send_message(aid,
                f"⚠️ <b>Жалоба «не работает»</b>\n\n"
                f"<b>Юзер:</b> {esc(display)}\n"
                f"<b>Username:</b> {uname}\n"
                f"<b>Telegram ID:</b> <code>{user.id}</code>\n"
                f"<b>Конфигов:</b> {len(user_peers)}\n"
                f"<b>Статус:</b> {esc(status)}")
        except Exception as e:
            log.exception("notify admin on broken: %s", e)

@bot.message_handler(func=lambda m: m.text=="⏳ Запрос в обработке" and not is_admin(m.from_user.id))
def cmd_pending_info(m):
    eat_user_msg(m)
    if is_banned(m.from_user.id): return
    send_eph(m.chat.id, "⏳ Админ ещё не ответил. Напишу сюда как только обработает.")

@bot.message_handler(func=lambda m: m.text=="📥 Мои конфиги" and not is_admin(m.from_user.id))
def cmd_my_configs(m):
    eat_user_msg(m)
    if is_banned(m.from_user.id): return
    user_peers = load_user_peers().get(str(m.from_user.id), [])
    if not user_peers:
        send_eph(m.chat.id, "У вас пока нет конфигов. Нажмите «Хочу VPN»."); return
    privs = load_privs()
    kb = types.InlineKeyboardMarkup()
    for pub in user_peers:
        rec = privs.get(pub)
        if not rec: continue
        kb.add(types.InlineKeyboardButton(f"📄 {rec.get('name','?')[:50]}", callback_data=f"myc:{pub}"))
    send_eph(m.chat.id, "Выбери конфиг:", reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("myc:"))
def cb_my_config(c):
    if is_admin(c.from_user.id): return
    pub = c.data[4:]
    user_peers = load_user_peers().get(str(c.from_user.id), [])
    if pub not in user_peers:
        bot.answer_callback_query(c.id, "Это не ваш конфиг"); return
    rec = load_privs().get(pub)
    if not rec:
        bot.answer_callback_query(c.id, "Данные утеряны"); return
    bot.answer_callback_query(c.id)
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("📄 Прислать .conf", callback_data=f"mycdl:{pub}"),
        types.InlineKeyboardButton("✏ Переименовать", callback_data=f"mycrn:{pub}"),
    )
    send_eph(c.message.chat.id,
        f"Конфиг <b>{esc(rec.get('name','?'))}</b>\nIP: <code>{rec['address']}</code>",
        reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("mycdl:"))
def cb_my_config_download(c):
    if is_admin(c.from_user.id): return
    pub = c.data[6:]
    user_peers = load_user_peers().get(str(c.from_user.id), [])
    if pub not in user_peers:
        bot.answer_callback_query(c.id, "Не ваш"); return
    bot.answer_callback_query(c.id, "Готовлю…")
    clear_eph(c.message.chat.id)
    rec = load_privs().get(pub)
    try:
        conf = client_conf(rec["priv"], rec["address"], mode="ru_mobile")
        f = io.BytesIO(conf.encode()); f.name = re.sub(r"[^\w\-]+","_", rec.get("name","peer"))[:30]+".conf"
        bot.send_document(c.message.chat.id, f, caption=f"📄 <b>{esc(rec.get('name','?'))}</b>")
    except Exception as e:
        log.exception("mycdl err"); bot.send_message(c.message.chat.id, f"❌ {esc(str(e))}")

@bot.callback_query_handler(func=lambda c: c.data.startswith("mycrn:"))
def cb_my_config_rename(c):
    if is_admin(c.from_user.id): return
    pub = c.data[6:]
    user_peers = load_user_peers().get(str(c.from_user.id), [])
    if pub not in user_peers:
        bot.answer_callback_query(c.id, "Не ваш"); return
    bot.answer_callback_query(c.id)
    msg = send_eph(c.message.chat.id, "Введи новое имя для конфига:")
    bot.register_next_step_handler(msg, lambda mm: do_rename_peer(mm, pub))

def do_rename_peer(m, pub, by_admin=False):
    if not by_admin and is_admin(m.from_user.id): return
    if not by_admin: eat_user_msg(m)
    new_name = (m.text or "").strip()[:40]
    if not new_name:
        if by_admin: bot.reply_to(m, "❌ Пустое имя")
        else: send_eph(m.chat.id, "❌ Пустое имя")
        return
    if not by_admin:
        user_peers = load_user_peers().get(str(m.from_user.id), [])
        if pub not in user_peers:
            send_eph(m.chat.id, "❌ Это не ваш конфиг"); return
    privs = load_privs()
    rec = privs.get(pub)
    if not rec:
        (bot.reply_to if by_admin else send_eph)(m if by_admin else m.chat.id, "❌ Конфиг не найден"); return
    rec["name"] = new_name
    privs[pub] = rec
    save_privs(privs)
    try:
        clients = read_clients()
        for cl in clients:
            if cl.get("clientId") == pub:
                cl.setdefault("userData", {})["clientName"] = new_name
                break
        write_clients(clients)
    except Exception as e:
        msg = f"⚠️ Имя записано, но clientsTable не обновлён: {e}"
        (bot.reply_to if by_admin else send_eph)(m if by_admin else m.chat.id, msg); return
    msg = f"✅ Переименовано: <b>{esc(new_name)}</b>"
    if by_admin: bot.reply_to(m, msg)
    else: send_eph(m.chat.id, msg)

@bot.callback_query_handler(func=lambda c: c.data.startswith("wantn:"))
def cb_want_n(c):
    if is_admin(c.from_user.id): return
    if is_banned(c.from_user.id):
        bot.answer_callback_query(c.id,"Вы заблокированы"); return
    if user_has_pending(c.from_user.id):
        bot.answer_callback_query(c.id,"Запрос уже в обработке"); return
    parts = c.data.split(":")
    n = int(parts[1]); device = parts[2] if len(parts) > 2 else "mixed"
    n = max(1, min(n, MAX_CONFIGS_PER_REQUEST))
    user_peers = load_user_peers().get(str(c.from_user.id), [])
    if n > MAX_CONFIGS_TOTAL_PER_USER - len(user_peers):
        bot.answer_callback_query(c.id, "Превышен лимит"); return
    bot.answer_callback_query(c.id)
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("Пропустить (имена по умолчанию)", callback_data=f"skipname:{n}:{device}"))
    if n == 1:
        prompt = ("Напиши <b>название</b> для конфига (например: <i>айфон</i>, "
                  "<i>ноутбук</i>, <i>работа</i>).\n\n"
                  "Это нужно чтобы потом в списке своих конфигов было понятно "
                  "какой на каком устройстве. Макс 40 символов.")
    else:
        prompt = (f"Напиши <b>{n}</b> названий для конфигов — "
                  f"<b>каждое с новой строки</b>.\n\n"
                  "Это нужно чтобы в списке «Мои конфиги» было понятно какой на каком устройстве.\n\n"
                  f"Например:\n<code>айфон\nноутбук\nпланшет</code>\n\n"
                  f"Макс 40 символов каждое.")
    msg = send_eph(c.message.chat.id, prompt, reply_markup=kb)
    bot.register_next_step_handler(msg, lambda mm: do_collect_names(mm, n, device))

@bot.callback_query_handler(func=lambda c: c.data.startswith("skipname:"))
def cb_skip_name(c):
    if is_admin(c.from_user.id): return
    if is_banned(c.from_user.id): return
    parts = c.data.split(":")
    n = int(parts[1]); device = parts[2] if len(parts) > 2 else "mixed"
    bot.answer_callback_query(c.id)
    _submit_request(c.message.chat.id, c.from_user, n, names=None, device=device)

def do_collect_names(m, n, device="mixed"):
    if is_admin(m.from_user.id): return
    if is_banned(m.from_user.id): return
    eat_user_msg(m)
    txt = (m.text or "").strip()
    if not txt:
        msg = send_eph(m.chat.id, "Пустое сообщение. Введи имена ещё раз (каждое на новой строке):")
        bot.register_next_step_handler(msg, lambda mm: do_collect_names(mm, n, device)); return
    parts = [p.strip() for p in re.split(r"[\n,;]+", txt) if p.strip()]
    if len(parts) != n:
        msg = send_eph(m.chat.id,
            f"Нужно {n} имён, а ты прислал {len(parts)}. "
            f"Попробуй ещё раз, каждое имя на новой строке.")
        bot.register_next_step_handler(msg, lambda mm: do_collect_names(mm, n, device)); return
    names = [p[:40] for p in parts]
    _submit_request(m.chat.id, m.from_user, n, names=names, device=device)

def _submit_request(chat_id, user, n, names=None, device="mixed"):
    """Called from either skip-callback or after names collected. Creates pending + notifies admin."""
    display = (user.first_name or "") + (" " + user.last_name if user.last_name else "")
    display = display.strip() or (user.username or f"id{user.id}")
    user_peers = load_user_peers().get(str(user.id), [])
    req_id = str(int(time.time()*1000))
    pending = load_pending()
    pending[req_id] = {
        "user_id": user.id, "chat_id": chat_id,
        "username": user.username or "", "display": display,
        "requested_at": int(time.time()), "status": "pending", "count": n,
        "custom_names": names,  # None → auto-named
        "device": device,
    }
    save_pending(pending)
    names_summary = ""
    if names:
        names_summary = "\n\n<b>Названия:</b>\n" + "\n".join(f"• {esc(x)}" for x in names)
    clear_eph(chat_id)
    try:
        bot.send_message(chat_id,
            f"⏳ Запрос на <b>{n}</b> конфигов отправлен админу.{names_summary}\n\n"
            f"Напишу сюда как ответит.",
            reply_markup=user_menu(user.id))
    except Exception as e:
        log.exception("send to user failed: %s", e)
        bot.send_message(chat_id, "Запрос отправлен админу.", reply_markup=user_menu(user.id))
    # notify admin
    for aid in ADMIN_IDS:
        kb = types.InlineKeyboardMarkup()
        kb.row(
            types.InlineKeyboardButton(f"✅ Создать {n}", callback_data=f"req_ok:{req_id}"),
            types.InlineKeyboardButton("❌ Отклонить", callback_data=f"req_no:{req_id}"),
        )
        kb.row(
            types.InlineKeyboardButton("🚫 Бан 24ч", callback_data=f"ban:1:{req_id}"),
            types.InlineKeyboardButton("🚫 Бан 7д", callback_data=f"ban:7:{req_id}"),
            types.InlineKeyboardButton("⛔ Навсегда", callback_data=f"ban:0:{req_id}"),
        )
        uname = f"@{esc(user.username)}" if user.username else f"id{user.id}"
        has = len(user_peers)
        names_list = ""
        if names:
            names_list = "\n\n<b>Названия:</b>\n" + "\n".join(f"• {esc(x)}" for x in names)
        text = (
            f"🆕 <b>Запрос на VPN × {n}</b>\n\n"
            f"<b>От:</b> {esc(display)}\n"
            f"<b>Username:</b> {uname}\n"
            f"<b>Telegram ID:</b> <code>{user.id}</code>\n"
            f"<b>Уже имеет:</b> {has} конфигов"
            f"{names_list}"
        )
        try:
            bot.send_message(aid, text, reply_markup=kb)
        except Exception as e:
            log.exception("admin notify failed: %s | text=%r", e, text[:200])
            # fallback: plain text, no HTML
            try:
                bot.send_message(aid, f"🆕 Запрос на VPN x{n} от {display} ({uname}) id {user.id}. Нужно создать {n} конфигов.",
                                 reply_markup=kb, parse_mode=None)
            except Exception as e2:
                log.exception("admin notify fallback also failed: %s", e2)

@bot.callback_query_handler(func=lambda c: c.data.startswith("req_ok:"))
def cb_req_ok(c):
    if not is_admin(c.from_user.id): return
    req_id = c.data[7:]
    pending = load_pending()
    rec = pending.get(req_id)
    if not rec or rec.get("status") != "pending":
        bot.answer_callback_query(c.id, "Запрос уже обработан"); return
    bot.answer_callback_query(c.id, "Создаю…")
    n = rec.get("count", 1)
    custom_names = rec.get("custom_names") or []
    device = rec.get("device", "mixed")
    # desktops get bigger CIDR list for better RU-bypass; mobiles get the small list
    mode = "ru_desktop" if device in ("win","mac") else "ru_mobile"
    created = []
    for i in range(n):
        if i < len(custom_names) and custom_names[i]:
            name = f"{rec['display']} / {custom_names[i]}"[:40]
        else:
            name = (rec["display"] + (f" #{i+1}" if n > 1 else ""))[:40]
        try:
            priv, pub, ip = add_peer(name)
            conf = client_conf(priv, ip, mode=mode)
            created.append((name, priv, pub, ip, conf))
        except Exception as e:
            bot.send_message(c.message.chat.id, f"⚠️ Создание #{i+1} провалилось: {e}")
    if not created:
        bot.edit_message_text(c.message.text+"\n\n❌ Не удалось создать", c.message.chat.id, c.message.message_id)
        return
    # Save user_peers mapping
    up = load_user_peers()
    uid_key = str(rec["user_id"])
    up.setdefault(uid_key, []).extend([pub for _,_,pub,_,_ in created])
    save_user_peers(up)
    # MARK APPROVED FIRST so user_menu() shows "Хочу ещё" instead of "⏳ Запрос в обработке"
    rec["status"] = "approved"
    pending[req_id] = rec
    save_pending(pending)
    # update admin message
    created_summary = "\n".join(f"• {esc(n_)} → <code>{ip_}</code>" for n_,_,_,ip_,_ in created)
    try:
        bot.edit_message_text(
            c.message.html_text + f"\n\n✅ Создано {len(created)}:\n{created_summary}",
            c.message.chat.id, c.message.message_id, parse_mode="HTML")
    except Exception as e:
        log.exception("edit admin msg failed: %s", e)
    # send to requester
    try:
        bot.send_message(rec["chat_id"],
            f"✅ Готово! Создано {len(created)} конфигов.\n\n"
            f"Файлы приду отдельными сообщениями ниже. "
            f"После всех — пришлю инструкцию.", reply_markup=user_menu(rec["user_id"]))
        for name_, priv_, pub_, ip_, conf_ in created:
            f = io.BytesIO(conf_.encode()); f.name = re.sub(r"[^\w\-]+","_", name_)[:30]+".conf"
            try:
                qr = make_qr_png(conf_)
                bot.send_photo(rec["chat_id"], qr, caption=f"📄 <b>{esc(name_)}</b>")
            except Exception: pass
            bot.send_document(rec["chat_id"], f)
        instr = instructions_for(rec.get("device","mixed"))
        bot.send_message(rec["chat_id"], instr, reply_markup=user_menu(rec["user_id"]), disable_web_page_preview=True)
    except Exception as e:
        log.exception("files to user failed: %s", e)
        bot.send_message(c.message.chat.id, f"⚠️ Файлы не отправились юзеру: {esc(str(e))}")

@bot.callback_query_handler(func=lambda c: c.data.startswith("req_no:"))
def cb_req_no(c):
    if not is_admin(c.from_user.id): return
    req_id = c.data[7:]
    pending = load_pending()
    rec = pending.get(req_id)
    if not rec or rec.get("status") != "pending":
        bot.answer_callback_query(c.id, "Запрос уже обработан"); return
    bot.answer_callback_query(c.id, "Отклонено")
    try:
        bot.edit_message_text(c.message.html_text + "\n\n❌ Отклонено",
            c.message.chat.id, c.message.message_id, parse_mode="HTML")
    except Exception as e: log.exception("edit on reject: %s", e)
    try:
        bot.send_message(rec["chat_id"], "❌ Админ отклонил ваш запрос.", reply_markup=user_menu(rec["user_id"]))
    except Exception as e: log.exception("notify user on reject: %s", e)
    rec["status"] = "rejected"
    pending[req_id] = rec
    save_pending(pending)

@bot.callback_query_handler(func=lambda c: c.data.startswith("ban:"))
def cb_ban(c):
    if not is_admin(c.from_user.id): return
    _, days, req_id = c.data.split(":", 2)
    days = int(days)
    pending = load_pending()
    rec = pending.get(req_id)
    if not rec:
        bot.answer_callback_query(c.id, "Запрос не найден"); return
    bans = load_bans()
    uid = rec["user_id"]
    until = 0 if days == 0 else int(time.time()) + days*86400
    bans[str(uid)] = {"until": until, "display": rec["display"], "by": c.from_user.id, "at": int(time.time())}
    save_bans(bans)
    label = "НАВСЕГДА" if days==0 else f"{days}д"
    bot.answer_callback_query(c.id, f"🚫 Забанен {label}")
    try:
        bot.edit_message_text(c.message.html_text + f"\n\n🚫 Юзер забанен {label}",
            c.message.chat.id, c.message.message_id, parse_mode="HTML")
    except Exception as e: log.exception("edit on ban: %s", e)
    try:
        if days != 0:
            bot.send_message(rec["chat_id"], f"⛔ Вы заблокированы на {days} дней.")
        else:
            bot.send_message(rec["chat_id"], "⛔ Вы заблокированы навсегда.")
    except Exception: pass
    # also remove any pending requests from this user
    pending[req_id]["status"] = "banned"
    save_pending(pending)

# Catch-all for non-admin spam: silently drop if banned
@bot.message_handler(func=lambda m: not is_admin(m.from_user.id) and is_banned(m.from_user.id))
def cmd_banned_silent(m):
    pass  # ignore everything

# Admin: /unban <user_id>
@bot.message_handler(commands=["unban"])
def cmd_unban(m):
    if not is_admin(m.from_user.id): return
    parts = m.text.split()
    if len(parts) < 2:
        bot.reply_to(m, "Usage: /unban &lt;user_id&gt;"); return
    uid = parts[1]
    bans = load_bans()
    if uid in bans:
        bans.pop(uid)
        save_bans(bans)
        bot.reply_to(m, f"✅ {uid} разбанен")
    else:
        bot.reply_to(m, "Не в бане")

# Admin: /bans — list current bans
@bot.message_handler(commands=["bans"])
def cmd_list_bans(m):
    if not is_admin(m.from_user.id): return
    bans = load_bans()
    if not bans:
        bot.reply_to(m, "Пусто."); return
    lines = []
    now = int(time.time())
    for uid, rec in bans.items():
        until = rec.get("until", 0)
        if until == 0: ends = "НАВСЕГДА"
        else:
            left = until - now
            ends = f"{left//3600}ч осталось" if left<86400 else f"{left//86400}д осталось"
        lines.append(f"• <code>{uid}</code> ({esc(rec.get('display','?'))}) — {ends}")
    bot.send_message(m.chat.id, "\n".join(lines))

@bot.message_handler(func=lambda m: m.text=="➕ Юзер (всё в тоннеле)")
def cmd_add_full(m):
    if not is_admin(m.from_user.id): return
    msg = bot.send_message(m.chat.id, "Имя клиента (весь трафик пойдёт через VPN):")
    bot.register_next_step_handler(msg, lambda mm: do_add(mm, mode="full"))

@bot.message_handler(func=lambda m: m.text=="💻 Юзер (RU-обход, ПК)")
def cmd_add_rudesktop(m):
    if not is_admin(m.from_user.id): return
    msg = bot.send_message(m.chat.id, "Имя клиента (RU-обход для ПК, большой список ~22к CIDR):")
    bot.register_next_step_handler(msg, lambda mm: do_add(mm, mode="ru_desktop"))

@bot.message_handler(func=lambda m: m.text=="📱 Юзер (RU-обход, моб.)")
def cmd_add_rumobile(m):
    if not is_admin(m.from_user.id): return
    msg = bot.send_message(m.chat.id, "Имя клиента (RU-обход для телефона, ~50 крупных подсетей):")
    bot.register_next_step_handler(msg, lambda mm: do_add(mm, mode="ru_mobile"))

def do_add(m, mode="full"):
    if not is_admin(m.from_user.id): return
    name = (m.text or "").strip()[:60]
    if not name: bot.reply_to(m,"❌ Пустое имя"); return
    try:
        priv, pub, ip = add_peer(name)
    except Exception as e:
        bot.reply_to(m, f"❌ Ошибка: <code>{e}</code>"); return
    conf = client_conf(priv, ip, mode=mode)
    label = {"full":"🌐 всё в тоннеле", "ru_desktop":"💻 RU-обход ПК", "ru_mobile":"📱 RU-обход моб"}[mode]
    cap = (f"✅ Создан: <b>{name}</b> ({label})\nIP: <code>{ip}</code>\n"
           f"PubKey: <code>{pub}</code>")
    if len(conf) < 3000:
        try:
            qr = make_qr_png(conf)
            bot.send_photo(m.chat.id, qr, caption=cap+"\n\nКонфиг — файлом ниже, QR — выше.")
        except Exception:
            bot.send_message(m.chat.id, cap)
    else:
        bot.send_message(m.chat.id, cap+f"\n\n⚠️ Конфиг {len(conf)//1024} КБ, QR не влезет — только файлом.")
    f = io.BytesIO(conf.encode()); f.name = re.sub(r"[^\w\-]+","_", name)[:30]+".conf"
    bot.send_document(m.chat.id, f)

@bot.message_handler(func=lambda m: m.text=="📥 Скачать конфиг")
def cmd_download_prompt(m):
    if not is_admin(m.from_user.id): return
    privs = load_privs()
    clients = read_clients()
    kb = types.InlineKeyboardMarkup()
    for c in clients:
        pub = c["clientId"]
        if pub not in privs: continue  # no stored priv, can't regenerate
        name = c.get("userData",{}).get("clientName","?")[:30]
        kb.add(types.InlineKeyboardButton(f"📄 {name}", callback_data=f"dl:{pub}"))
    if not kb.keyboard:
        bot.send_message(m.chat.id,"Нет юзеров с сохранёнными ключами (все созданы до появления этой функции).")
        return
    bot.send_message(m.chat.id,"Чей конфиг скачать?", reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("dl:"))
def cb_dl(c):
    if not is_admin(c.from_user.id): return
    pub = c.data[3:]
    privs = load_privs()
    rec = privs.get(pub)
    if not rec:
        bot.answer_callback_query(c.id, "Ключ не найден"); return
    bot.answer_callback_query(c.id)
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🌐 Всё в тоннеле", callback_data=f"dlm:full:{pub}"),
        types.InlineKeyboardButton("💻 RU-обход ПК", callback_data=f"dlm:ru_desktop:{pub}"),
    )
    kb.add(types.InlineKeyboardButton("📱 RU-обход моб.", callback_data=f"dlm:ru_mobile:{pub}"))
    bot.send_message(c.message.chat.id, f"Какой вариант конфига для <b>{esc(rec.get('name','?'))}</b>?", reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("dlm:"))
def cb_dl_mode(c):
    if not is_admin(c.from_user.id): return
    _, mode, pub = c.data.split(":", 2)
    privs = load_privs()
    rec = privs.get(pub)
    if not rec:
        bot.answer_callback_query(c.id,"Ключ не найден"); return
    bot.answer_callback_query(c.id,"Готовлю конфиг…")
    try:
        conf = client_conf(rec["priv"], rec["address"], mode=mode)
    except Exception as e:
        bot.send_message(c.message.chat.id, f"❌ {e}"); return
    label = {"full":"🌐 всё в тоннеле", "ru_desktop":"💻 RU-обход ПК", "ru_mobile":"📱 RU-обход моб"}[mode]
    cap = f"📄 <b>{esc(rec.get('name','?'))}</b> ({label})\nIP: <code>{rec['address']}</code>\nРазмер: {len(conf)//1024} КБ"
    if len(conf) < 3000:
        try:
            qr = make_qr_png(conf)
            bot.send_photo(c.message.chat.id, qr, caption=cap+"\n\nQR выше, файл ниже.")
        except Exception:
            bot.send_message(c.message.chat.id, cap)
    else:
        bot.send_message(c.message.chat.id, cap+"\n⚠️ Большой конфиг — QR не влезет, только файлом.")
    f = io.BytesIO(conf.encode()); f.name = re.sub(r"[^\w\-]+","_", rec.get("name","peer"))[:30]+".conf"
    bot.send_document(c.message.chat.id, f)

@bot.message_handler(func=lambda m: m.text=="➖ Удалить юзера")
def cmd_rm_prompt(m):
    if not is_admin(m.from_user.id): return
    clients = read_clients()
    if not clients: bot.send_message(m.chat.id,"Пусто."); return
    kb = types.InlineKeyboardMarkup()
    for c in clients:
        name = c.get("userData",{}).get("clientName","?")[:30]
        pub = c["clientId"]
        kb.add(types.InlineKeyboardButton(f"🗑 {name}", callback_data=f"rm:{pub}"))
    bot.send_message(m.chat.id,"Кого удалить?", reply_markup=kb)

@bot.callback_query_handler(func=lambda c: c.data.startswith("rm:"))
def cb_rm(c):
    if not is_admin(c.from_user.id): return
    pub = c.data[3:]
    try: remove_peer(pub); bot.answer_callback_query(c.id,"Удалён ✅")
    except Exception as e: bot.answer_callback_query(c.id, f"Ошибка: {e}"); return
    bot.edit_message_text("🗑 Удалён.", c.message.chat.id, c.message.message_id)

@bot.message_handler(func=lambda m: m.text=="📋 Список юзеров")
def cmd_list(m):
    if not is_admin(m.from_user.id): return
    clients = read_clients()
    if not clients: bot.send_message(m.chat.id,"Пусто."); return
    lines=[]
    for c in clients:
        d = c.get("userData",{})
        lines.append(f"• <b>{esc(d.get('clientName','?'))}</b> — <code>{d.get('allowed_ips','?')}</code>")
    bot.send_message(m.chat.id,"\n".join(lines))

@bot.message_handler(func=lambda m: m.text=="📊 Статистика")
def cmd_stats(m):
    if not is_admin(m.from_user.id): return
    peers = wg_show()
    clients = {c["clientId"]: c.get("userData",{}).get("clientName","?") for c in read_clients()}
    now = int(time.time())
    lines=[f"<b>Пиров:</b> {len(peers)}"]
    for p in sorted(peers, key=lambda x: -x["last_hs"]):
        name = clients.get(p["pub"],"unknown")
        if p["last_hs"]==0: hs="никогда"
        else:
            age = now-p["last_hs"]
            if age<60: hs=f"{age} сек назад"
            elif age<3600: hs=f"{age//60} мин назад"
            elif age<86400: hs=f"{age//3600} ч назад"
            else: hs=f"{age//86400} дн назад"
        rx_mb = p["rx"]/1024/1024; tx_mb = p["tx"]/1024/1024
        lines.append(f"• <b>{esc(name)}</b>\n  handshake: {hs}, ↓{rx_mb:.1f} ↑{tx_mb:.1f} МБ")
    bot.send_message(m.chat.id,"\n".join(lines))

@bot.message_handler(func=lambda m: m.text=="🌍 Проверить блок РКН")
def cmd_rkn(m):
    if not is_admin(m.from_user.id): return
    bot.send_message(m.chat.id,"⏳ Запрашиваю check-host.net …")
    try:
        req = http_json(f"https://check-host.net/check-ping?host={SERVER_IP}&max_nodes=5&node=ru1.node.check-host.net&node=ru2.node.check-host.net&node=ru3.node.check-host.net")
        rid = req["request_id"]
        time.sleep(10)
        res = http_json(f"https://check-host.net/check-result/{rid}")
        lines=[f"IP: <code>{SERVER_IP}</code>",""]
        ok_nodes = 0
        for node, data in res.items():
            city = req["nodes"].get(node,["?","?","?"])[2]
            if not data or not data[0]:
                lines.append(f"❓ {city}: нет ответа"); continue
            pings = data[0]
            okcnt = sum(1 for p in pings if p and p[0]=="OK")
            tot = len(pings)
            if okcnt>0:
                avg = sum(float(p[1]) for p in pings if p and p[0]=="OK")/okcnt*1000
                lines.append(f"✅ {city}: {okcnt}/{tot}, ~{avg:.0f} мс")
                ok_nodes += 1
            else:
                lines.append(f"❌ {city}: {okcnt}/{tot}")
        verdict = "✅ IP доступен из РФ" if ok_nodes>=2 else "⚠️ Возможен блок РКН"
        bot.send_message(m.chat.id, verdict+"\n\n"+"\n".join(lines))
    except Exception as e:
        bot.send_message(m.chat.id, f"❌ Ошибка: <code>{e}</code>")

def adguard_api(path, method="POST", body=None):
    import base64
    auth = base64.b64encode(f"{ADGUARD_USER}:{ADGUARD_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"{ADGUARD_URL}{path}", data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()

@bot.message_handler(func=lambda m: m.text=="⏸ Пауза AdGuard 5 мин")
def cmd_adguard_pause(m):
    if not is_admin(m.from_user.id): return
    try:
        adguard_api("/control/protection", body={"enabled": False, "duration": 300000})
        bot.send_message(m.chat.id, "⏸ AdGuard на паузе 5 минут. Фильтрация отключена, реклама покажется.")
    except Exception as e:
        bot.send_message(m.chat.id, f"❌ {e}")

@bot.message_handler(func=lambda m: m.text=="▶️ Включить AdGuard")
def cmd_adguard_resume(m):
    if not is_admin(m.from_user.id): return
    try:
        adguard_api("/control/protection", body={"enabled": True})
        bot.send_message(m.chat.id, "▶️ AdGuard снова фильтрует.")
    except Exception as e:
        bot.send_message(m.chat.id, f"❌ {e}")

@bot.message_handler(func=lambda m: m.text=="📣 Сообщение всем")
def cmd_broadcast_start(m):
    if not is_admin(m.from_user.id): return
    msg = bot.send_message(m.chat.id,
        "Напиши текст сообщения для <b>всех</b> юзеров (кроме тебя).\n"
        "Поддерживается HTML-разметка: &lt;b&gt;жирный&lt;/b&gt;, &lt;i&gt;курсив&lt;/i&gt;, "
        "&lt;a href=\"url\"&gt;ссылка&lt;/a&gt;.\n\n"
        "Или /cancel чтобы отменить.")
    bot.register_next_step_handler(msg, do_broadcast_confirm)

def do_broadcast_confirm(m):
    if not is_admin(m.from_user.id): return
    if m.text == "/cancel":
        bot.reply_to(m, "Отменено."); return
    text = m.html_text or m.text or ""
    if not text.strip():
        bot.reply_to(m, "Пустое сообщение. Попробуй снова через меню."); return
    # count recipients
    up = load_user_peers()
    non_admin = [k for k in up.keys() if int(k) not in ADMIN_IDS]
    non_banned = [k for k in non_admin if not is_banned(int(k))]
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton(f"✅ Отправить ({len(non_banned)})", callback_data="bc_go"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="bc_no"),
    )
    _pending_broadcast[m.from_user.id] = text
    bot.send_message(m.chat.id,
        f"<b>Предпросмотр:</b>\n\n{text}\n\n"
        f"Получат: <b>{len(non_banned)}</b> юзеров.",
        reply_markup=kb, disable_web_page_preview=True)

_pending_broadcast = {}

@bot.callback_query_handler(func=lambda c: c.data in ("bc_go","bc_no"))
def cb_broadcast(c):
    if not is_admin(c.from_user.id): return
    text = _pending_broadcast.pop(c.from_user.id, None)
    bot.answer_callback_query(c.id)
    if c.data == "bc_no" or not text:
        bot.edit_message_text("❌ Отменено.", c.message.chat.id, c.message.message_id); return
    up = load_user_peers()
    sent, failed = 0, 0
    for uid_str in up.keys():
        uid = int(uid_str)
        if uid in ADMIN_IDS or is_banned(uid): continue
        try:
            bot.send_message(uid, text, disable_web_page_preview=True)
            sent += 1
        except Exception as e:
            log.exception("broadcast to %s failed: %s", uid, e)
            failed += 1
        time.sleep(0.05)
    bot.edit_message_text(
        f"✅ Отправлено: <b>{sent}</b>\n❌ Ошибок: <b>{failed}</b>",
        c.message.chat.id, c.message.message_id, parse_mode="HTML")

@bot.message_handler(func=lambda m: m.text=="⚙️ Статус сервера")
def cmd_status(m):
    if not is_admin(m.from_user.id): return
    try:
        up = subprocess.run(["uptime","-p"], capture_output=True, timeout=5).stdout.decode().strip()
        load = subprocess.run(["cat","/proc/loadavg"], capture_output=True, timeout=5).stdout.decode().split()[0:3]
        mem = subprocess.run(["free","-m"], capture_output=True, timeout=5).stdout.decode().splitlines()[1].split()
        disk = subprocess.run(["df","-h","/"], capture_output=True, timeout=5).stdout.decode().splitlines()[1].split()
        ctname = discover_container() or "НЕ НАЙДЕН"
        port = discover_port() or "?"
        rc = 0 if discover_container() else 1
        ct = "🟢 up" if rc==0 else "🔴 down"
        txt = (f"<b>Контейнер:</b> {ct} ({ctname})\n"
               f"<b>Порт:</b> {port}/udp\n"
               f"<b>IP:</b> {SERVER_IP}\n"
               f"<b>Uptime:</b> {up}\n"
               f"<b>Load:</b> {' '.join(load)}\n"
               f"<b>RAM:</b> {mem[2]}/{mem[1]} МБ\n"
               f"<b>Диск /:</b> {disk[2]}/{disk[1]} ({disk[4]})")
        bot.send_message(m.chat.id, txt)
    except Exception as e:
        bot.send_message(m.chat.id, f"❌ Ошибка: <code>{e}</code>")

if __name__=="__main__":
    print("Bot starting…")
    bot.infinity_polling(timeout=30, long_polling_timeout=25)
