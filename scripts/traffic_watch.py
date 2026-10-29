#!/opt/awgbot/venv/bin/python
"""Detect heavy-traffic peers and send a gentle warning.
Runs every N minutes via cron, compares current RX+TX with saved snapshot.
If delta > threshold → warn the user that heavy traffic slows down VPN for everyone."""
import sys, json, subprocess, time, os, urllib.request, urllib.parse
sys.path.insert(0, "/opt/awgbot")
import bot as awgbot

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = set(int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip())
STATE_FILE = "/var/lib/awg-alerts/traffic_snapshot.json"
COOLDOWN_FILE = "/var/lib/awg-alerts/traffic_warn_cooldown.json"
# threshold: bytes transferred in the interval between runs that triggers a warning
# cron runs every 10 minutes → 2 GB per 10 min = ~27 Mbps sustained → heavy
THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
WARN_COOLDOWN = 2 * 3600  # 2h — don't spam

def notify(chat_id, msg):
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data=urllib.parse.urlencode({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode()
        ), timeout=10).read()
    except Exception as e:
        print(f"notify fail {chat_id}: {e}", file=sys.stderr)

def main():
    os.makedirs("/var/lib/awg-alerts", exist_ok=True)
    try:
        prev = json.load(open(STATE_FILE))
    except Exception:
        prev = {}
    try:
        cooldown = json.load(open(COOLDOWN_FILE))
    except Exception:
        cooldown = {}

    r = subprocess.run(["docker","exec",awgbot._ct_name(),"wg","show","awg0","dump"],
                       capture_output=True, timeout=15)
    if r.returncode != 0: return
    now = int(time.time())
    current = {}
    peer_hs = {}
    for ln in r.stdout.decode().strip().splitlines()[1:]:
        f = ln.split("\t")
        if len(f) < 7: continue
        pub = f[0]
        rx = int(f[5]); tx = int(f[6]); hs = int(f[4])
        current[pub] = {"rx": rx, "tx": tx, "ts": now}
        peer_hs[pub] = hs

    user_peers = awgbot.load_user_peers()
    pub_to_uid = {pub: int(uid) for uid, pubs in user_peers.items() for pub in pubs}
    clients = awgbot.read_clients()
    pub_to_name = {c["clientId"]: c.get("userData",{}).get("clientName","?") for c in clients}

    for pub, cur in current.items():
        if pub not in prev: continue
        p = prev[pub]
        # peer could have reset counters (container restart) → skip negative deltas
        d_rx = cur["rx"] - p.get("rx", 0)
        d_tx = cur["tx"] - p.get("tx", 0)
        if d_rx < 0 or d_tx < 0: continue
        total = d_rx + d_tx
        if total < THRESHOLD_BYTES: continue
        # cooldown
        last_warn = cooldown.get(pub, 0)
        if now - last_warn < WARN_COOLDOWN: continue
        uid = pub_to_uid.get(pub)
        if uid is None or uid in ADMIN_IDS: continue
        name = pub_to_name.get(pub, "?")
        gb = total / 1024 / 1024 / 1024
        interval_s = cur["ts"] - p.get("ts", now)
        mbps = (total * 8) / interval_s / 1024 / 1024 if interval_s > 0 else 0
        msg = (f"⚠️ <b>Активная загрузка через VPN</b>\n\n"
               f"Твой конфиг <b>{awgbot.esc(name)}</b> качает/отдаёт сейчас много "
               f"(~{gb:.1f} ГБ за последние {interval_s//60} мин, ~{mbps:.0f} Мбит/с).\n\n"
               f"VPN-сервер общий на несколько человек, и когда кто-то активно качает — "
               f"у остальных просаживается скорость.\n\n"
               f"<b>Если это необходимо</b> (большой апдейт, работа, итд) — всё ок, "
               f"продолжай. <b>Если скачиваешь торрент или качаешь большой файл "
               f"который можно без VPN</b> — пожалуйста, выключи VPN на это время.")
        notify(uid, msg)
        cooldown[pub] = now
        print(f"warned {name} ({mbps:.0f} Mbps, {gb:.1f} GB)")

    with open(STATE_FILE, "w") as f: json.dump(current, f)
    with open(COOLDOWN_FILE, "w") as f: json.dump(cooldown, f)

if __name__ == "__main__":
    main()
