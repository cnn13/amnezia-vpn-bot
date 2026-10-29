#!/opt/awgbot/venv/bin/python
"""Delete peers that haven't connected in 30+ days.
Also delete peers that never connected and were created 7+ days ago (dead configs).
Admin peer (Admin [...]) and 'колик телефон' peers are always kept.
Notifies the user of deleted peers via Telegram if they still have a pending chat."""
import sys, json, subprocess, time, urllib.request, urllib.parse, datetime
sys.path.insert(0, "/opt/awgbot")

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = set(int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip())
INACTIVE_DAYS = 30
NEVER_CONNECTED_DAYS = 7
PRESERVE_SUBSTR = ("admin", "колик телефон")

import bot as awgbot

def notify(chat_id, msg):
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data=urllib.parse.urlencode({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode()
        ), timeout=10).read()
    except Exception as e:
        print(f"  notify fail {chat_id}: {e}", file=sys.stderr)

def main():
    # dump wg
    r = subprocess.run(["docker","exec",awgbot._ct_name(),"wg","show","awg0","dump"],
                       capture_output=True, timeout=15)
    if r.returncode != 0:
        print("wg show failed:", r.stderr.decode()); return
    now = int(time.time())
    peer_hs = {}
    for ln in r.stdout.decode().strip().splitlines()[1:]:
        f = ln.split("\t")
        if len(f) < 5: continue
        peer_hs[f[0]] = int(f[4])

    clients = awgbot.read_clients()
    user_peers = awgbot.load_user_peers()
    pub_to_uid = {pub: int(uid) for uid, pubs in user_peers.items() for pub in pubs}

    to_delete = []
    for cl in clients:
        pub = cl["clientId"]
        ud = cl.get("userData", {})
        name = ud.get("clientName", "")
        if any(k in name.lower() for k in PRESERVE_SUBSTR):
            continue
        hs = peer_hs.get(pub, 0)
        if hs > 0:
            age_days = (now - hs) / 86400
            if age_days > INACTIVE_DAYS:
                to_delete.append((pub, name, f"не подключался {int(age_days)} дн."))
        else:
            # never connected — check creationDate
            created = ud.get("creationDate", "")
            try:
                dt = datetime.datetime.strptime(created, "%a %b %d %H:%M:%S %Y")
                if (datetime.datetime.utcnow() - dt).days > NEVER_CONNECTED_DAYS:
                    to_delete.append((pub, name, f"создан но ни разу не подключался за {(datetime.datetime.utcnow()-dt).days} дн."))
            except Exception:
                pass

    print(f"Found {len(to_delete)} peers to delete")
    for pub, name, reason in to_delete:
        try:
            awgbot.remove_peer(pub)
            print(f"  🗑 {name} — {reason}")
        except Exception as e:
            print(f"  ERR {name}: {e}")
            continue
        # update user_peers mapping
        uid = pub_to_uid.get(pub)
        if uid is not None:
            up = awgbot.load_user_peers()
            if str(uid) in up:
                up[str(uid)] = [p for p in up[str(uid)] if p != pub]
                if not up[str(uid)]: del up[str(uid)]
                awgbot.save_user_peers(up)
            # notify user
            if uid not in ADMIN_IDS:
                notify(uid, f"💤 Твой конфиг <b>{name}</b> удалён.\n\n"
                           f"Причина: {reason}.\n\n"
                           f"Если нужен снова — напиши боту «➕ Хочу VPN».")

if __name__ == "__main__":
    main()
