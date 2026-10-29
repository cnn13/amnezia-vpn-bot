#!/opt/awgbot/venv/bin/python
"""Broadcast a message to all non-admin, non-banned users who have VPN configs."""
import sys, json, urllib.request, urllib.parse, time

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = set(int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip())
USER_PEERS = "/opt/awgbot/user_peers.json"
BANS = "/opt/awgbot/bans.json"

if len(sys.argv) < 2:
    print("usage: broadcast.py <message>")
    sys.exit(1)
msg = sys.argv[1]

try:
    with open(USER_PEERS) as f: user_peers = json.load(f)
except Exception:
    user_peers = {}
try:
    with open(BANS) as f: bans = json.load(f)
except Exception:
    bans = {}

now = int(time.time())
def is_banned(uid):
    rec = bans.get(str(uid))
    if not rec: return False
    u = rec.get("until", 0)
    return u == 0 or now < u

sent, failed = 0, 0
for uid_str in user_peers.keys():
    try: uid = int(uid_str)
    except: continue
    if uid in ADMIN_IDS: continue
    if is_banned(uid): continue
    data = urllib.parse.urlencode({
        "chat_id": uid, "text": msg, "parse_mode": "HTML",
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TOKEN}/sendMessage",
        data=data,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        sent += 1
    except Exception as e:
        failed += 1
        print(f"  failed to {uid}: {e}", file=sys.stderr)
    time.sleep(0.05)  # avoid Telegram rate limit (30 msg/sec)

print(f"sent: {sent}, failed: {failed}")
