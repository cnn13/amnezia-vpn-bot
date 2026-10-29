#!/opt/awgbot/venv/bin/python
import urllib.request, netaddr
OUT = "/opt/awgbot/ru_bypass_allowed.txt"
URL = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
req = urllib.request.Request(URL, headers={"User-Agent":"Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=30) as r:
    lines = [l.strip() for l in r.read().decode().splitlines() if l.strip() and not l.startswith("#")]
ru = netaddr.IPSet(lines)
non_ru = netaddr.IPSet(["0.0.0.0/0"]) - ru
cidrs = [str(c) for c in non_ru.iter_cidrs()]
with open(OUT, "w") as f: f.write(",".join(cidrs))
print(f"RU: {len(lines)}, non-RU: {len(cidrs)} saved")
