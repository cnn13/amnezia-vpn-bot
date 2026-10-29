#!/bin/bash
# Monitors server state and sends TG alerts to admin
source /etc/awgbot/config.env
# CHAT comes from config.env
STATE=/var/lib/awg-alerts
mkdir -p "$STATE"
VPN_DOWN_FLAG="$STATE/vpn_down.flag"
BROADCAST=/usr/local/bin/awg-broadcast.py

tg() {
    local key="$1" msg="$2" cooldown="${3:-3600}"
    local last_file="$STATE/${key}.last"
    local now=$(date +%s)
    if [ -f "$last_file" ]; then
        local last=$(cat "$last_file")
        if [ "$((now - last))" -lt "$cooldown" ]; then return; fi
    fi
    echo "$now" > "$last_file"
    curl -sfS -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        -d chat_id="${CHAT}" -d parse_mode=HTML --data-urlencode text="$msg" >/dev/null
}

tg_clear() {
    local key="$1"
    rm -f "$STATE/${key}.last"
}

broadcast_users() {
    [ -x "$BROADCAST" ] || return 0
    "$BROADCAST" "$1" >>/var/log/awg-broadcast.log 2>&1
}

mark_vpn_down() {
    if [ ! -f "$VPN_DOWN_FLAG" ]; then
        touch "$VPN_DOWN_FLAG"
        broadcast_users "⚠️ <b>VPN временно не работает</b>
Админ уже чинит, обычно 1-5 минут. Напишу когда снова заработает."
    fi
}

mark_vpn_up() {
    if [ -f "$VPN_DOWN_FLAG" ]; then
        rm -f "$VPN_DOWN_FLAG"
        broadcast_users "✅ <b>VPN снова работает</b>
Подключайтесь."
    fi
}

# ---- 1. amnezia container down ----
vpn_bad=0
if ! docker ps --format '{{.Names}}' | grep -qx amnezia-awg2; then
    tg "amnezia_down" "🔴 <b>amnezia-awg2 упал!</b>%0AVPN не работает. Пробую стартануть…" 600
    docker start amnezia-awg2 2>/dev/null
    vpn_bad=1
else
    tg_clear "amnezia_down"
fi

# ---- 2. awg0 interface down inside container ----
if ! docker exec amnezia-awg2 wg show awg0 >/dev/null 2>&1; then
    tg "awg0_down" "⚠️ <b>Интерфейс awg0 не поднят</b>%0AКлиенты не могут подключиться." 600
    vpn_bad=1
else
    tg_clear "awg0_down"
fi

# notify end-users about VPN state transition
if [ "$vpn_bad" = "1" ]; then
    mark_vpn_down
else
    mark_vpn_up
fi

# ---- 3. AdGuard container down ----
if ! docker ps --format '{{.Names}}' | grep -qx adguardhome; then
    tg "adguard_down" "🟡 <b>AdGuard упал</b>%0AРеклама не блочится, но VPN работает." 600
    docker start adguardhome 2>/dev/null
else
    tg_clear "adguard_down"
fi

# ---- 4. disk > 80% ----
disk=$(df / | awk 'NR==2 {gsub("%",""); print $5}')
if [ "$disk" -gt 90 ]; then
    tg "disk_90" "🔴 <b>Диск заполнен на ${disk}%</b>%0AОсталось меньше 10%. Срочно освободите место." 7200
elif [ "$disk" -gt 80 ]; then
    tg "disk_80" "⚠️ <b>Диск заполнен на ${disk}%</b>%0AПора посмотреть что занимает место." 21600
else
    tg_clear "disk_80"; tg_clear "disk_90"
fi

# ---- 5. RAM > 90% sustained ----
mem_pct=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
if [ "$mem_pct" -gt 90 ]; then
    cnt_file="$STATE/mem_high_count"
    cnt=$(cat "$cnt_file" 2>/dev/null || echo 0)
    cnt=$((cnt + 1))
    echo "$cnt" > "$cnt_file"
    if [ "$cnt" -ge 2 ]; then  # 2 x 5 min = 10 min
        tg "ram_high" "⚠️ <b>RAM занят на ${mem_pct}%</b>%0AПодряд >10 минут. Если так продолжится — сервер начнёт тормозить." 7200
    fi
else
    rm -f "$STATE/mem_high_count"
    tg_clear "ram_high"
fi

# ---- 6. peers inactive > 7 days (only alert once per peer) ----
# Check peer handshakes via wg show
if docker exec amnezia-awg2 wg show awg0 dump 2>/dev/null | tail -n +2 > /tmp/peers.dump; then
    now_ts=$(date +%s)
    while IFS=$'\t' read -r pub psk endpoint allowed hs rx tx keep; do
        [ -z "$pub" ] && continue
        [ "$hs" -eq 0 ] && continue  # never connected — not an alert
        age=$((now_ts - hs))
        if [ "$age" -gt 604800 ]; then  # 7 days
            # look up name from clientsTable
            name=$(docker exec amnezia-awg2 cat /opt/amnezia/awg/clientsTable 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for c in d:
        if c['clientId'].startswith('${pub:0:20}'):
            print(c['userData'].get('clientName','?')); break
except: print('?')" 2>/dev/null)
            days=$((age / 86400))
            key="peer_inactive_${pub:0:16}"
            tg "$key" "💤 <b>${name}</b> не подключался ${days} дней.%0AМожет потерял .conf — проверьте." 604800  # weekly
        fi
    done < /tmp/peers.dump
    rm -f /tmp/peers.dump
fi
