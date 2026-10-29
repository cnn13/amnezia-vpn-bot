#!/bin/bash
source /etc/awgbot/config.env
# CHAT comes from config.env
IP=${SERVER_IP}
REQ=$(curl -sfS -H "User-Agent: Mozilla/5.0" "https://check-host.net/check-ping?host=${IP}&max_nodes=5&node=ru1.node.check-host.net&node=ru2.node.check-host.net&node=ru3.node.check-host.net")
RID=$(echo "$REQ" | jq -r .request_id)
[ -z "$RID" ] || [ "$RID" = "null" ] && exit 0
sleep 12
RES=$(curl -sfS -H "User-Agent: Mozilla/5.0" "https://check-host.net/check-result/$RID")
OK=$(echo "$RES" | jq '[.[] | select(.!=null and .[0]!=null) | [.[0][] | select(.[0]=="OK")] | length] | add // 0')
TOT=$(echo "$RES" | jq '[.[] | select(.!=null and .[0]!=null) | .[0] | length] | add // 0')
if [ "$OK" -lt 4 ]; then
    MSG="⚠️ *RKN monitor* IP ${IP} отвечает ${OK}/${TOT} из РФ. Возможна блокировка."
else
    MSG="✅ *RKN monitor* IP ${IP} доступен из РФ: ${OK}/${TOT}."
fi
curl -sfS -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id=${CHAT} -d parse_mode=Markdown --data-urlencode text="$MSG" >/dev/null
