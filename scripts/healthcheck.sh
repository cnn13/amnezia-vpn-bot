#!/bin/bash
set -e
CT=$(docker ps --format '{{.Names}}' | grep -m1 '^amnezia-awg' || true)
[ -z "$CT" ] && exit 0
LOG=/var/log/awg-healthcheck.log
if ! docker ps --format '{{.Names}}' | grep -qx "$CT"; then
    echo "$(date -Is) [RESTART] $CT down" >> "$LOG"
    docker start "$CT" 2>/dev/null || true
fi
if ! docker exec "$CT" wg show awg0 >/dev/null 2>&1; then
    echo "$(date -Is) [FIX] awg0 missing on $CT" >> "$LOG"
    docker exec -d "$CT" sh -c "bash /opt/amnezia/start.sh" 2>/dev/null || true
fi
