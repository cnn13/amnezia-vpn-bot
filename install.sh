#!/bin/bash
# One-shot installer for amnezia-vpn-bot on fresh Ubuntu 24.04.
# Usage:
#   git clone https://github.com/YOU/amnezia-vpn-bot /opt/amnezia-vpn-bot
#   cd /opt/amnezia-vpn-bot && sudo bash install.sh
#
# Prereq: you have a Telegram bot token (from @BotFather) and your admin Telegram ID (from @userinfobot).
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "===== amnezia-vpn-bot installer ====="
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

#######################################
# 1. Interactive config
#######################################
mkdir -p /etc/awgbot
if [ -f /etc/awgbot/config.env ]; then
    echo "Found existing /etc/awgbot/config.env — reusing. (delete it to re-prompt.)"
    source /etc/awgbot/config.env
else
    read -rp "Telegram bot token (from @BotFather): " BOT_TOKEN
    read -rp "Admin Telegram ID (your own id): " ADMIN_IDS
    SERVER_IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')
    read -rp "Public server IP [$SERVER_IP]: " SERVER_IP_IN
    SERVER_IP="${SERVER_IP_IN:-$SERVER_IP}"
    ADGUARD_USER="admin"
    ADGUARD_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    echo "Generated AdGuard admin password: $ADGUARD_PASS  (save it!)"
    cat > /etc/awgbot/config.env <<EOF
BOT_TOKEN="$BOT_TOKEN"
ADMIN_IDS="$ADMIN_IDS"
SERVER_IP="$SERVER_IP"
ADGUARD_USER="$ADGUARD_USER"
ADGUARD_PASS="$ADGUARD_PASS"
EOF
    chmod 600 /etc/awgbot/config.env
    source /etc/awgbot/config.env
fi

#######################################
# 2. OS packages + hardening
#######################################
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq -y install ufw fail2ban unattended-upgrades curl wget qrencode jq ca-certificates \
    gnupg lsb-release python3-pip python3-venv netcat-openbsd software-properties-common 2>&1 | tail -3

ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable

cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl restart fail2ban
systemctl enable fail2ban

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

#######################################
# 3. Docker
#######################################
if ! command -v docker >/dev/null; then
    curl -fsSL https://get.docker.com | sh 2>&1 | tail -3
fi
systemctl enable --now docker

#######################################
# 4. AmneziaWG kernel module (DKMS)
#######################################
if ! lsmod | grep -q amneziawg; then
    add-apt-repository -y --no-update ppa:amnezia/ppa 2>&1 | tail -3
    apt-get -qq update
    apt-get -qq -y install amneziawg-dkms amneziawg-tools 2>&1 | tail -3
    modprobe amneziawg || true
fi

#######################################
# 5. Python venv for bot + scripts
#######################################
mkdir -p /opt/awgbot
if [ ! -d /opt/awgbot/venv ]; then
    python3 -m venv /opt/awgbot/venv
fi
/opt/awgbot/venv/bin/pip install --quiet --upgrade pip
/opt/awgbot/venv/bin/pip install --quiet -r "$REPO_DIR/bot/requirements.txt"

#######################################
# 6. Install bot code + scripts
#######################################
install -m 755 "$REPO_DIR/bot/bot.py"               /opt/awgbot/bot.py
install -m 755 "$REPO_DIR/scripts/alerts.sh"        /usr/local/bin/awg-alerts.sh
install -m 755 "$REPO_DIR/scripts/healthcheck.sh"   /usr/local/bin/awg-healthcheck.sh
install -m 755 "$REPO_DIR/scripts/rkn_notify.sh"    /usr/local/bin/awg-rkn-notify.sh
install -m 755 "$REPO_DIR/scripts/broadcast.py"     /usr/local/bin/awg-broadcast.py
install -m 755 "$REPO_DIR/scripts/cleanup_abandoned.py" /usr/local/bin/awg-cleanup.py
install -m 755 "$REPO_DIR/scripts/traffic_watch.py" /usr/local/bin/awg-traffic.py
install -m 755 "$REPO_DIR/scripts/update_rulist.py" /usr/local/bin/awg-update-rulist.py
install -m 755 "$REPO_DIR/scripts/update_mobile_rulist.py" /usr/local/bin/awg-update-mobile-rulist.py

install -m 644 "$REPO_DIR/systemd/awgbot.service"           /etc/systemd/system/
install -m 644 "$REPO_DIR/systemd/awg0-alias.service"       /etc/systemd/system/
install -m 644 "$REPO_DIR/systemd/awg-dns-redirect.service" /etc/systemd/system/
install -m 644 "$REPO_DIR/cron/awg-crons"                   /etc/cron.d/awg-crons

#######################################
# 7. AdGuard Home — install if not running
#######################################
if ! docker ps -a --format '{{.Names}}' | grep -qx adguardhome; then
    # Disable systemd-resolved stub listener on :53 (we need the port free in the container)
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/noresolve.conf <<'EOF'
[Resolve]
DNS=1.1.1.1
DNSStubListener=no
EOF
    systemctl restart systemd-resolved

    mkdir -p /opt/adguard/conf /opt/adguard/work
    # Generate bcrypt hash of configured admin password
    BCRYPT=$(/opt/awgbot/venv/bin/python -c "import bcrypt,os;print(bcrypt.hashpw(os.environ['ADGUARD_PASS'].encode(), bcrypt.gensalt(rounds=10)).decode())")
    sed "s|__ADGUARD_BCRYPT__|${BCRYPT//|/\\|}|g" "$REPO_DIR/adguard/AdGuardHome.yaml.template" > /opt/adguard/conf/AdGuardHome.yaml

    docker pull adguard/adguardhome:latest >/dev/null
    # NOTE: AdGuard runs in HOST network at FIRST — once Amnezia container is created (via desktop
    # client), re-run this installer and it will attach AdGuard to the Amnezia container namespace.
    docker run -d --name adguardhome --restart unless-stopped --network host \
        -v /opt/adguard/work:/opt/adguardhome/work \
        -v /opt/adguard/conf:/opt/adguardhome/conf \
        adguard/adguardhome:latest >/dev/null
    echo "AdGuard installed. Access web UI at http://10.8.1.254:3000 (after VPN is up)."
fi

# If Amnezia container exists, re-attach AdGuard to its network namespace
if docker ps --format '{{.Names}}' | grep -qE '^amnezia-awg'; then
    AMN_CT=$(docker ps --format '{{.Names}}' | grep -E '^amnezia-awg' | head -1)
    CUR_NET=$(docker inspect -f '{{.HostConfig.NetworkMode}}' adguardhome 2>/dev/null || echo "")
    if [ "$CUR_NET" != "container:$AMN_CT" ]; then
        echo "Re-attaching AdGuard to Amnezia container's network namespace..."
        docker rm -f adguardhome 2>/dev/null || true
        docker run -d --name adguardhome --restart unless-stopped \
            --network "container:$AMN_CT" \
            -v /opt/adguard/work:/opt/adguardhome/work \
            -v /opt/adguard/conf:/opt/adguardhome/conf \
            adguard/adguardhome:latest >/dev/null
    fi

    # Add alias IP for stable DNS target
    docker exec "$AMN_CT" ip addr add 10.8.1.254/32 dev awg0 2>/dev/null || true
    # DNAT all client DNS to AdGuard
    docker exec "$AMN_CT" iptables -t nat -C PREROUTING -i awg0 -p udp --dport 53 -j DNAT --to-destination 10.8.1.254:53 2>/dev/null \
        || docker exec "$AMN_CT" iptables -t nat -A PREROUTING -i awg0 -p udp --dport 53 -j DNAT --to-destination 10.8.1.254:53
    docker exec "$AMN_CT" iptables -t nat -C PREROUTING -i awg0 -p tcp --dport 53 -j DNAT --to-destination 10.8.1.254:53 2>/dev/null \
        || docker exec "$AMN_CT" iptables -t nat -A PREROUTING -i awg0 -p tcp --dport 53 -j DNAT --to-destination 10.8.1.254:53
fi

#######################################
# 8. Enable systemd units
#######################################
systemctl daemon-reload
systemctl enable awg0-alias.service awg-dns-redirect.service >/dev/null
systemctl enable --now awgbot.service

#######################################
# 9. Initial RU-list generation
#######################################
/usr/local/bin/awg-update-rulist.py 2>&1 | tail -1
/usr/local/bin/awg-update-mobile-rulist.py 2>&1 | tail -1

echo
echo "===== INSTALL COMPLETE ====="
echo
systemctl is-active awgbot.service >/dev/null && echo "✅ Bot active" || echo "❌ Bot NOT active (check: journalctl -u awgbot -n 20)"
echo
if ! docker ps --format '{{.Names}}' | grep -qE '^amnezia-awg'; then
    echo "⚠️  AmneziaWG container not found yet. Next step:"
    echo "    1. Open AmneziaVPN desktop client → Setup new server → enter this server's IP + root/password"
    echo "    2. Install AmneziaWG protocol via the client"
    echo "    3. Re-run this installer:  sudo bash $REPO_DIR/install.sh"
    echo "       (second run attaches AdGuard to the Amnezia container's network)"
else
    echo "✅ AmneziaWG container detected."
    echo "   Bot admin menu available for @$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getMe" | jq -r .result.username)"
    echo "   AdGuard web UI: http://10.8.1.254:3000  (admin / password from config.env)"
fi
echo
echo "Config: /etc/awgbot/config.env  (chmod 600)"
echo "State:  /opt/awgbot/*.json       (peer_privs, user_peers, pending, bans)"
echo "To migrate: back up /etc/awgbot/ + /opt/awgbot/*.json + /opt/amnezia/awg/ (inside amnezia container)"
