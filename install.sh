#!/bin/bash

set -e
# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g., with sudo su)" >&2
  exit 1
fi
# Define the domain for your marzban instance
read -p "Enter your domain for marzban: " DOMAIN
read -p "Enter your email for SSL certificate (inibudi@daouse.com): " MAIL


# Update the system and install necessary packages
apt update -qq -y
apt install curl wget git ufw gnupg2 lsb-release socat tree idn net-tools vnstat iptables xz-utils apt-transport-https dnsutils cron bash-completion -y

# Install speedtest
echo "Checking for existing speedtest installation..."
if command -v speedtest >/dev/null 2>&1; then
    echo "speedtest is already installed. Skipping installation."
else
    echo "Installing speedtest..."
    wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1
    tar xzf ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1
    mv speedtest /usr/bin/
    rm -f ookla-* speedtest.* > /dev/null 2>&1
fi

# Enable BBR
echo "Enabling BBR congestion control..."
modprobe tcp_bbr >/dev/null 2>&1
echo "tcp_bbr" | tee -a /etc/modules-load.d/modules.conf
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
  echo "BBR has been enabled."
else
  echo "Failed to enable BBR."
fi

sysctl -w net.mptcp.enabled=1
if sysctl net.mptcp.enabled | grep -q "net.mptcp.enabled = 1"; then
  echo "MPTCP has been enabled."
else
  echo "Failed to enable MPTCP."
fi

sysctl -p >/dev/null 2>&1

if command -v marzban >/dev/null 2>&1; then
  echo "Existing marzban installation detected. Uninstalling..."
  marzban uninstall
fi

bash -c "$(curl -sL https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/marzban)" @ install
sleep 50

marzban cli admin create --sudo

[ -f /$HOME/reality.txt ] && rm -f /$HOME/reality.txt
[ -f /$HOME/shortIds.txt ] && rm -f /$HOME/shortIds.txt
[ -f /$HOME/xray_uuid.txt ] && rm -f /$HOME/xray_uuid.txt

# Generate Reality keys
echo "Generating Reality keys..."
docker exec marzban-marzban-1 xray x25519 genkey > /$HOME/reality.txt
PRIVATE_KEY=$(grep -oP 'Private key: \K\S+' /$HOME/reality.txt)
PUBLIC_KEY=$(grep -oP 'Public key: \K\S+' /$HOME/reality.txt)

# Generate shortIds
echo "Generating shortIds..."
openssl rand -hex 8 > /$HOME/shortIds.txt
SHORTIDS=$(cat /$HOME/shortIds.txt)

# Generating uuid for Reality
echo "Generating UUID for Reality..."
if ! docker ps | grep -q marzban-marzban-1; then
  echo "marzban container not running! Exiting."
  exit 1
fi
docker exec marzban-marzban-1 xray uuid > /$HOME/xray_uuid.txt
XRAY_UUID=$(cat /$HOME/xray_uuid.txt)
if [[ -z "$XRAY_UUID" ]]; then
  echo "Failed to generate UUID. Exiting."
  exit 1
fi

# Check if certificate already exists
rm -Rf /var/lib/marzban/certs >/dev/null 2>&1 || true
if [[ -f "/var/lib/marzban/certs/fullchain.pem" && -f "/var/lib/marzban/certs/key.pem" ]]; then
    echo "SSL certificate already exists. Skipping certificate installation."
else
    # Install Certificate using acme.sh
    bash -c "curl https://get.acme.sh | sh -s email=$MAIL"
    mkdir -p /var/lib/marzban/certs
    bash -c "~/.acme.sh/acme.sh --issue --force --standalone -d \"$DOMAIN\" --fullchain-file \"/var/lib/marzban/certs/fullchain.pem\" --key-file \"/var/lib/marzban/certs/key.pem\""
    marzban down

    # Set proper permissions
    chmod 600 "/var/lib/marzban/certs/key.pem"
    chmod 644 "/var/lib/marzban/certs/fullchain.pem"
fi

wget -O /opt/marzban/.env https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/env
# Download docker-compose.yml
wget -O /opt/marzban/docker-compose.yml https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/docker-compose.yml

# Download nginx.conf
wget -O /opt/marzban/nginx.conf https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/nginx.conf
# Replace placeholders in nginx.conf with user input
sed -i "s/server_name \$DOMAIN;/server_name $DOMAIN;/" /opt/marzban/nginx.conf

# Download xray_config.json
wget -O /var/lib/marzban/xray_config.json https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/xray_config.json

sed -i "s/YOUR_UUID/$XRAY_UUID/" /var/lib/marzban/xray_config.json

# Download the subscribers marzban
mkdir -p /var/lib/marzban/templates/subscription/
wget -N -P /var/lib/marzban/templates/subscription/ https://raw.githubusercontent.com/Elysya28/Script_installer_vps/maz1/index.html

# add geoip and geosite
wget -N -P /var/lib/marzban/assets/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
wget -N -P /var/lib/marzban/assets/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat

# Firewall configuration
echo "Configuring firewall..."
ufw allow 8000/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8444/tcp
ufw allow 8445/tcp
ufw allow 8446/tcp
ufw allow 8447/tcp
ufw allow 8448/tcp
ufw allow 9443/tcp
ufw allow 10443/tcp
ufw allow 22/tcp
ufw allow 2222/tcp
ufw allow 2021/tcp
ufw allow 2022/tcp
ufw allow 2023/tcp
ufw allow 2024/tcp
ufw allow 2025/tcp
ufw allow 51820/tcp
ufw allow 51821/tcp
ufw allow 51822/tcp
ufw allow 51823/tcp
ufw allow 51824/tcp
ufw allow 51825/tcp
ufw allow 8443/tcp
ufw allow 9443/tcp
ufw allow 62050/tcp
ufw allow 62051/tcp

ufw --force enable

echo "==============================================="
echo "private key: $PRIVATE_KEY"
echo "public key: $PUBLIC_KEY"
echo "ShortIds: $SHORTIDS"
echo "UUID: $XRAY_UUID"
echo "==============================================="

echo "marzban installation and configuration completed successfully!"
echo "You can access marzban at https://$DOMAIN"
echo "Make sure to configure your Xray clients with the provided Reality keys and UUID."
echo "==============================================="


read -p "Do you want to reboot now? [Y/n]: " answer
answer=${answer:-Y}
if [[ "$answer" =~ ^[Yy]$ ]]; then
  echo "Rebooting system..."
  reboot
else
  echo "Reboot cancelled. Please reboot manually if needed."
fi
