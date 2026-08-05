#!/usr/bin/env bash
# Tencent Cloud resolver-identity 2GiB baseline bootstrap (run as ubuntu with sudo -n).
# Safe to re-run: all steps are idempotent. Never modifies machine-id or network interface config.
set -euo pipefail

ROLE="${1:?usage: base-bootstrap.sh <role>}"
HOSTNAME="${2:?usage: base-bootstrap.sh <role> <hostname>}"
FQDN="${3:?usage: base-bootstrap.sh <role> <hostname> <fqdn>}"
PRIVATE_IP="${4:?usage: base-bootstrap.sh <role> <hostname> <fqdn> <private_ip>}"

log() { printf '[bootstrap] %s\n' "$*"; }

# --- 2GiB swap: replace Tencent default 1.9G /swap.img with a real 2G /swapfile ---
if ! swapon --show --noheadings | grep -q '/swapfile'; then
  if swapon --show --noheadings | grep -q '/swap.img'; then
    log 'removing Tencent default swap.img'
    sudo swapoff /swap.img 2>/dev/null || true
    sudo sed -i '\#/swap.img#d' /etc/fstab
    sudo rm -f /swap.img
  fi
  if [ ! -f /swapfile ]; then
    log 'creating 2G /swapfile'
    sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress
  fi
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

# --- sysctl 2GiB profile ---
cat <<'EOF' | sudo tee /etc/sysctl.d/99-ri-cloud-2g.conf >/dev/null
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
sudo sysctl --system >/dev/null 2>&1 || true

# --- hostname ---
if [ "$(hostname)" != "$HOSTNAME" ]; then
  log "setting hostname to $HOSTNAME"
  sudo cp /etc/hostname "/etc/hostname.bak.$(date +%Y%m%d%H%M%S)"
  sudo hostnamectl set-hostname "$HOSTNAME"
fi

# --- /etc/hosts: rebuild cleanly ---
sudo cp /etc/hosts "/etc/hosts.bak.$(date +%Y%m%d%H%M%S)"
{
  printf '127.0.0.1 localhost\n'
  printf '::1 localhost ip6-localhost ip6-loopback\n'
  printf 'ff02::1 ip6-allnodes\n'
  printf 'ff02::2 ip6-allrouters\n'
  printf '\n# Tencent Cloud private lab names\n'
  printf '10.206.16.15 ri-management.cloud.lab ri-management\n'
  printf '10.206.16.3  ri-norn-a.cloud.lab ri-norn-a\n'
  printf '10.206.16.5  ri-norn-b.cloud.lab ri-norn-b\n'
  printf '10.206.16.14 ri-r1.cloud.lab ri-r1\n'
  printf '10.206.16.17 ri-r2.cloud.lab ri-r2\n'
  printf '10.206.16.7  ri-r3.cloud.lab ri-r3\n'
  printf '10.206.16.13 ri-authdns.cloud.lab ri-authdns\n'
} | sudo tee /etc/hosts >/dev/null

# --- NTP: prefer systemd-timesyncd against Tencent sources ---
if command -v chronyd >/dev/null 2>&1 && chronyc tracking >/dev/null 2>&1 && chronyc tracking | grep -qi 'Leap status.*Normal'; then
  log 'chrony already synchronized; keeping chrony'
else
  sudo systemctl disable --now chrony 2>/dev/null || true
  sudo systemctl stop chronyd 2>/dev/null || true
  sudo mkdir -p /etc/systemd/timesyncd.conf.d
  cat <<'EOF' | sudo tee /etc/systemd/timesyncd.conf.d/ri-tencent-cloud.conf >/dev/null
[Time]
NTP=time1.tencentyun.com time2.tencentyun.com time3.tencentyun.com
FallbackNTP=
EOF
  sudo systemctl enable systemd-timesyncd >/dev/null 2>&1 || true
  sudo systemctl restart systemd-timesyncd || true
fi

# --- Docker: install if missing (Ubuntu 24.04) ---
if ! docker --version >/dev/null 2>&1; then
  log 'installing docker'
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl gnupg docker.io docker-compose-v2 >/dev/null 2>&1 || \
    sudo apt-get install -y -qq docker.io docker-compose-v2
fi
sudo systemctl enable --now docker >/dev/null 2>&1 || true
sudo mkdir -p /etc/docker
cat <<'EOF' | sudo tee /etc/docker/daemon.json >/dev/null
{
  "log-driver": "json-file",
  "log-opts": {"max-size": "20m", "max-file": "3"},
  "iptables": true
}
EOF
sudo systemctl restart docker >/dev/null 2>&1 || true
sudo usermod -aG docker ubuntu 2>/dev/null || true

# --- UFW baseline (SSH first so management channel is never cut) ---
sudo apt-get install -y -qq ufw >/dev/null 2>&1 || true
if command -v ufw >/dev/null 2>&1; then
  CONTROLLER_IP="${SSH_CLIENT%% *}"
  if [ -n "${CONTROLLER_IP:-}" ]; then
    sudo ufw allow from "$CONTROLLER_IP" to any port 22 proto tcp >/dev/null 2>&1 || true
  fi
  sudo ufw allow from 10.206.16.0/20 to any port 22 proto tcp >/dev/null 2>&1 || true
  sudo ufw default deny incoming >/dev/null 2>&1 || true
  sudo ufw default allow outgoing >/dev/null 2>&1 || true
  sudo ufw --force enable >/dev/null 2>&1 || true
  sudo ufw reload >/dev/null 2>&1 || true
fi

# --- verify ---
NTP_VAL=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)
echo "BOOTSTRAP_OK role=$ROLE hostname=$(hostname) fqdn=$(hostname -f) swap=$(swapon --show --noheadings | wc -l) docker=$(docker --version 2>/dev/null || echo NONE) ufw=$(ufw status 2>/dev/null | grep -o 'Status: active' || echo inactive) ntp=$NTP_VAL"
