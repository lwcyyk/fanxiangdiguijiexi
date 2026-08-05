#!/usr/bin/env bash
# Provision the test authoritative DNS on ri-authdns for the Tencent Cloud
# resolver-identity lab: bind9 (Ubuntu package), zone ri-test.invalid, fixed
# A/AAAA/TXT records, non-recursive, listening on the lab private address.
# Stages:
#   1. Open UDP/TCP 53 from the lab subnet in UFW.
#   2. Install bind9 from Ubuntu official repositories.
#   3. Deploy named config + zone file, checkconfig/checkzone, restart named.
#   4. Verify the zone answers over UDP.
set -Eeuo pipefail

ALIAS=ri-authdns-cloud
LOCAL_CONFIG=/home/lwc/fanxiangdiguijiexi/deploy/tencent-cloud/config/hosts/ri-authdns
LISTEN_IP=10.206.16.13
ZONE=ri-test.invalid

echo "== authdns: open UDP/TCP 53 from the lab subnet =="
ssh "$ALIAS" "sudo -n bash -c '
  ufw allow from 10.206.16.0/20 to any port 53 proto udp comment \"ri-lab test authoritative DNS\"
  ufw allow from 10.206.16.0/20 to any port 53 proto tcp comment \"ri-lab test authoritative DNS\"
  ufw reload
  ufw status | grep -E \".*53.*10.206.16.0/20\"
'"

echo "== authdns: install bind9 =="
ssh "$ALIAS" "sudo -n bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bind9 >/dev/null && dpkg-query -W -f=\"\${Version}\n\" bind9'"

echo "== authdns: deploy config =="
scp -q "$LOCAL_CONFIG/named.conf.options" "$LOCAL_CONFIG/named.conf.local" "$LOCAL_CONFIG/db.$ZONE" "$ALIAS:/tmp/"
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  install -o root -g root -m 644 /tmp/named.conf.options /etc/bind/named.conf.options
  install -o root -g root -m 644 /tmp/named.conf.local /etc/bind/named.conf.local
  install -o root -g root -m 644 /tmp/db.$ZONE /etc/bind/db.$ZONE
  rm -f /tmp/named.conf.options /tmp/named.conf.local /tmp/db.$ZONE
  named-checkconf
  named-checkzone $ZONE /etc/bind/db.$ZONE
  systemctl restart named
  sleep 2
  systemctl is-active named
  ss -lunpt | grep :53
'"

echo "== authdns: verify over UDP and TCP =="
ssh "$ALIAS" "dig @$LISTEN_IP www.$ZONE A +short; dig @$LISTEN_IP www.$ZONE AAAA +short; dig @$LISTEN_IP txt.$ZONE TXT +short; dig @$LISTEN_IP $ZONE NS +short; dig @$LISTEN_IP www.$ZONE A +tcp +short"

echo "== authdns setup complete =="
