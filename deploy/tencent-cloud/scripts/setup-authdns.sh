#!/usr/bin/env bash
# Deploy the RC12 authoritative DNS data plane on ri-authdns.
# BIND serves the signed zone on loopback:5353; authority-proxy owns public :53.
set -Eeuo pipefail

ALIAS=ri-authdns-cloud
MANAGEMENT_ALIAS=ri-management-cloud
ROOT=/opt/domain-center-install/cloud-928ed0e
RELEASE_ROOT="$ROOT/release/ri-authdns"
CONFIG_DIR="$ROOT/config/authdns"
SECRET_DIR="$ROOT/secret/secrets"
AGENT_TLS_DIR="$ROOT/secret/agent-tls"
NORN_TLS_DIR="$ROOT/secret/norn-tls"
DATA_DIR=/var/lib/resolver-identity/ri-authdns
LOCAL_CONFIG=/home/lwc/fanxiangdiguijiexi/deploy/tencent-cloud/config/hosts/ri-authdns
LISTEN_IP=10.206.16.13
ZONE=ri-test.invalid
PROJECT=ri-authdns
IMAGE=resolver-identity/rust-data-plane:0.3.0-norn-knot-rc12
IMAGE_ID=sha256:326c4f1e6da5940b0510c44d457cbbd06a581927cbcf4182570e2f0e3a190bf6
MGMT_WORK=/opt/domain-center-install/cloud-928ed0e/work
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REMOTE_STAGE=/tmp/ri-authdns-stage-$STAMP
BACKUP_DIR=/var/backups/ri-authdns/$STAMP

require_file() { test -f "$1" || { echo "missing local file: $1" >&2; exit 1; }; }
for f in docker-compose.yml named.conf.options named.conf.local db.$ZONE; do
  require_file "$LOCAL_CONFIG/$f"
done

rollback() {
  trap - ERR
  set +e
  echo "authdns cutover failed; restoring previous BIND listener" >&2
  ssh "$ALIAS" "sudo -n bash -s" <<'REMOTE_ROLLBACK'
set +e
cd /opt/domain-center-install/cloud-928ed0e/release/ri-authdns
if test -f compose.env; then
  docker compose --env-file compose.env -p ri-authdns -f docker-compose.yml stop authority-proxy agent registry-sync >/dev/null 2>&1
fi
if test -f /var/backups/ri-authdns/CURRENT/named.conf.options; then
  install -o root -g bind -m 644 /var/backups/ri-authdns/CURRENT/named.conf.options /etc/bind/named.conf.options
  install -o root -g bind -m 644 /var/backups/ri-authdns/CURRENT/named.conf.local /etc/bind/named.conf.local
  systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
fi
rm -rf /tmp/ri-authdns-stage-* 2>/dev/null
REMOTE_ROLLBACK
}
trap 'rollback; exit 1' ERR

ssh "$ALIAS" "sudo -n bash -s" <<REMOTE_PREFLIGHT
set -Eeuo pipefail
command -v docker >/dev/null
command -v dig >/dev/null
ufw allow from 10.206.16.0/20 to any port 53 proto udp comment 'ri-lab authoritative DNS' >/dev/null
ufw allow from 10.206.16.0/20 to any port 53 proto tcp comment 'ri-lab authoritative DNS' >/dev/null
ufw allow from 10.206.16.0/20 to any port 8443 proto tcp comment 'ri-lab authority Agent mTLS' >/dev/null
ufw reload >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bind9 bind9-utils dnsutils >/dev/null
actual=\$(docker image inspect --format '{{.Id}}' '$IMAGE' 2>/dev/null || true)
test "\$actual" = '$IMAGE_ID' || { echo "unexpected RC12 image id: \$actual" >&2; exit 1; }
for f in '$SECRET_DIR/agent_private_key' '$SECRET_DIR/trace_ingest_token' '$SECRET_DIR/agent_wrapper_token' '$SECRET_DIR/agent_peer_credentials.json' '$AGENT_TLS_DIR/agent.crt' '$AGENT_TLS_DIR/agent.key' '$AGENT_TLS_DIR/client-ca.crt' '$AGENT_TLS_DIR/agent-client.crt' '$AGENT_TLS_DIR/agent-client.key' '$AGENT_TLS_DIR/agent-ca.crt' '$AGENT_TLS_DIR/authority-client.crt' '$AGENT_TLS_DIR/authority-client.key' '$NORN_TLS_DIR/ca.crt' '$NORN_TLS_DIR/client.crt' '$NORN_TLS_DIR/client.key'; do
  test -f "\$f" || { echo "missing secret or certificate: \$f" >&2; exit 1; }
done
mkdir -p '$RELEASE_ROOT' '$CONFIG_DIR' '$DATA_DIR' /var/lib/bind/zones /var/lib/bind/keys/$ZONE /var/backups/ri-authdns/CURRENT
chown 10002:10002 '$DATA_DIR'
chmod 700 '$DATA_DIR'
chown bind:bind /var/lib/bind/zones /var/lib/bind/keys/$ZONE
chmod 750 /var/lib/bind/zones
chmod 700 /var/lib/bind/keys/$ZONE
mkdir -p '$BACKUP_DIR'
cp -a /etc/bind/named.conf.options '$BACKUP_DIR/named.conf.options' 2>/dev/null || true
cp -a /etc/bind/named.conf.local '$BACKUP_DIR/named.conf.local' 2>/dev/null || true
cp -a /etc/bind/named.conf.options /var/backups/ri-authdns/CURRENT/named.conf.options 2>/dev/null || true
cp -a /etc/bind/named.conf.local /var/backups/ri-authdns/CURRENT/named.conf.local 2>/dev/null || true
REMOTE_PREFLIGHT

ssh "$ALIAS" "mkdir -p '$REMOTE_STAGE'"
scp -q "$LOCAL_CONFIG/docker-compose.yml" "$LOCAL_CONFIG/named.conf.options" "$LOCAL_CONFIG/named.conf.local" "$LOCAL_CONFIG/db.$ZONE" "$ALIAS:$REMOTE_STAGE/"
ssh "$ALIAS" "sudo -n bash -s" <<REMOTE_INSTALL
set -Eeuo pipefail
install -o root -g root -m 644 '$REMOTE_STAGE/named.conf.options' /etc/bind/named.conf.options
install -o root -g root -m 644 '$REMOTE_STAGE/named.conf.local' /etc/bind/named.conf.local
install -o root -g bind -m 644 '$REMOTE_STAGE/db.$ZONE' /var/lib/bind/zones/db.$ZONE
chown bind:bind /var/lib/bind/zones/db.$ZONE
install -o root -g root -m 644 '$REMOTE_STAGE/docker-compose.yml' '$RELEASE_ROOT/docker-compose.yml'
cat > '$RELEASE_ROOT/compose.env' <<'ENV'
RI_IMAGE=$IMAGE
RI_FIELD_HOST_ID=ri-authdns
RI_FIELD_COMPOSE_PROJECT=ri-authdns
RI_FIELD_DATA_DIR=$DATA_DIR
RI_AUTHDNS_CONFIG_DIR=$CONFIG_DIR
RI_AUTHDNS_MANAGEMENT_IP=$LISTEN_IP
RI_AGENT_SERVER_ID=operator/authdns
RI_AGENT_KEY_ID=agent-key-authdns
RI_CHAIN_ADAPTER=norn
RI_CHAIN_RPC_URLS=https://10.206.16.3:8443,https://10.206.16.5:8443
RI_CHAIN_ID=20001
RI_NORN_GENESIS_BLOCK_HASH=0xce696ab6f10a16f1a56bfab12c51771e107b57f4c75422abea2231a3fac8c70c
RI_CHAIN_REGISTRY_ADDRESS=0x1000000000000000000000000000000000000001
RI_NORN_REGISTRY_KEY=resolver-identity-registry-v2
RI_NORN_SIGNER_ISSUER=norn-registry
RI_NORN_SIGNER_KEY_ID=snapshot-key-1
RI_CHAIN_REGISTRY_SCHEMA_HASH=0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499
RI_CHAIN_CONFIRMATIONS=12
RI_NORN_REGISTRY_START_HEIGHT=0
RI_NORN_MAX_SCAN_BLOCKS=100000
RI_NORN_CLIENT_TLS_DIR=$NORN_TLS_DIR
RI_RESOLVER_SECRET_DIR=$SECRET_DIR
RI_AGENT_TLS_DIR=$AGENT_TLS_DIR
RI_REGISTRY_MAX_STALENESS_SECONDS=45
RI_AUTHORITY_PUBLIC_BIND=$LISTEN_IP:53
RI_AUTHORITY_AGENT_URL=https://$LISTEN_IP:8443
ENV
chmod 600 '$RELEASE_ROOT/compose.env'
named-checkconf
named-checkzone '$ZONE' /var/lib/bind/zones/db.$ZONE
systemctl stop bind9 2>/dev/null || systemctl stop named 2>/dev/null || true
systemctl start bind9 2>/dev/null || systemctl start named
for i in \$(seq 1 30); do
  if dig @127.0.0.1 -p 5353 '$ZONE' SOA +dnssec +noall +answer |
    grep -qE '[[:space:]]IN[[:space:]]+RRSIG[[:space:]]+SOA[[:space:]]'; then
    break
  fi
  sleep 1
done
dig @127.0.0.1 -p 5353 '$ZONE' DNSKEY +dnssec +noall +answer |
  grep -qE '[[:space:]]IN[[:space:]]+DNSKEY[[:space:]]'
dig @127.0.0.1 -p 5353 '$ZONE' SOA +dnssec +noall +answer |
  grep -qE '[[:space:]]IN[[:space:]]+RRSIG[[:space:]]+SOA[[:space:]]'
REMOTE_INSTALL

ssh "$MANAGEMENT_ALIAS" "sudo -n bash -s" <<REMOTE_STAGE_IDS
set -Eeuo pipefail
cp '$MGMT_WORK/identities-v2.json' /tmp/ri-authdns-identities.json
cp '$MGMT_WORK/issuer-keys.json' /tmp/ri-authdns-issuer-keys.json
chmod 644 /tmp/ri-authdns-identities.json /tmp/ri-authdns-issuer-keys.json
REMOTE_STAGE_IDS
scp -q "$MANAGEMENT_ALIAS:/tmp/ri-authdns-identities.json" /tmp/ri-authdns-identities.json
scp -q "$MANAGEMENT_ALIAS:/tmp/ri-authdns-issuer-keys.json" /tmp/ri-authdns-issuer-keys.json
scp -q /tmp/ri-authdns-identities.json /tmp/ri-authdns-issuer-keys.json "$ALIAS:$REMOTE_STAGE/"
rm -f /tmp/ri-authdns-identities.json /tmp/ri-authdns-issuer-keys.json
ssh "$MANAGEMENT_ALIAS" "sudo -n rm -f /tmp/ri-authdns-identities.json /tmp/ri-authdns-issuer-keys.json"

ssh "$ALIAS" "sudo -n bash -s" <<REMOTE_START
set -Eeuo pipefail
install -o root -g root -m 644 '$REMOTE_STAGE/ri-authdns-identities.json' '$CONFIG_DIR/identities-v2.json'
install -o root -g root -m 644 '$REMOTE_STAGE/ri-authdns-issuer-keys.json' '$CONFIG_DIR/issuer-keys.json'
cd '$RELEASE_ROOT'
docker compose --env-file compose.env -p '$PROJECT' -f docker-compose.yml config >/dev/null
docker compose --env-file compose.env -p '$PROJECT' -f docker-compose.yml up -d registry-sync
for i in \$(seq 1 60); do curl -fsS http://$LISTEN_IP:9109/readyz >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://$LISTEN_IP:9109/readyz >/dev/null
docker compose --env-file compose.env -p '$PROJECT' -f docker-compose.yml up -d agent
for i in \$(seq 1 60); do curl --fail --silent --show-error --cacert '$AGENT_TLS_DIR/agent-ca.crt' --cert '$AGENT_TLS_DIR/agent-client.crt' --key '$AGENT_TLS_DIR/agent-client.key' https://$LISTEN_IP:8443/readyz >/dev/null 2>&1 && break; sleep 2; done
curl --fail --silent --show-error --cacert '$AGENT_TLS_DIR/agent-ca.crt' --cert '$AGENT_TLS_DIR/agent-client.crt' --key '$AGENT_TLS_DIR/agent-client.key' https://$LISTEN_IP:8443/readyz >/dev/null
docker compose --env-file compose.env -p '$PROJECT' -f docker-compose.yml up -d authority-proxy
for i in \$(seq 1 30); do dig @$LISTEN_IP '$ZONE' SOA +short >/dev/null 2>&1 && break; sleep 1; done
dig @$LISTEN_IP www.$ZONE A +short | grep -qx 192.0.2.10
dig @$LISTEN_IP www.$ZONE AAAA +short | grep -qx 2001:db8::10
dig @$LISTEN_IP txt.$ZONE TXT +short | grep -q resolver-identity-lab-test
dig +tcp @$LISTEN_IP www.$ZONE A +short | grep -qx 192.0.2.10
rm -rf '$REMOTE_STAGE'
echo AUTHDNS_RC12_READY
REMOTE_START
trap - ERR
echo "== authdns RC12 cutover complete =="
