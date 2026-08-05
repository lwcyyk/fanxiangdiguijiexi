#!/usr/bin/env bash
# Bring one norn node host to an installed/activated state for the Tencent Cloud
# resolver-identity lab.
#
#   setup-norn-node.sh <norn-a|norn-b> [activate]
#
# Stages (each idempotent; rerun safe):
#   0. Deploy the Docker-29-adapted OCI loader and load/verify all role images.
#   1. Ensure secret/norn-tls client material (mTLS used by the installer's
#      norn_ready probe) exists; pulled from the management host lab-pki if absent.
#   1.5 Deploy the activate probe relay (systemd) so the frozen urllib probe can
#       see grpc-status (nginx sends it as an HTTP/1.1 trailer over h2-upstream).
#   2. Push the rendered runtime config dir to <ROOT>/config/ri-<node>.
#   3. norn-generate config.yml into secret/node (once), chown 10003.
#   4. wizard install --no-start.
#   5. chown the norn data dir to 10003:10003 (install leaves it root-owned).
#   6. [activate] wizard activate, then wait for node-a peer ID and genesis hash.
set -Eeuo pipefail

NODE="${1:?usage: setup-norn-node.sh <norn-a|norn-b> [activate]}"
ACTIVATE="${2:-}"
case "$NODE" in norn-a|norn-b) ;; *) echo "unsupported node $NODE" >&2; exit 1 ;; esac

ALIAS="ri-${NODE}-cloud"
ROOT=/opt/domain-center-install/cloud-928ed0e
INSTALL_ROOT="$ROOT/install/ri-${NODE}"
SECRET="$ROOT/secret"
DATA_DIR="/var/lib/resolver-identity/ri-${NODE}"
RUNTIME_CONFIG="$ROOT/config/${NODE}"   # config-dir keyed by role SHORT name
LOCAL_CONFIG="/home/lwc/fanxiangdiguijiexi/deploy/tencent-cloud/config/hosts/ri-${NODE}/config"
WIZARD="$INSTALL_ROOT/wizard.py"
FQDN="ri-${NODE}.cloud.lab"
NORN_IMAGE="offline/resolver-identity/norn:ri-ad8b495d892c35b1"
STAGE=/tmp/ri-norn-tls-client-${NODE}

# ---- Stage 0: Docker-29 loader + image load ----
bash "$(dirname "$0")/deploy-loader-docker29.sh" "$NODE"

# ---- Stage 1: norn-tls probe client material ----
has_client() {
  ssh "$ALIAS" "sudo -n bash -c 'test -s $SECRET/norn-tls/client.key && test -s $SECRET/norn-tls/client.crt && test -s $SECRET/norn-tls/ca.crt'"
}
if ! has_client; then
  echo "== $NODE: provisioning norn-tls probe client from management =="
  # lab-pki is root-only on management; stage via sudo tar -> controller -> node.
  STAGE_TGZ=/tmp/ri-norn-tls-client-${NODE}.tgz
  ssh ri-management-cloud "sudo -n bash -c '
    cd $ROOT/lab-pki/mgmt-norn-tls && tar czf /tmp/ri-norn-tls-client.tgz ca.crt client.crt client.key
  '"
  scp -q "ri-management-cloud:/tmp/ri-norn-tls-client.tgz" "$STAGE_TGZ"
  ssh ri-management-cloud "sudo -n rm -f /tmp/ri-norn-tls-client.tgz"
  scp -q "$STAGE_TGZ" "$ALIAS:/tmp/ri-norn-tls-client.tgz"
  ssh "$ALIAS" "sudo -n bash -c '
    set -e
    mkdir -p $SECRET/norn-tls && chmod 700 $SECRET/norn-tls
    tar xzf /tmp/ri-norn-tls-client.tgz -C $SECRET/norn-tls
    chown -R root:root $SECRET/norn-tls
    chmod 600 $SECRET/norn-tls/ca.crt $SECRET/norn-tls/client.crt $SECRET/norn-tls/client.key
    rm -f /tmp/ri-norn-tls-client.tgz
    echo NORN_TLS_CLIENT_PROVISIONED $NODE
  '"
  rm -f "$STAGE_TGZ"
else
  echo "== $NODE: norn-tls probe client already present =="
fi

# ---- Stage 1.5: activate probe relay (frozen urllib probe vs nginx trailers) ----
# The frozen activate readiness probe (_norn_grpc_ready) uses urllib (HTTP/1.1),
# which cannot read the grpc-status trailer nginx grpc_pass emits over HTTP/1.1,
# so it rejects the healthy read proxy with NORN_HTTP_REJECTED. The rendered
# .env points RI_NORN_READ_HOSTNAME=localhost at a local relay that forwards to
# the real read proxy and surfaces grpc-status as a header. This stage deploys
# that relay as a systemd unit if it is not already running.
UPSTREAM_IP="$(grep -E '^RI_NORN_READ_BIND_ADDRESS=' "$LOCAL_CONFIG/.env" | cut -d= -f2)"
echo "== $NODE: ensuring probe relay on 127.0.0.1:8443 -> $UPSTREAM_IP =="
if ! ssh "$ALIAS" "sudo -n systemctl is-active ri-norn-probe-relay" 2>/dev/null | grep -qx active; then
  RELAY_SCRIPT="$(dirname "$0")/probe-relay.py"
  RELAY_UNIT="$(dirname "$0")/ri-norn-probe-relay.service"
  scp -q "$RELAY_SCRIPT" "$ALIAS:/tmp/ri-probe-relay.py"
  ssh "$ALIAS" "sudo -n bash -c 'mkdir -p /opt/domain-center-install/cloud-928ed0e/bin && install -m 700 -o root -g root /tmp/ri-probe-relay.py /opt/domain-center-install/cloud-928ed0e/bin/probe-relay.py && rm -f /tmp/ri-probe-relay.py' && echo RELAY_BIN_INSTALLED"
  sed "s/__UPSTREAM_HOST__/${UPSTREAM_IP}/" "$RELAY_UNIT" | ssh "$ALIAS" "sudo -n tee /etc/systemd/system/ri-norn-probe-relay.service > /dev/null" && echo RELAY_UNIT_WRITTEN
  ssh "$ALIAS" "sudo -n bash -c 'chmod 644 /etc/systemd/system/ri-norn-probe-relay.service; systemctl daemon-reload; systemctl enable ri-norn-probe-relay; systemctl start ri-norn-probe-relay; sleep 1; systemctl is-active ri-norn-probe-relay'"
else
  echo "== $NODE: probe relay already active =="
fi

# ---- Stage 2: rendered runtime config ----
echo "== $NODE: pushing rendered runtime config =="
rm -rf /tmp/ri-norn-config-stage-${NODE}
scp -q -r "$LOCAL_CONFIG" "$ALIAS:/tmp/ri-norn-config-stage-${NODE}"
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  mkdir -p $RUNTIME_CONFIG
  cp -a /tmp/ri-norn-config-stage-${NODE}/. $RUNTIME_CONFIG/
  chown -R root:root $RUNTIME_CONFIG
  find $RUNTIME_CONFIG -type f -exec chmod 600 {} +
  rm -rf /tmp/ri-norn-config-stage-${NODE}
  echo CONFIG_PUSHED $NODE
'"

# ---- Stage 3: norn-generate config.yml ----
echo "== $NODE: generating norn config.yml =="
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  if [ ! -s $SECRET/node/config.yml ]; then
    docker run --rm --user 0:0 --volume $SECRET/node:/config --workdir /config $NORN_IMAGE /usr/local/bin/norn-generate
  fi
  chmod 600 $SECRET/node/config.yml
  chown -R 10003:10003 $SECRET/node $SECRET/tls
  echo CONFIG_GENERATED $NODE
'"

# ---- Stage 4: install --no-start ----
echo "== $NODE: install --no-start =="
ssh "$ALIAS" "sudo -n env DC_MIN_MEMORY_MB=1900 python3 '$WIZARD' install \
  --package-root '$INSTALL_ROOT/product-kit' --role '$NODE' --expected-host '$FQDN' \
  --config-dir '$RUNTIME_CONFIG' --secret-dir '$SECRET' --images '$INSTALL_ROOT/images' \
  --install-root '$INSTALL_ROOT' --yes --no-start"

# ---- Stage 5: data dir ownership ----
echo "== $NODE: chown data dir to 10003 =="
ssh "$ALIAS" "sudo -n bash -c 'test -d $DATA_DIR && chown -R 10003:10003 $DATA_DIR && echo DATA_CHOWNED $NODE'"

if [ "$ACTIVATE" = "activate" ]; then
  # ---- Stage 6: activate (starts norn-node + norn-read-proxy, waits for readiness) ----
  echo "== $NODE: activate =="
  ssh "$ALIAS" "sudo -n env DC_MIN_MEMORY_MB=1900 python3 '$WIZARD' activate \
    --package-root '$INSTALL_ROOT/product-kit' --role '$NODE' --expected-host '$FQDN' \
    --secret-dir '$SECRET' --install-root '$INSTALL_ROOT' --yes"
fi

echo "== $NODE setup complete =="
