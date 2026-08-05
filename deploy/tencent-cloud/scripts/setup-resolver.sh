#!/usr/bin/env bash
# Bring one resolver host (r1|r2|r3) to an installed/activated state for the
# Tencent Cloud resolver-identity lab.
#
#   setup-resolver.sh <r1|r2|r3> [activate]
#
# Stages (each idempotent; rerun safe):
#   0. Deploy the Docker-29-adapted OCI loader and load/verify all role images.
#   1. Push the rendered runtime config dir (real norn genesis hash) to
#      <ROOT>/config/<role-short>, overwriting any stale placeholder config.
#   2. Replace the placeholder identities/issuer-keys in that config dir with
#      the registry-signed identities-v2.json + issuer-keys.json (fetched from
#      the management host work dir). The wizard copies this dir into the
#      release config at install, and the resolver compose mounts those files,
#      so they must be the real signed material before install/activate.
#   3. wizard install --no-start.
#   4. [activate] wizard activate, then verify status + readiness.
set -Eeuo pipefail

ROLE="${1:?usage: setup-resolver.sh <r1|r2|r3> [activate]}"
ACTIVATE="${2:-}"
case "$ROLE" in r1|r2|r3) ;; *) echo "unsupported role $ROLE" >&2; exit 1 ;; esac

ALIAS="ri-${ROLE}-cloud"
ROOT=/opt/domain-center-install/cloud-928ed0e
INSTALL_ROOT="$ROOT/install/ri-${ROLE}"
SECRET="$ROOT/secret"
DATA_DIR="/var/lib/resolver-identity/ri-${ROLE}"
RUNTIME_CONFIG="$ROOT/config/${ROLE}"    # config-dir keyed by role SHORT name
LOCAL_CONFIG="/home/lwc/fanxiangdiguijiexi/deploy/tencent-cloud/config/hosts/ri-${ROLE}/config"
WIZARD="$INSTALL_ROOT/wizard.py"
FQDN="ri-${ROLE}.cloud.lab"
MANAGEMENT_ALIAS=ri-management-cloud
MGMT_WORK=/opt/domain-center-install/cloud-928ed0e/work

# ---- Stage 0: Docker-29 loader + image load ----
bash "$(dirname "$0")/deploy-loader-docker29.sh" "$ROLE"

# ---- Stage 1: rendered runtime config (real genesis hash) ----
echo "== $ROLE: pushing rendered runtime config =="
rm -rf /tmp/ri-resolver-config-stage-${ROLE}
scp -q -r "$LOCAL_CONFIG" "$ALIAS:/tmp/ri-resolver-config-stage-${ROLE}"
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  mkdir -p $RUNTIME_CONFIG
  cp -a /tmp/ri-resolver-config-stage-${ROLE}/. $RUNTIME_CONFIG/
  chown -R root:root $RUNTIME_CONFIG
  # .env is read only by the wizard (root): 0600. The files bind-mounted into
  # containers (kresd.conf -> knot uid 10003; identities/issuer-keys -> rust
  # uid 10002) must stay world-readable: 0644, or the container read-only
  # mounts fail with EACCES.
  find $RUNTIME_CONFIG -maxdepth 1 -name '.env' -exec chmod 600 {} +
  find $RUNTIME_CONFIG -maxdepth 1 -type f ! -name '.env' -exec chmod 644 {} +
  rm -rf /tmp/ri-resolver-config-stage-${ROLE}
  echo CONFIG_PUSHED $ROLE
'"

# ---- Stage 2: real signed identities + issuer-keys into config dir ----
# The placeholders {\"identities\":[]} / {\"keys\":[]} are not usable by the
# resolver compose mounts; replace them with the registry-signed material.
echo "== $ROLE: replacing placeholder identities with registry-signed material =="
STAGE_IDS=/tmp/ri-identities-${ROLE}.json
STAGE_KEYS=/tmp/ri-issuer-keys-${ROLE}.json
ssh "$MANAGEMENT_ALIAS" "sudo -n bash -c 'cp $MGMT_WORK/identities-v2.json /tmp/ri-identities-mgmt.json && cp $MGMT_WORK/issuer-keys.json /tmp/ri-issuer-keys-mgmt.json && chmod 644 /tmp/ri-identities-mgmt.json /tmp/ri-issuer-keys-mgmt.json && echo MGMT_STAGED'"
scp -q "ri-management-cloud:/tmp/ri-identities-mgmt.json" "$STAGE_IDS"
scp -q "ri-management-cloud:/tmp/ri-issuer-keys-mgmt.json" "$STAGE_KEYS"
ssh "$MANAGEMENT_ALIAS" "sudo -n rm -f /tmp/ri-identities-mgmt.json /tmp/ri-issuer-keys-mgmt.json"
scp -q "$STAGE_IDS" "$ALIAS:/tmp/ri-identities.json"
scp -q "$STAGE_KEYS" "$ALIAS:/tmp/ri-issuer-keys.json"
rm -f "$STAGE_IDS" "$STAGE_KEYS"
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  python3 - <<PYEOF
import json
for name in (\"identities-v2.json\", \"issuer-keys.json\"):
    p = \"$RUNTIME_CONFIG/\" + name
    data = json.load(open(\"/tmp/\" + (\"ri-identities.json\" if name == \"identities-v2.json\" else \"ri-issuer-keys.json\")))
    if name == \"identities-v2.json\":
        assert len(data[\"identities\"]) == 3, \"expected 3 signed identities\"
    else:
        assert len(data[\"keys\"]) == 2, \"expected 2 issuer keys\"
    open(p, \"w\").write(json.dumps(data, indent=2) + \"\n\")
    print(name, \"OK\", len(data[\"identities\"]) if name == \"identities-v2.json\" else len(data[\"keys\"]))
PYEOF
  chown root:root $RUNTIME_CONFIG/identities-v2.json $RUNTIME_CONFIG/issuer-keys.json
  # world-readable: the registry-sync/agent/trace-adapter containers mount
  # these files read-only and run as uid 10002 (not root).
  chmod 644 $RUNTIME_CONFIG/identities-v2.json $RUNTIME_CONFIG/issuer-keys.json
  rm -f /tmp/ri-identities.json /tmp/ri-issuer-keys.json
  echo IDENTITIES_PUSHED $ROLE
'"

# ---- Stage 3: install --no-start ----
echo "== $ROLE: install --no-start =="
ssh "$ALIAS" "sudo -n env DC_MIN_MEMORY_MB=1900 python3 '$WIZARD' install \
  --package-root '$INSTALL_ROOT/product-kit' --role '$ROLE' --expected-host '$FQDN' \
  --config-dir '$RUNTIME_CONFIG' --secret-dir '$SECRET' --images '$INSTALL_ROOT/images' \
  --install-root '$INSTALL_ROOT' --yes --no-start"

if [ "$ACTIVATE" = "activate" ]; then
  # ---- Stage 4: activate (starts registry-sync, agent, trace, resolver [+wrapper for r1]) ----
  echo "== $ROLE: activate =="
  ssh "$ALIAS" "sudo -n env DC_MIN_MEMORY_MB=1900 python3 '$WIZARD' activate \
    --package-root '$INSTALL_ROOT/product-kit' --role '$ROLE' --expected-host '$FQDN' \
    --secret-dir '$SECRET' --install-root '$INSTALL_ROOT' --yes"
fi

echo "== $ROLE setup complete =="
