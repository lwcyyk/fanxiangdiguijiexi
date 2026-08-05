#!/usr/bin/env bash
# Install + activate the management role on ri-management for the Tencent Cloud
# resolver-identity lab. Stages:
#   1. Push the rendered runtime config dir to <ROOT>/config/ri-management.
#   2. wizard preflight (records preflight.json evidence).
#   3. wizard install --no-start.
#   4. wizard activate (starts the management-tools compose project).
set -Eeuo pipefail

ALIAS=ri-management-cloud
ROOT=/opt/domain-center-install/cloud-928ed0e
INSTALL_ROOT="$ROOT/install/ri-management"
SECRET="$ROOT/secret"
RUNTIME_CONFIG="$ROOT/config/management"   # config-dir keyed by role SHORT name
LOCAL_CONFIG="/home/lwc/fanxiangdiguijiexi/deploy/tencent-cloud/config/hosts/ri-management/config"
WIZARD="$INSTALL_ROOT/wizard.py"
FQDN=ri-management.cloud.lab
ENV_PREFIX="sudo -n env DC_MIN_MEMORY_MB=1900"
STAGE=/tmp/ri-mgmt-config-stage

echo "== management: push rendered runtime config =="
rm -rf "$STAGE"
scp -q -r "$LOCAL_CONFIG" "$ALIAS:$STAGE"
ssh "$ALIAS" "sudo -n bash -c '
  set -e
  mkdir -p $RUNTIME_CONFIG
  cp -a $STAGE/. $RUNTIME_CONFIG/
  chown -R root:root $RUNTIME_CONFIG
  find $RUNTIME_CONFIG -type f -exec chmod 600 {} +
  rm -rf $STAGE
  echo CONFIG_PUSHED
'"

echo "== management: preflight =="
ssh "$ALIAS" "$ENV_PREFIX python3 '$WIZARD' preflight \
  --package-root '$INSTALL_ROOT/product-kit' --role management --expected-host '$FQDN' \
  --config-dir '$RUNTIME_CONFIG' --secret-dir '$SECRET' --images '$INSTALL_ROOT/images' \
  --install-root '$INSTALL_ROOT' --yes"

echo "== management: install --no-start =="
ssh "$ALIAS" "$ENV_PREFIX python3 '$WIZARD' install \
  --package-root '$INSTALL_ROOT/product-kit' --role management --expected-host '$FQDN' \
  --config-dir '$RUNTIME_CONFIG' --secret-dir '$SECRET' --images '$INSTALL_ROOT/images' \
  --install-root '$INSTALL_ROOT' --yes --no-start"

echo "== management: activate =="
ssh "$ALIAS" "$ENV_PREFIX python3 '$WIZARD' activate \
  --package-root '$INSTALL_ROOT/product-kit' --role management --expected-host '$FQDN' \
  --secret-dir '$SECRET' --install-root '$INSTALL_ROOT' --yes"

echo "== management setup complete =="
