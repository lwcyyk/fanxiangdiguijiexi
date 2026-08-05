#!/usr/bin/env bash
# Host-side deployment of the Docker-29-adapted OCI image loader.
#
#   deploy-loader-docker29.sh <host>...
#
# <host> is a cloud alias name (norn-a, r1, ...) resolved to its SSH alias
# ri-<host>-cloud in ~/.ssh/config.d/ri-tencent-cloud.
#
# For each host:
#   1. Backs up the frozen loader to product-kit/common/load_images.py.frozen
#      (first time only).
#   2. Installs the Docker-29-adapted loader at product-kit/common/load_images.py
#      (outside role_root, so the installer's role_sha256/config_sha256/
#      images_sha256 digests are unchanged).
#   3. Runs the standalone load (sudo env DC_MIN_MEMORY_MB=1900 python3 ...) so
#      all archives for the role are imported and verified before norn-generate
#      and install.
#
# Nothing is written to the frozen repo; this only mutates the extracted host
# runtime tree under /opt on each host.
set -Eeuo pipefail

PATCHED="$(cd "$(dirname "$0")" && pwd)/load_images.docker29.py"
INSTALL_BASE=/opt/domain-center-install/cloud-928ed0e/install

for host in "$@"; do
  alias="ri-${host}-cloud"
  root="$INSTALL_BASE/ri-${host}"
  echo "=== $alias ($host) ==="
  ssh "$alias" "test -f '$root/product-kit/common/load_images.py'" \
    || { echo "FATAL: no host package tree at $root on $alias" >&2; exit 1; }

  scp -q "$PATCHED" "$alias:/tmp/load_images.docker29.py"

  # Back up the frozen loader once, then install the adapted one.
  ssh "$alias" "sudo -n bash -c '
    set -e
    PK=$root/product-kit/common/load_images.py
    [ -f \$PK.frozen ] || cp -a \$PK \$PK.frozen
    install -m 0644 -o root -g root /tmp/load_images.docker29.py \$PK
    echo LOADER_INSTALLED host=\$(hostname) sha=\$(sha256sum \$PK | cut -d\" \" -f1)
  '"

  # Standalone load + verify (also validates every archive sha256 up front).
  ssh "$alias" "sudo -n env DC_MIN_MEMORY_MB=1900 python3 '$root/product-kit/common/load_images.py' '$root/images'" \
    || { echo "FATAL: image load failed on $alias" >&2; exit 1; }

  rm -f /tmp/load_images.docker29.py
  echo "=== $host OK ==="
done
