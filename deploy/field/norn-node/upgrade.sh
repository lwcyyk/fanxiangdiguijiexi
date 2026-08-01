#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=upgrade exec "$(dirname "$0")/common/lifecycle.sh" "$@"
