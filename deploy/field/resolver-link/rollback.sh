#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=rollback exec "$(dirname "$0")/common/lifecycle.sh" "$@"
