#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=preflight exec "$(dirname "$0")/common/lifecycle.sh" "$@"
