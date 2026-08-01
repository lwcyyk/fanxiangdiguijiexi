#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=health-check exec "$(dirname "$0")/common/lifecycle.sh" "$@"
