#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=uninstall exec "$(dirname "$0")/common/lifecycle.sh" "$@"
