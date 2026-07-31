#!/usr/bin/env bash
set -Eeuo pipefail
FIELD_ACTION=install exec "$(dirname "$0")/common/lifecycle.sh" "$@"
