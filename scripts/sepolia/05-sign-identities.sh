#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq python3 install
load_sepolia_env
assert_sepolia_network
require_var RI_UNSIGNED_IDENTITIES_SOURCE
require_var ISSUER_PRIVATE_KEY_FILE
require_var ISSUER_PUBLIC_KEY_FILE
require_var ISSUER_ID
require_var ISSUER_KEY_ID
require_private_file "${ISSUER_PRIVATE_KEY_FILE}" "Issuer private key"
[[ -f "${ISSUER_PUBLIC_KEY_FILE}" ]] || die "Issuer public key file does not exist"
[[ -f "${RI_UNSIGNED_IDENTITIES_SOURCE}" ]] || die "unsigned identity source does not exist"

UNSIGNED="${SEPOLIA_DEPLOYMENTS}/identities-v2.unsigned.json"
SIGNED="${SEPOLIA_DEPLOYMENTS}/identities-v2.json"
ISSUER_KEYS="${SEPOLIA_DEPLOYMENTS}/issuer-keys.json"
install -m 0644 "${RI_UNSIGNED_IDENTITIES_SOURCE}" "${UNSIGNED}"

python3 - "${UNSIGNED}" <<'PY'
import base64
import binascii
import ipaddress
import json
import sys
import time
from urllib.parse import urlsplit

path = sys.argv[1]
payload = json.load(open(path, encoding="utf-8"))
items = payload.get("identities")
if not isinstance(items, list) or not items:
    raise SystemExit("identity input must contain a non-empty identities list")

now = int(time.time())
documentation_networks = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]
endpoint_owners = {}
agent_key_ids = set()
agent_public_keys = set()

def reject_placeholder(value, label):
    text = str(value)
    upper = text.upper()
    if "${" in text or "REPLACE" in upper or "EXAMPLE.INVALID" in upper:
        raise SystemExit(f"{label} contains a placeholder")

for identity in items:
    server_id = identity.get("server_id", "")
    reject_placeholder(server_id, "server_id")
    valid_from = int(identity.get("valid_from", 0))
    valid_until = int(identity.get("valid_until", 0))
    if valid_from > now + 300:
        raise SystemExit(f"{server_id}: valid_from is too far in the future")
    if valid_until < now + 86400:
        raise SystemExit(f"{server_id}: valid_until must extend at least 24 hours")
    if valid_until > now + 825 * 86400:
        raise SystemExit(f"{server_id}: validity exceeds the 825-day preproduction limit")
    for endpoint in identity.get("endpoints", []):
        address = ipaddress.ip_address(endpoint.get("ip", ""))
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
            or any(address in network for network in documentation_networks)
        ):
            raise SystemExit(f"{server_id}: endpoint is not a real preproduction address")
        key = (str(address), int(endpoint.get("port", 0)), endpoint.get("transport", "").lower())
        if key in endpoint_owners:
            raise SystemExit(f"endpoint is shared by {endpoint_owners[key]} and {server_id}")
        endpoint_owners[key] = server_id
    agent = identity.get("agent")
    if identity.get("role") in {"RECURSIVE", "FORWARDER"} and not agent:
        raise SystemExit(f"{server_id}: recursive/forwarder identity requires an Agent")
    if agent:
        reject_placeholder(agent.get("key_id", ""), "Agent key_id")
        reject_placeholder(agent.get("public_key", ""), "Agent public key")
        reject_placeholder(agent.get("service_url", ""), "Agent service_url")
        parsed = urlsplit(agent.get("service_url", ""))
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.endswith(".invalid"):
            raise SystemExit(f"{server_id}: Agent service_url must be a real HTTPS URL")
        try:
            key = base64.b64decode(agent.get("public_key", ""), validate=True)
        except (ValueError, binascii.Error) as error:
            raise SystemExit(f"{server_id}: Agent public key is invalid") from error
        if len(key) != 32 or key == bytes(32):
            raise SystemExit(f"{server_id}: Agent public key must be a nonzero Ed25519 key")
        key_id = agent.get("key_id", "")
        if key_id in agent_key_ids or key in agent_public_keys:
            raise SystemExit(f"{server_id}: Agent key must be unique")
        agent_key_ids.add(key_id)
        agent_public_keys.add(key)
PY

ISSUER_PUBLIC_KEY="$(
  python3 - "${ISSUER_PUBLIC_KEY_FILE}" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
try:
    value = json.loads(text)
except json.JSONDecodeError:
    print(text)
else:
    if isinstance(value, dict):
        if value.get("public_key"):
            print(value["public_key"])
        elif isinstance(value.get("keys"), list) and len(value["keys"]) == 1:
            print(value["keys"][0].get("public_key", ""))
        else:
            print("")
    else:
        print("")
PY
)"

python3 - "${ISSUER_PUBLIC_KEY}" <<'PY'
import base64
import binascii
import sys

try:
    key = base64.b64decode(sys.argv[1], validate=True)
except (ValueError, binascii.Error) as error:
    raise SystemExit("Issuer public key is invalid base64") from error
if len(key) != 32 or key == bytes(32):
    raise SystemExit("Issuer public key must be a nonzero Ed25519 public key")
PY

jq -n \
  --arg issuer "${ISSUER_ID}" \
  --arg key_id "${ISSUER_KEY_ID}" \
  --arg public_key "${ISSUER_PUBLIC_KEY}" \
  '{keys:[{issuer:$issuer,key_id:$key_id,algorithm:"ed25519",public_key:$public_key}]}' |
  write_json_atomic "${ISSUER_KEYS}"

jq -e \
  --arg issuer "${ISSUER_ID}" \
  --arg key_id "${ISSUER_KEY_ID}" \
  'all(.identities[]; .issuer == $issuer and .key_id == $key_id)' \
  "${UNSIGNED}" >/dev/null ||
  die "identity issuer/key_id does not match the pinned Issuer key"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" sign \
  --input "${UNSIGNED}" \
  --private-key-file "${ISSUER_PRIVATE_KEY_FILE}" \
  --output "${SIGNED}"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" verify-identities \
  --identities "${SIGNED}" \
  --issuer-keys "${ISSUER_KEYS}"

log "signed identities were independently verified with the pinned Issuer public key"
