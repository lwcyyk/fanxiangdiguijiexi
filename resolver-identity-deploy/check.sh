#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=${1:-$ROOT/config/node.env}
COMPOSE=$ROOT/compose/docker-compose.yml
EXPECTED_REGISTRY_SYNC=7be62dc1b6a7c71fc975481036be3a2ac548dda67b4e10f037afdfc0d0352545

[ -f "$ENV_FILE" ] || { echo "missing node environment: $ENV_FILE" >&2; exit 1; }
set -a
. "$ENV_FILE"
set +a

docker compose --env-file "$ENV_FILE" -f "$COMPOSE" ps
container=$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE" ps -q registry-sync)
[ -n "$container" ]
[ "$(docker inspect "$container" --format '{{.State.Status}}')" = running ]
[ "$(docker inspect "$container" --format '{{.RestartCount}}')" = 0 ]
actual=$(docker exec "$container" sha256sum /usr/local/bin/ri-registry-sync | cut -d' ' -f1)
[ "$actual" = "$EXPECTED_REGISTRY_SYNC" ]

management=${RI_MANAGEMENT_BIND_ADDRESS:?required}
registry_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://$management:9109/readyz")
[ "$registry_code" = 204 ]
trace_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://$management:9110/readyz")
[ "$trace_code" = 204 ]

if [ "${RI_NODE_ROLE:-resolver}" = first-hop ]; then
  dns_address=${DNS_BIND_ADDRESS:?required}
  dns_port=${DNS_PORT:-53}
  dig @"$dns_address" -p "$dns_port" www.ri-test.invalid A +dnssec +time=10 +tries=1 |
    grep -q 'status: NOERROR'
fi

echo "resolver identity deployment check passed"
