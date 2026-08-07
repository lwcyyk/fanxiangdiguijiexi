#!/bin/bash
# Diagnostic script for R1 resolver
set -e

HOST=$1
if [ -z "$HOST" ]; then
    echo "Usage: $0 <host>"
    exit 1
fi

echo "=== $(date -u) ==="
echo "=== Containers ==="
ssh ubuntu@$HOST "sudo docker ps --format '{{.Names}} {{.Status}}'" 2>&1

echo ""
echo "=== Agent logs (last 5) ==="
ssh ubuntu@$HOST "sudo docker logs ri-r1-agent-1 --tail 5 2>&1 || echo 'NO LOGS'"

echo ""
echo "=== Registry-sync logs (last 3) ==="
ssh ubuntu@$HOST "sudo docker logs ri-r1-registry-sync-1 --tail 3 2>&1 || echo 'NO LOGS'"

echo ""
echo "=== DB check ==="
ssh ubuntu@$HOST "sudo python3 << 'PYEOF'
import sqlite3, time
db = sqlite3.connect('/var/lib/resolver-identity/ri-r1/evidence-v2.db')
rows = db.execute(\"SELECT meta_key, meta_value FROM ri_v2_meta WHERE meta_key IN ('registry_last_success_epoch', 'cache_generation')\").fetchall()
d = dict(rows)
for k,v in rows:
    print(f'{k}={v}')
now = int(time.time())
last = int(d.get('registry_last_success_epoch', 0))
print(f'now={now}')
print(f'diff={now - last}s')
print(f'count_identities={db.execute(\"SELECT COUNT(*) FROM ri_v2_identities\").fetchone()[0]}')
PYEOF" 2>&1

echo ""
echo "=== Agent healthz from inside ==="
ssh ubuntu@$HOST "sudo docker exec ri-r1-agent-1 wget -qO- --no-check-certificate https://localhost:8443/healthz 2>&1 || echo 'healthz FAILED'"

echo ""
echo "=== Agent readyz from inside ==="
ssh ubuntu@$HOST "sudo docker exec ri-r1-agent-1 wget -qO- --no-check-certificate https://localhost:8443/readyz 2>&1 || echo 'readyz FAILED'"

echo ""
echo "=== Agent process ==="
ssh ubuntu@$HOST "sudo docker exec ri-r1-agent-1 ps aux 2>&1 || echo 'ps FAILED'"

echo ""
echo "=== Done ==="
