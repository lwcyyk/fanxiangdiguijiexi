#!/bin/bash
# Step 1: Read-only diagnostics for all 3 resolver hosts
set -e

for HOST in 1.13.159.107 118.195.130.7 118.195.189.105; do
  echo ""
  echo "================================================================"
  echo "=== HOST: $HOST ==="
  echo "================================================================"

  echo ""
  echo "--- registry_max_staleness_seconds (agent container env) ---"
  ssh ubuntu@$HOST "sudo docker inspect ri-r*-agent-1 --format '{{.Name}} {{range .Config.Env}}{{.}} {{end}}' 2>&1 | tr ' ' '\n' | grep RI_REGISTRY_MAX" 2>&1 || echo "FAILED"

  echo ""
  echo "--- DB heartbeat + cache_generation ---"
  ssh ubuntu@$HOST "sudo python3 << 'PYEOF'
import sqlite3, time, os, glob
# Find the evidence DB
db_paths = glob.glob('/var/lib/resolver-identity/ri-r*/evidence-v2.db')
if not db_paths:
    print('NO DB FOUND')
else:
    db_path = db_paths[0]
    print(f'DB: {db_path}')
    db = sqlite3.connect(db_path)
    rows = db.execute(\"SELECT meta_key, meta_value FROM ri_v2_meta WHERE meta_key IN ('registry_last_success_epoch', 'cache_generation', 'registry_finalized_block')\").fetchall()
    d = dict(rows)
    for k,v in rows:
        print(f'  {k}={v}')
    now = int(time.time())
    last = int(d.get('registry_last_success_epoch', 0))
    diff = now - last
    print(f'  now={now}')
    print(f'  heartbeat_age_seconds={diff}')
    print(f'  threshold=45')
    print(f'  EXCEEDS_THRESHOLD={\"YES\" if diff > 45 else \"no\"}')
    count = db.execute('SELECT COUNT(*) FROM ri_v2_identities').fetchone()[0]
    print(f'  identity_count={count}')
PYEOF" 2>&1 || echo "FAILED"

  echo ""
  echo "--- Registry-sync reconciliation intervals (last 10) ---"
  ssh ubuntu@$HOST "sudo docker logs ri-r*-registry-sync-1 --tail 10 2>&1 | grep 'finalized Registry' | awk '{print \$1}' | while read ts; do echo \$ts; done" 2>&1 || echo "FAILED"

  echo ""
  echo "--- Agent /readyz ---"
  ssh ubuntu@$HOST "sudo docker exec \$(sudo docker ps --format '{{.Names}}' | grep 'ri-r.-agent') wget -qO- --no-check-certificate https://localhost:8443/readyz 2>&1" 2>&1 || echo "FAILED (expected if agent stale)"

  echo ""
  echo "--- Agent /healthz ---"
  ssh ubuntu@$HOST "sudo docker exec \$(sudo docker ps --format '{{.Names}}' | grep 'ri-r.-agent') wget -qO- --no-check-certificate https://localhost:8443/healthz 2>&1" 2>&1 || echo "FAILED"

  echo ""
  echo "--- Registry-sync /readyz ---"
  ssh ubuntu@$HOST "curl -sk -o /dev/null -w '%{http_code}' https://\$(sudo docker inspect \$(sudo docker ps --format '{{.Names}}' | grep 'ri-r.-registry-sync') --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'):9109/readyz 2>&1)" 2>&1 || echo "FAILED"

  echo ""
  echo "--- Container status ---"
  ssh ubuntu@$HOST "sudo docker ps --format 'table {{.Names}}\t{{.Status}}' | grep ri-r" 2>&1 || echo "FAILED"
done

echo ""
echo "=== STEP 1 COMPLETE ==="
