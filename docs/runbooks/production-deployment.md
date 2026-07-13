# Resolver Identity Production Runbook

## Scope and ownership

This runbook operates the single-host Docker Compose production profile. Assign named owners for DNS operations, Registry administration, key custody, and on-call response before launch.

For a non-executing walkthrough with expected results, failure states, monitoring, recovery, and capacity scenarios, see [`../production_simulated_execution.md`](../production_simulated_execution.md). A simulated checklist is not production evidence.

## Prerequisites

- Linux host with Docker Engine and Docker Compose v2.
- Host firewall allowing DNS UDP/TCP from intended clients only.
- TLS-protected external EVM RPC endpoint.
- Foundry for first deployment or an already deployed Registry contract.
- Controlled first-hop resolver and a reachable Agent for every reported recursive/forwarding hop.
- Encrypted off-host backup destination.

## Initial preparation

1. Generate local secrets and the issuer trust bundle:

   ```bash
   PYTHONPATH=src python3 tools/prepare_production.py
   ```

2. Record the printed Web3 publisher address. Protect `deploy/secrets/` and its backup as restricted key material.
3. Edit `.env.production`. Replace every example RPC, contract, resolver, Agent, and terminal endpoint.
4. For remote Agents, place CA/certificate material in `deploy/tls/`, set the `/run/tls/...` paths in `.env.production`, and remove remote names from the plaintext allowlist.
5. Confirm file permissions:

   ```bash
   stat -c '%a %n' .env.production deploy/secrets deploy/secrets/*
   ```

   Expected: `.env.production` and secret files `600`; secret directory `700`.

## Registry deployment and roles

Deploy with a temporary administrator account when no Registry exists:

```bash
cd contracts
forge create src/ResolverIdentityRegistryV1.sol:ResolverIdentityRegistryV1 \
  --rpc-url "$RESOLVER_IDENTITY_WEB3_RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --constructor-args "$REGISTRY_ADMIN_ADDRESS"
```

Inspect the deployed identity and pin the exact output values in `.env.production`:

```bash
PYTHONPATH=src python3 tools/inspect_registry.py \
  --rpc-url "$RESOLVER_IDENTITY_WEB3_RPC_URL" \
  --contract-address "$RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS"
```

Verify the chain ID, contract address, and runtime code hash through a second trusted RPC or explorer before proceeding. Any later code-hash difference makes readiness fail.

The initial admin receives all roles. Grant the generated publisher only the roles it needs, normally root publisher, resolver publisher, and endpoint manager. Use a separate revoker account. Revoke unnecessary roles from the deployer after testing role recovery.

## Preflight

```bash
docker compose --env-file .env.production -f docker-compose.production.yml config --quiet
python3 -m pytest -q
cd contracts && forge test -vvv
```

Do not deploy if configuration rendering or either test suite fails.

## Build and deploy

```bash
docker compose --env-file .env.production -f docker-compose.production.yml build --pull
docker compose --env-file .env.production -f docker-compose.production.yml up -d
docker compose --env-file .env.production -f docker-compose.production.yml ps
```

Expected: all services, including EventWatcher and Admin, report healthy. EventWatcher health requires a recent successful synchronization cycle, not only a running process.

## Publish the first identity

Submit a resolver object whose `attestation.agent.public_key` equals the Agent public key printed by `prepare_production.py`. Authenticate every Admin request:

```bash
ADMIN_TOKEN="$(cat deploy/secrets/admin_api_token)"
curl --fail --silent --show-error \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data @resolver-object-request.json \
  http://127.0.0.1:8002/v1/admin/resolvers
```

Store the returned object hash, state root, resolver key, transaction receipt, and object version in the change record.

## Acceptance checks

```bash
curl --fail http://127.0.0.1:9108/readyz
curl --fail http://127.0.0.1:9108/metrics
dig @127.0.0.1 -p "${DNS_PORT:-53}" example.com A +tcp
dig @127.0.0.1 -p "${DNS_PORT:-53}" example.com A +notcp
```

Then test an unregistered resolver, invalid Agent signature, stopped Agent, resolver revocation, and root revocation. Every negative case must return `SERVFAIL` without the original answer.

## Backup

Create a verified online SQLite backup without stopping writers. The backup directory must be writable only by the image UID:

```bash
sudo install -d -m 700 -o 10001 -g 10001 "$PWD/backups"
BACKUP="resolver_identity-$(date -u +%Y%m%dT%H%M%SZ).db"
docker run --rm \
  -v fanxiangdiguijiexi_resolver-data:/data \
  -v "$PWD/backups:/backup" \
  resolver-identity-prototype:0.1.0-production \
  tools/db_admin.py --db /data/resolver_identity.db backup --output "/backup/$BACKUP"
docker run --rm \
  -v "$PWD/backups:/backup:ro" \
  resolver-identity-prototype:0.1.0-production \
  tools/db_admin.py --db "/backup/$BACKUP" verify
```

Record the printed SHA-256, encrypt and move the backup off-host. Back up `.env.production`, issuer trust bundle, TLS material, and secrets separately under the key-custody policy. Test restore quarterly.

For restore, stop every service, preserve the failed volume, verify the selected backup with the exact target image, replace the database as UID/GID `10001`, then start Indexer and EventWatcher before Agent, Wrapper, and Admin. Do not restore a database whose schema version is newer than the target image supports.

## Upgrade and rollback

1. Take a database and secret/config backup.
2. Build an immutable image tag and run all CI gates.
3. Deploy during a maintenance window and run acceptance checks.
4. Roll back application code by redeploying the previous image tag.
5. If a schema change is incompatible, stop all writers and restore the matching database backup.

Never roll back Registry object or Agent config versions. Publish a new higher version instead. A Registry contract rollback requires deployment of a new contract and an explicit trust-anchor change.

## Incident: Agent or RPC unavailable

- Confirm `/readyz`, container state, DNS decision metrics, and logs.
- Agent unavailable: strict mode returns `SERVFAIL`; restore Agent connectivity or use an already approved alternate resolver path.
- RPC unavailable: hot cache may operate until hard TTL. Restore RPC before expiry; do not increase TTL during the incident without security approval.
- Do not disable distributed verification or re-enable HMAC as an availability workaround.

## Incident: suspected key compromise

1. Isolate the affected service and revoke its Registry role or resolver identity.
2. Rotate the key from a clean workstation.
3. For Agent keys, publish a higher resolver object version binding the new public key, wait for invalidation, then restart the Agent with the new private key.
4. For issuer keys, distribute the new pinned public bundle before publishing objects signed by it.
5. Review audit logs and on-chain events, then document the exposure window.

## Incident: database lock or corruption

- Stop all services except one diagnostic container.
- Run SQLite integrity checking against a copy, not the only production file.
- Restore the most recent verified backup if integrity fails.
- Never place the SQLite volume on NFS or attach it to multiple hosts.

## Routine maintenance

- Daily: alert review, RPC/Agent health, failed DNS decisions, disk capacity.
- Weekly: dependency and image vulnerability scan, backup verification, and administrative audit retention:

  ```bash
  docker compose --env-file .env.production -f docker-compose.production.yml exec -T indexer \
    python tools/db_admin.py --db /var/lib/resolver-identity/resolver_identity.db prune-audit --retention-days 90
  ```

- Monthly: negative-path smoke tests and role review.
- Quarterly: restore drill, key rotation exercise, reorg/finality review, runbook update.
