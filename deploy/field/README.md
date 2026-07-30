# Domain-center field deployment assets

This directory contains non-secret templates for the star-topology deployment.
The link runtime remains `deploy/link/docker-compose.yml`.

Never put a real site inventory, rendered bundle, RPC credential, private key,
token, or TLS private key in this directory. Use:

```text
deployments/field/private/
```

The center management host validates a private inventory and renders one
independent bundle per link unit:

```bash
python3 tools/manage_field_deployment.py validate \
  --inventory /secure/field/site-inventory.json

scripts/field/01-render-bundles.sh \
  /secure/field/site-inventory.json \
  deployments/field/private
```

Prometheus templates are under `prometheus/`. Replace all placeholders and use a
different Agent metrics client certificate for each link. HTTP metrics ports
must only be reachable from the operations management network.
