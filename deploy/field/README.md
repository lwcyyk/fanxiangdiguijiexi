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

The inventory pins two independent HTTPS RPC providers and four non-secret
Registry evidence files: finalized bytecode verification, role separation,
the immutable publication plan, and all five publication phases. Rendering is
refused when these artifacts disagree with the signed identities or when the
Agent private key does not derive the public key in its identity.

The currently verified Sepolia Registry is
`0x519c70babf33771b8e87c22fd3e2e1b1092e1e2a`, with runtime code hash
`0x3ff1c0bc964b2751a4006fa9bc54f8a1e1bb04872f62fabaf3eef52132e0a2d3`.
Root, Resolver identity, and Endpoint publication remain required before a
field bundle can pass the production validator.

Prometheus templates are under `prometheus/`. Replace all placeholders and use a
different Agent metrics client certificate for each link. HTTP metrics ports
must only be reachable from the operations management network.
