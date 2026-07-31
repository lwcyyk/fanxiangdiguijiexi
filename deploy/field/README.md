# Go-Norn field delivery templates

This directory is the non-secret source for three field packages:

- `management`: offline identity/snapshot tooling and controlled Norn publication;
- `norn-node`: one Go-Norn node plus an mTLS read-only proxy;
- `resolver-link`: `first-hop` or `upstream` Rust data-plane units.

`inventory.example.yaml` uses JSON syntax, which is valid YAML 1.2. The renderer
uses the Python standard library and therefore intentionally accepts this
restricted, duplicate-key-safe YAML subset.

Render a release without secrets:

```bash
python3 tools/manage_norn_field_delivery.py validate \
  --inventory deploy/field/inventory.example.yaml --template

python3 tools/manage_norn_field_delivery.py render \
  --inventory /secure/inventory.yaml \
  --output-root artifacts/field-deployment
```

Generated packages contain no private key, password, token, certificate or
database. Each target host mounts its private material from a separately
controlled directory described in `secret-requirements.json`.

The current repository has a production Trace consumer and verification data
model, but it does not include a production BIND, Unbound, Knot Resolver or
PowerDNS Recursor Trace producer. Every generated manifest therefore sets
`production_trace_ready=false` and records a P0 cutover blocker.
