# Go-Norn field delivery templates

The integrated release candidate version is `0.3.0-norn-knot-rc1`.

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

The repository includes one production Trace integration: Knot Resolver 6.3.0
at pinned upstream commit `124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e`.
The renderer sets `production_trace_ready=true` only when it receives the
script-generated acceptance file for the exact release commit. Without that
evidence it keeps `production_trace_ready=false` and records a P0 blocker.
Every rendered manifest also records `field_package_ready`,
`real_server_deployed`, and `production_traffic_enabled`; rendering never
changes either deployment flag to true.
