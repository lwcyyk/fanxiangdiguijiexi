# Agent TLS material

This directory belongs to the legacy Python V1 deployment only.

Place the legacy CA bundle and optional mTLS client certificate/key here, then
reference their container paths under `/run/tls` from `.env.legacy-python`.

New Rust V2 link deployments use `deploy/link/tls/` and
`deploy/link/docker-compose.yml`.

Do not commit certificate or key files. Keep private keys mode `0600` and this directory mode `0700` on the production host.
