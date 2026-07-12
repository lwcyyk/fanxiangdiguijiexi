# Agent TLS material

Place the production CA bundle and optional mTLS client certificate/key in this directory, then reference their container paths under `/run/tls` from `.env.production`.

Do not commit certificate or key files. Keep private keys mode `0600` and this directory mode `0700` on the production host.
