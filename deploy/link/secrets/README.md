# Link secrets

Create mode `0400` files owned by UID/GID `10002` (the non-root account in the
production image):

- `agent_private_key`: base64-encoded 32-byte Ed25519 private key unique to this DNS server;
- `trace_ingest_token`: at least 32 random bytes, unique to this link.
- `agent_wrapper_token`: at least 32 random bytes, unique to the local Wrapper/Agent pair.
- `agent_peer_credentials.json`: directional adjacent-Agent credentials. Each outbound
  entry binds one random token to an exact target `server_id`; the target has the matching
  inbound entry bound to the source `(server_id, key_id)`. Tokens must be unique per
  direction and must never be reused across directions, links, Wrapper, or Trace APIs.

Do not place issuer, Registry publisher, Registry revoker, endpoint manager, or
governance private keys on a link host.
