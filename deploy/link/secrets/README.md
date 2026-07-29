# Link secrets

Create mode `0400` files owned by UID/GID `10002` (the non-root account in the
production image):

- `agent_private_key`: base64-encoded 32-byte Ed25519 private key unique to this DNS server;
- `trace_ingest_token`: at least 32 random bytes, unique to this link.
- `agent_wrapper_token`: at least 32 random bytes, unique to the local Wrapper/Agent pair.
- `agent_peer_token`: at least 32 random bytes, shared only by adjacent Agents in one
  actual DNS chain and never across L01/L02/L03.

Do not place issuer, Registry publisher, Registry revoker, endpoint manager, or
governance private keys on a link host.
