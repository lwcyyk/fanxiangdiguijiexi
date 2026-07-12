Create `deploy/secrets/` with mode `0700` and these files with mode `0600`:

- `admin_api_token`: at least 32 random bytes, encoded as text.
- `agent_private_key_b64`: base64-encoded raw Ed25519 private key for this Agent.
- `issuer_private_key_b64`: base64-encoded raw Ed25519 issuer key used by Admin.
- `web3_private_key`: EVM publisher private key. Use a dedicated least-privilege account.

Never commit the populated directory.
