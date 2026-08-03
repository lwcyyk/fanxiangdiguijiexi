# Management secret contract

Management requires three independent, unencrypted Ed25519 private keys:

- `identity-issuer-ed25519-private-key`: PKCS#8 PEM.
- `snapshot-issuer-ed25519-private-key`: PKCS#8 PEM.
- `publication-ssh-identity`: OpenSSH private-key format.

The dedicated secret directory must be an absolute real directory owned by `root:root` with mode `0700`. Each file must be a regular non-symlink owned by `root:root` with mode `0600`. The preflight uses the installed `cryptography` library to parse each key, reject encrypted or malformed material, require Ed25519, derive public keys, and reject issuer duplicates or publication-key reuse.

For test fixtures only, run as root with the explicit flag:

```text
sudo python3 tools/generate_management_secrets.py --secret-dir /absolute/test-secrets --test-only
```

The generator refuses to overwrite existing files and prints only filenames, formats, algorithms, public-key SHA-256 fingerprints, and permissions. Its output is marked `TEST ONLY — NOT FOR PRODUCTION`; never use it for production or commit its output.

The SSH publication path uses `publication-ssh-identity` only for the authenticated non-simulation SSH tunnel. It requires pinned `known_hosts`, `IdentitiesOnly=yes`, `BatchMode=yes`, and `StrictHostKeyChecking=yes`; the private key is not mounted into the Norn container.

Management secret errors:

- `SEC201`/`SEC202`: unsafe directory or directory permissions.
- `SEC203`: missing, empty, symlink, or non-regular key file.
- `SEC204`: key file permissions are not exactly `0600`.
- `SEC211`: cryptography parser unavailable.
- `SEC212`: malformed, encrypted, wrong-format, or non-Ed25519 key.
- `SEC214`: issuer duplicate or publication-key reuse.
- `SEC215`: directory or file is not owned by `root:root`.
