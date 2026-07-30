# Sepolia Deployment Artifacts

This directory contains public, non-secret evidence for the real Sepolia
preproduction deployment. Files are created by `scripts/sepolia/00` through
`12`; they must never be hand-edited to make an incomplete deployment appear
successful.

Expected public artifacts:

- `deployment.json`: contract deployment transaction and block.
- `verification.json`: two-RPC finalized bytecode and code-hash comparison.
- `roles.json`: role addresses and grant/revoke receipts.
- `identities-v2.unsigned.json`: reviewed identity payload before signing.
- `identities-v2.json`: signed public identities.
- `issuer-keys.json`: public Ed25519 issuer key bundle.
- `registry-plan-v2.json`: immutable publication plan.
- `publication-transactions.json`: phase and transaction receipts.
- `test-results.json`: predeployment Rust/Python/Foundry/Docker results.
- `runtime-files.sha256`: chain-link configuration transfer manifest.
- `deployment-manifest.json`: final evidence index and known gaps.

Secret inputs, password files and private keys belong under
`deployments/sepolia/private/`, `secrets/sepolia/`, or an external secret
manager. Those paths are ignored by Git. RPC URLs in committed artifacts must
be reduced to host names without credentials, paths or query strings.

An absent artifact means that stage has not completed. Example or zero values
must not be substituted for missing deployment results.
