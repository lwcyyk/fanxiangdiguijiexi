# Sepolia Deployment Artifacts

This directory contains public, non-secret evidence for the real Sepolia
preproduction deployment. Files are created by `scripts/sepolia/00` through
`12`; they must never be hand-edited to make an incomplete deployment appear
successful.

Expected public artifacts:

- `deployment.json`: contract deployment transaction and block.
- `verification.json`: two-RPC finalized bytecode and code-hash comparison.
- `roles.json`: role addresses and grant/revoke receipts.
- `rejected-candidate-address.json`: two-RPC evidence for a supplied address
  rejected because it had no runtime bytecode.
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

## Current deployment

The following Registry deployment completed on Ethereum Sepolia on 2026-07-30:

- Chain ID: `11155111`
- Registry: `0x519c70babf33771b8e87c22fd3e2e1b1092e1e2a`
- Deployment transaction:
  `0x1c84f14dc9be0ad4ed1eb36f41142761773a81eb6b0c31c8cba16b5205884918`
- Deployment block: `11380297`
- Finalized verification block: `11380319`
- Runtime code hash:
  `0x3ff1c0bc964b2751a4006fa9bc54f8a1e1bb04872f62fabaf3eef52132e0a2d3`
- Role split: complete; eight grant/revoke transactions succeeded and
  `adminCount` is `1`.

The previously supplied candidate
`0x381766b18497993d153c76bF55004358E2238AEb` was not reused: both independent
RPCs returned empty runtime bytecode at latest and finalized, so it is an EOA,
not a Registry contract. See `rejected-candidate-address.json`.

`deployment.json`, `verification.json`, and `roles.json` are the authoritative
machine-readable evidence. Identity publication remains blocked because real
DNS endpoints, Agent HTTPS URLs, and per-Agent Ed25519 public keys have not yet
been supplied. Therefore no Root, Resolver, or Endpoint publication is claimed,
and `deployment-manifest.json` has not been generated.
