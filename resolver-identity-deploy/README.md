# Resolver Identity RC14 offline install

This package installs one resolver-link node with the verified RC14 Rust data-plane image. It does not perform remote orchestration.

## Prepare

1. Install Docker Engine with the Compose plugin and `dig`/`curl`.
2. Copy `config/node.env.example` to `config/node.env` and fill the node-specific paths and addresses.
3. Place the node's existing configuration and out-of-band secret/TLS directories at the paths named in `config/node.env`. The installer does not create, print, or modify credentials.
4. Keep `RI_VERIFICATION_MODE=controlled-strict` and `RI_REGISTRY_MAX_STALENESS_SECONDS=45`.

## Install

```bash
sudo ./install.sh
```

For R1 set:

```text
RI_NODE_ROLE=first-hop
```

For R2/R3 use `RI_NODE_ROLE=resolver` or omit it.

## Check

```bash
sudo ./check.sh
```

The check verifies container state, the RC14 `ri-registry-sync` binary, Registry/Trace readiness and, for a first-hop node, a DNSSEC query through Wrapper.
