# Vendored build dependency

This directory is the exact source tree of Knot Resolver's
`modules/policy/lua-aho-corasick` submodule at commit
`9f983c48af8ddddbcc38f34a4d589600b47645c1`.

The source is vendored because the authoritative GitLab endpoint rejects
unauthenticated GitHub-hosted runner clone requests. The parent Knot Resolver
source remains pinned to commit `124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e`
and is read from the official `CZ-NIC/knot-resolver` GitHub mirror. The Docker
build verifies every vendored file against `SHA256SUMS` before compilation.
