# Link TLS files

The production Compose profile requires:

- `agent.crt`, `agent.key`: Agent server certificate with SAN `agent`;
- `client-ca.crt`: CA accepted by the Agent server;
- `wrapper-client.crt`, `wrapper-client.key`: Wrapper client identity;
- `trace-client.crt`, `trace-client.key`: Trace adapter client identity;
- `agent-client.crt`, `agent-client.key`: Agent identity for adjacent Agent calls;
- `agent-ca.crt`: CA used to verify Agent servers.

Issue separate certificates per service and link. Make private keys mode `0400`
and owned by UID/GID `10002`; public certificates and CA files may be `0444`.
Do not reuse certificates between L01, L02, or L03. Compose mounts only the files
needed by each container, never the complete TLS directory.
