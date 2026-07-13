# API Reference

本文只描述当前代码中实际存在的 HTTP 路由。生产 DNS 主路径是 Wrapper 的 UDP/TCP 监听器；HTTP Wrapper 主要用于 DoH、诊断和受控运维。

## 通用约定

- JSON 路由使用 UTF-8。
- DNS-over-HTTPS 使用 `application/dns-message`。
- `/healthz` 只表示进程存活。
- `/readyz` 会检查数据库；依赖 Registry 的服务还会检查 chain ID、合约代码和最新区块。
- 生产环境的 Admin 路由要求 `X-Admin-Token`。
- 未验证、证据不完整、撤销或依赖不可用且无有效缓存时，DNS 主路径返回 `SERVFAIL`，不得释放原始答案。

请求体限制：

| 服务 | 上限 |
|---|---:|
| Wrapper | 65,535 bytes |
| Agent | 65,536 bytes |
| Admin | 1 MiB |

## Wrapper

### DNS-over-HTTPS

`POST /dns-query`

- 请求：DNS wire-format message。
- 响应：验证成功时返回原始 DNS 响应；失败时返回 `SERVFAIL` wire message。
- 响应头：`X-Resolver-Identity-Request-Id`。

### 身份验证

`POST /v1/verify/resolver`

```json
{
  "endpoint": {
    "ip": "192.0.2.53",
    "port": 53,
    "transport": "udp"
  }
}
```

返回 `accepted`、`status`、`resolver_id`、`reasons` 和结构化 `evidence`。

`POST /v1/verify/query`

```json
{
  "observed_resolvers": [
    {"ip": "192.0.2.53", "port": 53, "transport": "udp"}
  ]
}
```

空列表会返回 `accepted=false` 和 `reason=no_observed_resolvers`。

### 缓存与证据

- `GET /v1/cache`
- `POST /v1/cache/invalidate/resolver/{resolver_id:path}?status=REVOKED`
- `POST /v1/cache/invalidate/root/{state_root}?status=REVOKED`
- `POST /v1/cache/refresh`
- `GET /v1/proofs/{request_id}`

生产撤销应通过 Registry 和 EventWatcher 传播；手工 invalidate 路由只用于受控运维和诊断。

### 状态

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`

指标包括 Wrapper 存活、DNS ALLOW/SERVFAIL 计数、验证计数和 gate latency 总和/次数。

## Indexer

Indexer 是非可信数据提供者；调用方必须将对象、proof 和 endpoint binding 与 Registry 锚点重新核对。

### 查询

- `GET /v1/lookup/ip/{ip}`
- `GET /v1/lookup/name/{name}`
- `GET /v1/resolvers/{resolver_id:path}`
- `GET /v1/resolvers/{resolver_id:path}/proof`
- `GET /v1/resolvers/{resolver_id:path}/status`
- `GET /v1/roots/{state_root}`
- `GET /v1/audit/logs?limit=100`

Audit `limit` 会被限制在 1 至 1,000。

### 状态

- `GET /healthz`
- `GET /readyz`

## Resolver Identity Agent

### 身份与配置

- `GET /v1/identity`
- `GET /v1/upstreams`

响应由 Agent Ed25519 私钥签名，包含 resolver ID、endpoint、upstreams、config version、签发/过期时间、issuer 和 key ID。Agent 响应不能自证可信；其公钥必须来自已经验证的 resolver identity object。

### 生产验证链

`POST /v1/verification-chain`

```json
{
  "challenge": "wrapper-generated-random-value-at-least-32-characters"
}
```

约束：

- challenge 长度为 32 至 256 个字符；
- 每个嵌套 `VerificationChain` 必须包含并签名同一个 challenge；
- Agent 只验证自己的相邻 upstream；
- downstream Agent 公钥来自已验证 hop evidence；
- loop、max depth、过期、config rollback、缺失 downstream chain 或 terminal overlap 都会失败关闭。

返回的 chain 包含：

- `resolver_id`、`endpoint`、`config_version`；
- 已签名 `hops`；
- 已签名 `downstream_chains`；
- `terminal_upstreams`；
- `chain_errors` 和 `final_result`；
- `issued_at`、`expires_at`、`issuer`、`key_id`、`signature`；
- 当前请求 challenge。

`GET /v1/verification-chain` 是无 challenge 的兼容/诊断接口，不得用于生产 Wrapper 信任决策。

### 兼容别名

- `GET /v1/agent/identity`
- `GET /v1/agent/observed-resolvers`
- `GET /v1/agent/verification-chain`

这些路由仅为早期客户端兼容保留。

### 状态

- `GET /healthz`
- `GET /readyz`

## Admin

生产请求必须携带：

```http
X-Admin-Token: <secret>
```

### 已实现

- `POST /v1/admin/resolvers`：构建、签名并幂等发布 resolver object、root、anchor 和 endpoint binding。
- `POST /v1/admin/resolvers/{resolver_id:path}/revoke`：链上永久撤销 resolver。
- `POST /v1/admin/roots/publish`：发布 root；已撤销 root 不能复活。
- `GET /healthz`
- `GET /readyz`

发布相同版本和相同内容会恢复未完成的 Indexer 写入；相同版本但内容不同或版本回退会拒绝。

### 明确未实现

- `POST /v1/admin/operators`：返回 HTTP 501。
- `POST /v1/admin/resolvers/{resolver_id:path}/endpoints`：返回 HTTP 501；端点变更必须发布更高版本 resolver object。

## 暴露策略

生产 Compose 默认只发布：

- DNS UDP/TCP 53；
- localhost Metrics；
- localhost Admin。

Indexer 和 Agent 应只存在于内部 control network。跨主机 Agent 链路必须使用 HTTPS；明文 HTTP 只允许精确列入 `RESOLVER_IDENTITY_AGENT_PLAINTEXT_HOSTS` 的内部主机。
