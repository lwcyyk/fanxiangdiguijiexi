# 应用层双链路查询闭环

## 1. 正常 DNS 查询链路

本项目保留现有 DNS 查询链路，不修改 DNS 协议、DNS 报文格式、系统 DNS 配置、内核网络栈或底层网络设备。

应用侧看到的查询路径为：

```text
应用 / DNS 客户端
  -> 本地 DNS Verification Wrapper
  -> 已配置的递归解析器或转发解析器
  -> 正常 DNS 递归 / 转发 / 权威查询链路
  -> 返回原始 DNS 响应
```

Wrapper 只在应用层接收 UDP DNS、TCP DNS 或本地 DoH 请求，并把查询转发到配置中的上游解析器。DNS 响应返回后，Wrapper 不立即交给应用，而是进入 `PENDING_VERIFICATION` 状态。

本阶段实现不验证 DNS 数据本身；不引入 DNSSEC、TPM、TEE、路径回执或查询执行证明。

## 2. 带外身份认证链路

带外链路独立于正在被验证的 DNS 解析器，不通过该解析器获取认证材料。

身份认证链路为：

```text
本地 Verification Wrapper / QueryCoordinator
  -> 本地可信缓存
  -> 缓存未命中或 hard TTL 到期
  -> SQLite Indexer 读取完整 ResolverAuthenticityObjectV1 与 Merkle proof
  -> Registry anchor 读取 endpoint binding、object hash、object version、state root、status
  -> issuer key registry 验证 Ed25519 / 兼容 HMAC 签名
  -> 语义、状态、端点与有效期检查
```

Verifier 将 Indexer 视为不可信数据源。完整对象必须重新计算 canonical object hash，并与 registry anchor 对照；Merkle proof 必须重算到 registry anchor 中的 state root；root 与 resolver 状态必须为 `ACTIVE`。

## 3. 应用层结果暂存与放行

`QueryCoordinator` 实现双链路闭环：

```text
DNS 查询
  -> 转发到上游 resolver
  -> 暂存原始 DNS 响应
  -> ResolverChainProvider 返回可观测 resolver 列表
  -> 逐个/并行验证 resolver 身份
  -> 全部通过：返回原始 DNS 响应
  -> 任一失败：丢弃原始响应并返回 SERVFAIL
```

关键规则：

- DNS 查询成功不代表响应可被应用使用。
- 原始 DNS 响应只有在所有可观测 resolver 身份验证通过后才放行。
- 任一 resolver 身份失败时，原始 DNS 响应不得返回给应用。
- 无可观测 resolver 时，严格模式下拒绝并返回 SERVFAIL。
- 不允许身份认证失败后静默降级为“直接信任 DNS 响应”。

## 4. 可观测解析器边界

系统只验证应用层能够明确观测或配置的解析器，不猜测标准 DNS 协议中无法观测的中间递归器。

已实现抽象：

- `ResolverChainProvider`
  - 可观测 resolver 列表的抽象接口。
- `FirstHopResolverProvider`
  - 返回客户端实际配置并连接的第一跳 resolver。
- `StaticResolverChainProvider`
  - 从受控环境配置读取 R1、R2、R3 等 resolver 链。

边界说明：

- 第一跳 resolver 可由 wrapper 上游配置直接确定。
- 受控多级转发环境可由静态配置或未来 Agent API 提供。
- 未被配置、未被 Agent 报告、无法从应用层明确观测的中间 resolver 不会被猜测。

## 5. 项目信任假设

本文采用的项目信任前提为：

> 只要解析器身份真实、合法、未过期且未撤销，就认为其返回的 DNS 结果可信。

因此，本项目验证的是“本次查询涉及的 resolver 是否可信”，而不是 DNS 结果内容是否被权威链路或 DNSSEC 证明。

不解决的问题包括：

- 合法 resolver 是否返回了错误 DNS 数据。
- 权威服务器身份是否可信。
- 域名数据自身完整性。
- 完全不可观测的隐藏中间 resolver。

## 6. 本地可信缓存策略

客户端本地可信缓存独立于 Indexer，用于热路径身份验证。

缓存层级：

```text
内存缓存
  -> SQLite trusted_cache 持久缓存
  -> Indexer + Registry 完整验证
```

缓存绑定不是“某个 IP 可信”，而是绑定完整身份与端点：

- `resolver_id`
- IP
- port
- transport
- server_name / URI
- `object_version`

缓存保存：

- `object_hash`
- `state_root`
- `verified_at`
- `soft_expire_at`
- `hard_expire_at`
- `status`
- endpoint JSON
- 验证 evidence

缓存状态：

- `VERIFIED`
- `REFRESHING`
- `EXPIRED`
- `REVOKED`

规则：

- soft TTL 内：直接使用本地缓存。
- soft TTL 到期但未超过 hard TTL：允许本次使用，并标记为 `REFRESHING`，触发后台刷新。
- hard TTL 到期：不得继续信任，必须重新完整验证。
- resolver 被撤销：关联缓存立即标记为 `REVOKED`。
- root 被撤销：关联缓存立即标记为 `REVOKED`。
- endpoint binding、object hash、object version 或 state root 变化：旧缓存标记为 `EXPIRED`。

## 7. 撤销与刷新

当前阶段不伪造链上事件。在没有真实事件监听时，系统提供明确的轮询/刷新与 invalidate API：

- `POST /v1/cache/invalidate/resolver/{resolver_id}`
- `POST /v1/cache/invalidate/root/{state_root}`
- `POST /v1/cache/refresh`

`refresh_registry_state` 会比较缓存 evidence 与当前 registry 状态：

- endpoint binding 不一致 -> `EXPIRED`
- anchor 缺失 -> `EXPIRED`
- object version 改变 -> `EXPIRED`
- object hash 改变 -> `EXPIRED`
- state root 改变 -> `EXPIRED`
- resolver/root 为 `REVOKED` -> `REVOKED`

## 8. Fail-closed 规则

以下场景必须拒绝并返回 SERVFAIL：

- 无可观测 resolver。
- resolver 未注册。
- endpoint binding 不匹配。
- chain anchor 缺失。
- resolver status 不是 `ACTIVE`。
- root status 不是 `ACTIVE`。
- object hash 与 registry anchor 不一致。
- object version 与 registry anchor 不一致。
- Merkle proof 缺失或无法重算到 state root。
- issuer/key_id 找不到或签名验证失败。
- identity object 过期或尚未生效。
- endpoint 不在 identity object 中。
- hard TTL 到期且带外链路不可用。

失败时：

```text
丢弃原始 DNS 响应
  -> 返回 SERVFAIL
```

## 9. 审计日志

每次查询决策记录 `QueryDecision` 审计事件，字段包括：

- `request_id`
- `qname`
- `qtype`
- resolver 列表
- cache hit / miss / stale-hit-refreshing
- verification results
- `object_hash`
- `state_root`
- final decision
- failure reason
- total latency

审计日志不得记录私钥、secret、助记词或完整 RPC URL。
