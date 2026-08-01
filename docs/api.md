# Rust V2 API

生产 DNS 入口是 `ri-wrapper` 的 UDP/TCP 监听器。以下 HTTP API 只存在于 Agent
和 Wrapper 监控面，生产环境均应由网络 ACL 和 mTLS 保护。

## Agent

### `POST /v2/evidence-graph`

请求：

```json
{
  "trace_id": "wrapper-generated-id",
  "correlation_id": "0x<32-byte-sha256>",
  "challenge": "at-least-32-random-characters",
  "query_digest": "0x<32-byte-sha256>",
  "response_digest": "0x<32-byte-sha256>",
  "visited_server_ids": []
}
```

该端点只接受本机 Wrapper token，并要求 Wrapper 已在共享 Store 登记一次性查询
上下文。Agent 只能占用登记行边界之后产生、尚未被其他请求占用且精确匹配
correlation/query/response 的本地最终响应。调用方不能提交路径、节点或切换匹配
模式。响应为已签名 `QueryEvidenceGraphV2`。

### `POST /v2/downstream-evidence-graph`

只接受相邻 Agent 的 peer token，用于递归子图获取；请求必须携带父级真实 Resolver
事件生成的 `target_correlation_id`，目标 Agent 只接受精确
correlation/query/response 绑定，不使用时间、qname 或“最近响应”进行关联。
`visited_server_ids` 由 Agent 维护以阻断环路。它与 Wrapper 端点分离，peer token
不能调用本地 Wrapper 端点。

### `POST /v2/attest-response`

该端点只接受相邻 Agent peer token。请求同时携带目标查询的 `correlation_id`。
受控目标 Agent 只有在本地找到相同
correlation、query digest、response digest 和 endpoint 的实际响应事件时才返回
`TargetResponseAttestationV2`。响应中的观察时间来自本地事件，不采用请求方提交的
时间。

### `POST /v2/trace-events`

写入一个 `TraceEventV2`。要求：

- `Authorization: Bearer <link-unique-token>`；
- observer server ID 必须等于本 Agent；
- schema、digest、correlation、时间窗口和字段通过校验；
- outbound query/response 事件必须携带目标请求的 `target_correlation_id`。
- CacheHit 必须显式携带 TTL 和精确的 source graph digest；
- `event_id` 不可变；完全相同的重试是幂等操作，内容冲突会被拒绝。

### `POST /v2/trace-events/batch`

一次写入 1 至 1024 个事件，全部校验后在一个 SQLite 事务中提交。Trace Adapter
生产使用该接口。

### 状态

- `GET /healthz`：进程存活；
- `GET /readyz`：本机 identity 存在、issuer 签名有效、Registry 状态有效，并且
  Agent 私钥与 identity 中绑定的 key ID/public key 相同。
- `GET /metrics`：证据图请求/失败和 Trace 摄入计数，位于同一 mTLS 监听器。

Agent 生产服务强制客户端证书认证；Wrapper、peer Agent 和 Trace 摄入还使用三个
用途隔离的 bearer token。
`RI_AGENT_MAX_AGE_SECONDS` 必须在 1 至 60 秒之间。
HTTP 并发数和请求体分别受 `RI_AGENT_MAX_CONCURRENT_REQUESTS` 与
`RI_AGENT_MAX_REQUEST_BODY_BYTES` 限制；该字节上限也约束 Agent 从相邻 Agent
读取的响应证明和子图。

## Wrapper 监控面

- `GET /healthz`：进程存活；
- `GET /readyz`：最近一次 Agent 深度就绪探测成功，且 Wrapper 本地 Registry
  快照心跳仍在允许窗口内；
- `GET /metrics`：Prometheus 文本格式。

主要指标：

- `resolver_identity_dns_queries_total`
- `resolver_identity_dns_accepted_total`
- `resolver_identity_dns_servfail_total`
- `resolver_identity_dns_overloaded_total`
- `resolver_identity_upstream_failures_total`
- `resolver_identity_verification_failures_total`
- `resolver_identity_dns_inflight`
- `resolver_identity_ready`

## DNS 行为

Wrapper 支持 UDP 和 TCP。请求超过并发上限、上游超时/异常、Agent 超时、证据图
无效、撤销、DNSSEC 不满足或 Trace 缺失时，均返回与原请求 transaction ID 对应的
`SERVFAIL`，不会返回暂存的原始答案。
上游响应还必须与请求的 opcode、question count、规范化 qname、qtype 和 qclass
逐项一致；畸形或循环 DNS name compression 会被拒绝。

TCP 入口另受 `RI_WRAPPER_MAX_TCP_CONNECTIONS` 和
`RI_WRAPPER_TCP_IO_TIMEOUT_MS` 约束。连接上限耗尽时直接关闭新连接；DNS 帧读写
超过空闲时限时关闭该连接，避免慢连接长期占用文件描述符。Agent 返回体受
`RI_WRAPPER_MAX_AGENT_RESPONSE_BYTES` 限制。

Wrapper 为发往 R1 的每个活动请求分配唯一内部 DNS transaction ID，并按以下公式
生成关联值：

```text
correlation_id =
  SHA-256("dns-correlation-v2:" + transaction_id_hex + ":" + dns_wire_digest)
```

`dns_wire_digest` 是把 DNS 报文 transaction ID 两字节清零后计算的 SHA-256。
Resolver Trace 生产者必须对进入本解析上下文的 wire message 使用相同算法，并将
该 `correlation_id` 写入本上下文的全部事件；转发到下一 DNS 服务时，再对实际
outbound wire message 计算下一跳关联值并写入 `target_correlation_id`。下游解析器
以该值作为其解析上下文的 `correlation_id`。Wrapper 只接受关联值、查询摘要和响应
摘要均精确匹配的证据图，之后恢复客户端原 transaction ID。内部 transaction ID 在
`RI_WRAPPER_TRANSACTION_ID_REUSE_DELAY_MS` 冷却期内不得复用。不能使用 qname、
宽松时间窗口或“最新一条相同摘要”替代关联值。

## Registry Sync 与 Trace Adapter 监控面

- Registry Sync：`GET /healthz`、`GET /readyz`、`GET /metrics`，默认映射到主机
  `127.0.0.1:9109`；JSON-RPC 响应受 `RI_RPC_MAX_RESPONSE_BYTES` 限制。
- Trace Adapter：`GET /healthz`、`GET /readyz`、`GET /metrics`，默认映射到主机
  `127.0.0.1:9110`；指标包含 spool 待传数和 dead-letter 数。

## Python V1

`/v1/*` 路由仍保留在 Python 原型中，用于历史实验和迁移回归，不属于 Rust V2
生产 Compose 的接口，不应与 V2 Agent 混用。
