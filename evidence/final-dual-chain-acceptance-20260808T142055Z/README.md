# RC14 最终双链路验收证据

## 正式查询

- UTC：`2026-08-08T14:20:55Z`
- DNS transaction ID：`63690`
- 查询：`www.ri-test.invalid. AAAA`
- Wrapper：`10.206.16.14:1053/udp`
- 结果：`NOERROR`、`AD=true`、包含 `RRSIG`
- AAAA：`2001:db8::10`
- Wrapper request trace：`3e570b54ff0af0ff848892bb83dc17ce`
- Resolver producer trace：`knot-ce0c018d646b4415bee697db853e7c31`
- Evidence Graph：`0x724da06e7046cd8afd3294467f07205031e40dc1453e93a67adaddcdc63f5f56`
- Registry generation：`3`
- Registry state root：`0x43d79c30546d28af891965e81162bb6c471d4a01b95fb16b2469226a548b042a`

## 已实际证明

1. Wrapper 返回了成功的 DNSSEC 响应，响应摘要与 Evidence Graph 顶层 `response_digest` 相同。
2. Graph 为 `CONTROLLED_STRICT`，`final_result=true`，`graph_errors=[]`。
3. Graph 包含 R1、R2、R3、Auth DNS 四个 ACTIVE、MATCHED、accepted 身份节点。
4. Graph 包含真实的 R1→R2、R2→R3、R3→Auth DNS 边；本次解析发生重试，因此每种关系各出现两条真实边，均有目标 Agent attestation 且 `accepted=true`。
5. 四台数据库的 Trace Event 通过逐跳 `target_correlation_id`、query digest 和 response digest 对齐。
6. 停止 R1 Agent 后，相同查询由 Wrapper 返回 SERVFAIL；Wrapper 日志明确记录 Agent 请求失败和 DNS response rejected。

## 由代码结构证明

Wrapper 在拿到 Resolver 响应后先计算 response digest，再调用 Agent；只有验证返回 `Ok(())` 时，才恢复客户端 transaction ID 并返回原始 DNS 响应。验证失败走 `make_servfail`。代码位置：

- `rust/crates/ri-wrapper/src/lib.rs:242-278`
- `rust/crates/ri-wrapper/src/lib.rs:185-200`
- `rust/crates/ri-wrapper/src/lib.rs:807-815`

## 尚未通过

`recovery_after_identity_failure=false`。

R1 Agent 恢复为 running 后，立即执行的相同缓存查询仍返回 SERVFAIL。真实日志显示原因不是 Agent 仍不可用，而是 CacheHit 携带的 `source_graph_digest` 指向一个派生缓存 Graph；Agent 的 current-generation source lookup 不能把它作为当前源 Graph 找回。随后等待自然 TTL 到期、不清缓存，新的完整递归 miss 在 `2026-08-08T14:20:55Z` 成功，形成了本目录的正式验收 Graph。

这不否定本次 fresh miss 的 DNS/身份双链路成功，但意味着“Agent 恢复后同一缓存查询立即成功”的对照条件没有成立。

## Trace Binding P0

当前 Wrapper request trace ID 与 Knot Producer trace ID 是两个独立随机值，并未在查询前显式端到端传播。当前实现依赖：

- correlation ID；
- Wrapper 内部 DNS transaction ID；
- query/response digest；
- SQLite `min_event_rowid` 边界；
- 完整 Producer lineage；
- one-time event claim；
- 事后匹配。

因此按本轮要求保守报告：

- `trace_binding_passed=false`
- `trace_binding_known_p0=true`
- `release_ready=false`

## 文件说明

- `01-query.txt`：正式 dig 查询及时间
- `02-dns-response.txt`：完整 DNS 输出
- `03-trace-summary.json`：四节点 Trace 摘要与关联标识
- `04-evidence-graph.json`：完整成功 Graph（包含真实签名、公钥，但不含私钥或 token）
- `05-identity-nodes.json`：身份节点摘要
- `06-identity-edges.json`：逐跳身份边摘要
- `07-registry-snapshot-summary.json`：当前 Registry 快照摘要
- `08-wrapper-decision.txt`：ControlledStrict 放行摘要与代码路径
- `09-fail-close.txt`：R1 Agent 停止对照
- `10-recovery.txt`：恢复尝试及未通过结果
- `FINAL-RESULT.json`：最终布尔值
- `SHA256SUMS`：所有证据文件校验和
