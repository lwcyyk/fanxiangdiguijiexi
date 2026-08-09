# 递归解析器身份认证系统 RC14 最终双链路验收

## 1. 验收目标

本次验收以一次真实 DNS 查询为唯一主线，同时验证：

1. DNS 数据解析链路能够完整返回正确 DNSSEC 响应；
2. 带外身份认证链路能够对 R1、R2、R3、Auth DNS 逐跳建立真实证据；
3. Wrapper 仅在 ControlledStrict 验证成功后释放 DNS 响应；
4. 身份验证不可用时 Wrapper fail-close。

正式证据目录：`evidence/final-dual-chain-acceptance-20260808T142055Z/`。

## 2. 实验环境

| 角色 | 身份 | DNS endpoint | Agent endpoint |
|---|---|---|---|
| R1 | `operator/L01/r1` | `10.206.16.14:53` | `https://10.206.16.14:8443` |
| R2 | `operator/L01/r2` | `10.206.16.17:53` | `https://10.206.16.17:8443` |
| R3 | `operator/L01/r3` | `10.206.16.7:53` | `https://10.206.16.7:8443` |
| Auth DNS | `operator/authdns` | `10.206.16.13:53` | `https://10.206.16.13:8443` |

验证模式为 `controlled-strict`，Registry freshness 上限保持 45 秒。正式查询完成时 Registry heartbeat age 为 2 秒，Trace spool pending 和 dead letter 均为 0。

Registry：

- generation：`3`
- state root：`0x43d79c30546d28af891965e81162bb6c471d4a01b95fb16b2469226a548b042a`
- chain identity：`norn-genesis:0xce696ab6f10a16f1a56bfab12c51771e107b57f4c75422abea2231a3fac8c70c`

## 3. 正常 DNS 链路

正式查询：

```text
UTC: 2026-08-08T14:20:55Z
transaction ID: 63690
qname: www.ri-test.invalid.
qtype: AAAA
Wrapper: 10.206.16.14:1053/udp
```

响应：

```text
rcode=NOERROR
AD=true
RRSIG=true
AAAA=2001:db8::10
query_time=250 ms
```

实际链路：

```text
Client
  → Wrapper
  → R1
  → R2
  → R3
  → Authority Proxy / Auth DNS
  ← R3
  ← R2
  ← R1
  ← Wrapper
  ← Client
```

验收：

```text
[PASS] Client → Wrapper
[PASS] Wrapper → R1
[PASS] R1 → R2
[PASS] R2 → R3
[PASS] R3 → Auth DNS
[PASS] Auth DNS → R3
[PASS] R3 → R2
[PASS] R2 → R1
[PASS] R1 → Wrapper
[PASS] Wrapper → Client
```

`dns_resolution_chain_passed=true`

## 4. 带外身份认证链路

本次成功 Evidence Graph：

```text
wrapper_request_trace_id=3e570b54ff0af0ff848892bb83dc17ce
producer_trace_id=knot-ce0c018d646b4415bee697db853e7c31
graph_digest=0x724da06e7046cd8afd3294467f07205031e40dc1453e93a67adaddcdc63f5f56
query_digest=0xa1d32e3cd41c2e32b051cc4bca4812d97f491eef9fcf3b1b91e0b8dea744c9b2
response_digest=0xedf0875b1eab20b8bdfd5decdcbd32a2b3eadb52b322d9d203153988e57e7779
mode=CONTROLLED_STRICT
dnssec_status=SECURE
final_result=true
graph_errors=[]
```

Graph 包含四个身份节点，全部满足：

```text
identity_status=ACTIVE
registry_status=ACTIVE
root_status=ACTIVE
endpoint_binding_status=MATCHED
snapshot_generation=3
accepted=true
reasons=[]
```

本次解析出现真实 upstream retry，因此 Graph 中 R1→R2、R2→R3、R3→Auth DNS 各有两条 accepted 边。重复边不是伪造或抽象重复，而是两次真实 DNS 上游尝试留下的证据。

```text
OUT-OF-BAND IDENTITY CHAIN

Wrapper
  │ verify returned R1-rooted graph [PASS]
  │ identity=operator/L01/r1
  │ graph=0x724da06e...f5f56
  ▼
R1
  │ verify R2 [PASS, 2 real attempts]
  │ identity=operator/L01/r2
  │ Registry generation=3
  ▼
R2
  │ verify R3 [PASS, 2 real attempts]
  │ identity=operator/L01/r3
  │ Registry generation=3
  ▼
R3
  │ verify Auth DNS [PASS, 2 real attempts]
  │ identity=operator/authdns
  │ Registry generation=3
  ▼
Auth DNS
```

## 5. Wrapper → R1 验证

当前 schema 没有伪造一条 `Wrapper→R1` Graph edge。真实表达方式是：

1. Wrapper 向 R1 Agent 请求本次响应的 Evidence Graph；
2. 返回 Graph 的 `entry_server_id=operator/L01/r1`；
3. R1 节点为 ACTIVE、MATCHED、REGISTRY_BOUND、AGENT_ATTESTED、accepted；
4. Wrapper 对 Graph 顶层 trace/correlation/query/response digest 做精确绑定；
5. Wrapper 使用本地独立 Registry SQLite 快照检查身份、endpoint、generation 和 Registry reference；
6. ControlledStrict policy 验证通过后才返回响应。

```text
subject_identity=operator/L01/r1
registry_valid=true
endpoint_valid=true
snapshot_valid=true
controlled_strict_valid=true
wrapper_to_r1_identity_passed=true
```

## 6. R1 → R2 验证

两条真实边均满足：

- `from_server_id=operator/L01/r1`
- `to_server_id=operator/L01/r2`
- endpoint=`10.206.16.17:53/udp`
- Registry ACTIVE/MATCHED，generation 3
- target attestation 由 `agent-key-L01-r2` 签署
- edge accepted，reasons 为空

```text
r1_to_r2_identity_passed=true
```

## 7. R2 → R3 验证

两条真实边均满足：

- `from_server_id=operator/L01/r2`
- `to_server_id=operator/L01/r3`
- endpoint=`10.206.16.7:53/udp`
- Registry ACTIVE/MATCHED，generation 3
- target attestation 由 `agent-key-L01-r3` 签署
- edge accepted，reasons 为空

```text
r2_to_r3_identity_passed=true
```

## 8. R3 → Auth DNS 验证

两条真实终止边均满足：

- `from_server_id=operator/L01/r3`
- `to_server_id=operator/authdns`
- endpoint=`10.206.16.13:53/udp`
- Auth DNS Registry ACTIVE/MATCHED，generation 3
- target attestation 由 `agent-key-authdns` 签署
- Auth DB 中存在匹配 correlation/query/response digest 的 `CLIENT_QUERY → AUTHORITY_RESPONSE`
- R3 最终 `CLIENT_RESPONSE` 为 `dnssec_status=SECURE`
- Graph 顶层为 `dnssec_status=SECURE`

```text
r3_to_auth_identity_passed=true
```

## 9. 双链路关联

本次客户端得到的 DNS 响应与 Graph 的绑定值：

```text
qname=www.ri-test.invalid.
qtype=AAAA
query_digest=0xa1d32e3cd41c2e32b051cc4bca4812d97f491eef9fcf3b1b91e0b8dea744c9b2
response_digest=0xedf0875b1eab20b8bdfd5decdcbd32a2b3eadb52b322d9d203153988e57e7779
Evidence Graph digest=0x724da06e7046cd8afd3294467f07205031e40dc1453e93a67adaddcdc63f5f56
cache_object_digest=0xcabd2cf89e21ea46f341ba6fe0fe1dc6dbbebc4f92c4e5407f64570f62a769a0
source_graph_digest=null
```

本次正式查询是自然 TTL 到期后的完整递归 miss，不是 CacheHit，因此没有 `source_graph_digest`。R1 terminal `CLIENT_RESPONSE.response_digest`、Evidence Graph 顶层 `response_digest` 和 Wrapper 验证请求使用相同值。

```text
dns_and_identity_evidence_correlated=true
```

## 10. ControlledStrict 放行

实际 Graph：

```text
verification_mode=controlled-strict
identity_verification_result=true
final_result=true
graph_errors=[]
```

代码路径证明响应释放顺序：

```text
Resolver DNS response temporarily held
  → Wrapper computes response digest
  → Wrapper calls R1 Agent
  → Agent builds/signs/validates Evidence Graph
  → Wrapper validates graph and independent Registry snapshot
  → verify_response returns Ok
  → Wrapper restores client transaction ID
  → Wrapper returns original DNS response
```

关键代码：`rust/crates/ri-wrapper/src/lib.rs:242-278`。失败时 `rust/crates/ri-wrapper/src/lib.rs:185-200` 返回 SERVFAIL。

```text
controlled_strict_release_verified=true
```

## 11. Fail-Close 对照实验

停止 R1 Agent 后执行同一查询：

```text
UTC=2026-08-08T14:26:05Z
rcode=SERVFAIL
answer_count=0
```

Wrapper 日志：

```text
Agent request failed: ... https://agent:8443/v2/evidence-graph
DNS response rejected: all upstreams failed
```

因此身份链失败会阻止 DNS 响应释放：

```text
identity_failure_blocks_dns_release=true
```

R1 Agent 随后恢复为 running，但立即执行同一缓存查询仍为 SERVFAIL。真实原因是当前 Cache Provenance selector 选择了一个派生 CacheHit Graph，Agent 按 current-generation source graph 规则无法将它重新解析为源 Graph。自然 TTL 到期后的完整递归 miss 可以成功，但“恢复后相同缓存查询立即成功”未成立。

```text
recovery_after_identity_failure=false
```

该问题是本轮只读取证据时发现的真实运行时缺陷；本轮没有修改源码或协议。

## 12. Trace Binding P0 与最终结果

当前实现没有在 Wrapper 接收查询之前生成一个 trace ID 并显式传播到 Knot Producer。实际为：

```text
Wrapper request_trace_id=3e570b54ff0af0ff848892bb83dc17ce
Knot producer trace_id=knot-ce0c018d646b4415bee697db853e7c31
```

二者通过 correlation ID、DNS transaction ID、query/response digest、SQLite `min_event_rowid`、完整 lineage 和 one-time claim 事后绑定。因此按严格定义保留 P0：

```text
trace_binding_passed=false
trace_binding_known_p0=true
release_ready=false
production_capacity_validated=false
production_deployed=false
```

本次 fresh miss 的双链路验收本身成立：

```text
dns_resolution_chain_passed=true
wrapper_to_r1_identity_passed=true
r1_to_r2_identity_passed=true
r2_to_r3_identity_passed=true
r3_to_auth_identity_passed=true
out_of_band_identity_chain_passed=true
dns_and_identity_evidence_correlated=true
controlled_strict_release_verified=true
identity_failure_blocks_dns_release=true
recovery_after_identity_failure=false
dual_chain_end_to_end_passed=true
```

`dual_chain_end_to_end_passed=true` 表示本次真实 fresh miss 的 DNS 与身份认证双链路成功；它不表示 Trace Binding P0、恢复缓存路径或生产发布门已经通过。
