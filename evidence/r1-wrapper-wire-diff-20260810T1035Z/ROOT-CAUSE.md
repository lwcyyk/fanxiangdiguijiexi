# R1 Wrapper ControlledStrict 验证阻塞 — ROOT_CAUSE（字节证据）

记录时间：2026-08-10T10:35Z
范围：R1（operator/L01/r1）wrapper `/v2/evidence-graph` ControlledStrict 验证 503。
结论先置前：

> **ROOT_CAUSE 不是 response_digest 不一致。** 同一请求下，wrapper 计算的
> response_digest 与 producer CLIENT_RESPONSE 事件的 response_digest 字节级相等
> （`0xa4a1b017…` == `0xa4a1b017…`）。
> 真正的阻塞是：R1 evidence DB `ri_v2_evidence_graphs` 为 0，Knot 缓存中的
> www A/AAAA、txt TXT 条目是 **无 G0 provenance 的孤儿条目**。ControlledStrict
> 对 cache-hit 强制要求可验证的 cache provenance（`source_graph_digest` →
> canonical G0 graph），孤儿条目无法验证 → fail-closed SERVFAIL。
> 这是正确的安全行为，不是 bug。修复路径是：缓存条目过期后由 wrapper 认证的
> MISS 重建 G0（已实测通过：ns1.ri-test.invalid 首查 MISS → G0 建立 →
> 次查 CACHE HIT 带 provenance 验证通过，wrapper 释放 NOERROR+AD）。

---

## 1. 四条 response_digest 代码路径（文件+函数）

| 路径 | 文件:函数 | 计算 |
|---|---|---|
| WRAPPER_DIGEST_PATH | `rust/crates/ri-wrapper/src/lib.rs:256` `process_query_inner` | `let response_digest = dns_wire_digest(&response);` 对 resolver 返回的响应 wire 计算 |
| PRODUCER_DIGEST_PATH | `rust/crates/ri-knot-trace-producer/src/lib.rs:336` `finish`（含临时调试 eprintln） | `let response_digest = dns_wire_digest(&frame.wire);` 对 FINISH hook 的 `ctx->req.answer` wire 计算 |
| ADAPTER_DIGEST_BEHAVIOR | `rust/crates/ri-trace-adapter/src/main.rs`（透传，不做 digest 改写） | 事件原样入 DB；`prepare_upload_batch` 仅为 CACHE_HIT 事件补充 `source_graph_digest` |
| AGENT_SELECTOR_PATH | `rust/crates/ri-agent/src/lib.rs:1153` `wait_for_trace_anchor` → `ri-store/src/lib.rs:584` `claim_matching_response` | 按 `correlation_id + query_digest + response_digest + kind=CLIENT_RESPONSE` 匹配 anchor |

四处均调用 **`ri_core::crypto::dns_wire_digest`（`rust/crates/ri-core/src/crypto.rs:27`）**，
同一实现：`sha256_hex(wire with bytes[0..2]=0)`（txid 置零）。无共享实现偏差。

## 2. 同一次请求的精确 wire diff（字节证据）

受控请求：`wire-diff-1786357751.ri-test.invalid A`（`dig +dnssec +tcp`，
wrapper 转发的 TCP attempt，correlation_id `0x7a4d90ad00228e382468ba32542bac2d630aa730fee0fa761fdbefea73e84efe`）。

### 2.1 Wrapper 侧（`RI_DEBUG_WRAPPER_RESPONSE`，来自临时 eprintln 输出）

```
upstream=172.28.0.10:1053 transport=Tcp len=116
digest=0xa4a1b0176b9356c014ec96eb31daf32c271ab61165d65ba150663b0243ee178f
raw=000181a3000100000001000114776972652d646966662d31373836333537373531
     0772692d7465737407696e76616c69640000010001c021000600010000012c0027
     036e7331c0210a686f73746d6173746572c02178c38aea00000e10000003840009
     3a800000012c00002904d0000000000000
```

独立复算：`sha256(raw[2..]) = 0xa4a1b0176b9356c014ec96eb31daf32c271ab61165d65ba150663b0243ee178f` ✓

### 2.2 Producer 侧（evidence DB `ri_v2_trace_events` CLIENT_RESPONSE 事件）

```
kind=CLIENT_RESPONSE  response_digest=0xa4a1b0176b9356c014ec96eb31daf32c271ab61165d65ba150663b0243ee178f
                       correlation_id=0x7a4d90ad00228e382468ba32542bac2d630aa730fee0fa761fdbefea73e84efe
```

### 2.3 结论

`wrapper_digest == producer_client_response_digest`，**字节级相等**。
同一次请求内 **first_different_offset 不存在（无差异）**，difference_class=IDENTICAL。

同 trace 中的 UPSTREAM_RESPONSE digest（`0x5ba24cfd…`）与 CLIENT_RESPONSE digest
（`0xa4a1b017…`）不同，这是 Knot 在 upstream 收包与 client 发包之间合法重序列化
（缓存插入/压缩/TTL）的必然结果，且被正确建模：graph 的 edge 绑定
UPSTREAM_RESPONSE digest（R2 的 attestation），graph 的 response_digest 绑定
CLIENT_RESPONSE digest（wrapper 实际收到的 wire）。两者都真，不构成不一致。

## 3. G0 缺失证据（真正阻塞）

R1 evidence DB（`/var/lib/resolver-identity/ri-r1/evidence-v2.db`）：

```
ri_v2_evidence_graphs = 0            ← 修复前（2026-08-10T10:2xZ）
ri_v2_trace_events   = 16           ← 修复前仅 16 条历史事件
```

孤儿 CACHE_HIT 事件（无 `source_graph_digest`）：

```json
{"kind":"CACHE_HIT","cache_object_digest":"0xdf7cd7aeb3853c279abe06518c420fd28eb6fd866c7d470567729157a2be8309",
 "response_digest":"0x5eee5289b4475a34a8faa35f5d8d675a9635ac41a9cf82d11dcf80586bdb31b7", ...}
```

adapter 日志（连续每个 CACHE_HIT 均无法找到 G0）：

```
WARN ri_trace_adapter: cache provenance source graph not found; uploading CacheHit without provenance
```

agent 侧 ControlledStrict fail-closed（`ri-agent/src/lib.rs:759`
`build_unverified_cache_graph`）：

```
"controlled-strict mode requires verified cache provenance; \
 cache-hit event has no source graph digest"
```

### 3.1 锚点匹配成功（digest 不匹配假设被证伪）

错误序列演变（wrapper 日志）：
1. `08:54–09:03Z`：`no matching final resolver response event`
   —— 当时 adapter 配置非法（RI_TRACE_CACHE_PROVENANCE_WAIT_MS=90000 超出
   100–30000 范围）导致事件未入库，anchor 不可见。
2. `09:05Z 起`：`cache-hit event has no source graph digest`
   —— adapter 恢复后，**anchor 被找到**（digest 匹配成功），错误前移到 cache
   provenance 阶段。

若存在 response_digest 不一致，错误不可能从第 1 种变为第 2 种。

## 4. 修复路径（实测通过）

受控验证（`ns1.ri-test.invalid A +dnssec`，真实 wrapper 10.206.16.14:1053）：

| 步骤 | 请求 | 结果 | graphs |
|---|---|---|---|
| 1 | 首次查询（缓存 MISS） | `NOERROR ad ANSWER:2`，Query time 4172ms | 0 → 1 |
| 2 | 二次查询（缓存 HIT） | `NOERROR ad ANSWER:2`，Query time 43ms | 1 → 2 |
| 3 | UDP 缓存 HIT | `NOERROR ad ANSWER:2`，Query time 41ms | — |

DB 中的 graph 链（`ri_v2_evidence_graphs`）：

```
trace d4b94aa5  graph_digest=0xb7207da1…  cache_provenance=NULL   ← G0 canonical root
trace 3068729b  cache_provenance={"source_graph_digest":"0xb7207da1…",
                                   source_dnssec_required":true,
                                   "dns_ttl_expires_at":1786361692,
                                   "snapshot_generation":3}        ← verified cache-hit graph
trace cca30635  cache_provenance={…同 G0 引用…}                     ← verified cache-hit graph
```

CACHE_HIT 事件被 adapter 成功补充 `source_graph_digest=0xb7207da1…`。

## 5. 源码修复评估

**无需源码变更。** response_digest 计算一致（§2 字节证据）；ControlledStrict
对无 provenance 缓存命中 fail-closed 是既定安全策略（`controlled_strict()` policy），
不属于 RC15 修复范围。孤儿条目的产生源于 08:43–08:57 gate 期间 trace pipeline
（adapter）失效，属于运行期前置条件问题，修复方式是：缓存条目按 TTL 过期后，
由 wrapper 认证的 MISS 重建 G0（§4 已实测）。

## 6. 延迟重新审视（90s 等待）

实测：wrapper-verified MISS 端到端 ~4.2s（R1→R2→R3→AuthDNS TCP 链路）；
verified CACHE HIT 43ms。agent 的 `RI_TRACE_WAIT_MILLIS=90000` 是安全裕量
（事件经 producer→adapter→DB 的摄入延迟），不是实际瓶颈。90s 等待无需修改。
