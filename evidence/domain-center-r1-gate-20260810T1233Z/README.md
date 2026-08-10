# R1 服务级门（Service-Level Gate）— PASSED

记录时间：2026-08-10T12:29:25Z
结论：`r1_migration_passed = true`

## 门检查结果

| 检查项 | 结果 |
|---|---|
| containers_running | true（agent/registry-sync/resolver/trace-adapter/trace-producer/wrapper） |
| restart_count_zero | true（全部 0） |
| registry_freshness_passed | true（registry-sync 每 2s reconcile count=4） |
| evidence_db_quick_check | ok |
| spool_db_quick_check | ok，spool_pending=0 |
| A/AAAA/TXT × UDP/TCP（+dnssec） | 全部 NOERROR + answers=2 + AD + RRSIG |
| wrapper_response_digest == final_event_response_digest | true（6/6 digest 匹配 DB CLIENT_RESPONSE 事件） |
| controlled_strict_release_passed | true |
| **r1_migration_passed** | **true** |

## 与上次门（20260810T0718Z，blocked）的差异

上次门阻塞于 `controlled_strict_dns_release`：wrapper 返回 503
"cache-hit event has no source graph digest"。

本会话根因定位（evidence/r1-wrapper-wire-diff-20260810T1035Z/ROOT-CAUSE.md）：
- **非 response_digest 不一致**。同请求 wrapper digest == producer CLIENT_RESPONSE digest（字节级相等，`0xa4a1b017…`）。
- 真正阻塞：`ri_v2_evidence_graphs=0`，Knot 缓存条目为无 G0 provenance 的孤儿；ControlledStrict fail-closed。
- 修复路径：孤儿按 TTL 过期后由 wrapper 认证的 MISS 重建 G0（ns1 实测：MISS→G0→NOERROR 4.2s；CACHE HIT→NOERROR 43ms）。
- 本次门跑在孤儿过期后的 warm cache 上：wrapper 认证的 MISS/HIT 全部建立 provenance，6/6 释放。

## 运行二进制（frozen matrix 未变）

沿用服务级冻结镜像矩阵（docs/rc15-service-image-matrix.md）：wrapper/agent/trace-adapter/producer 均为冻结 OCI，
本次未做任何源码变更（调试 eprintln 已还原）。tools/run_r1_gate.py 为本次新增门脚本。
