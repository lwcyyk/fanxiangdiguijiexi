# Sepolia 预发布回滚手册

## 原则

链上部署、交易和撤销不能删除。回滚只能停止流量、恢复仍与链上 ACTIVE 状态
一致的链下制品，或部署新的 Registry 并重新走治理批准。不得篡改清单或把
旧 SQLite 快照伪装成当前链状态。

## 触发条件

- 双 RPC 的 Chain ID、runtime code 或 finalized hash 不一致。
- 角色地址错误或 Governance 未完成权限收敛。
- 身份、Root、Resolver Anchor 或 Endpoint 与批准计划不一致。
- Registry Sync 高水位/区块哈希检查失败。
- Wrapper 错误释放 DNS 响应，或 Trace/mTLS/Token 验证失效。

## 立即止损

```bash
docker compose \
  --project-name ri-sepolia-preprod \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml stop wrapper trace-adapter agent registry-sync
```

保留容器、卷、日志、当前 env 的 SHA-256 和链上交易，不执行 `down -v`。

## 分阶段处理

### 合约部署错误

旧合约不能销毁。标记其地址为禁止使用，使用正确 Governance 部署新实例，
重新完成双 RPC 验证、角色拆分、计划和发布。任何运行配置切换前必须审批新
合约地址和 runtime code hash。

### 角色错误

Governance 先授予正确角色并用第二 RPC 核验，再撤销错误角色。最后一个
管理员不能撤销；Governance 轮换见密钥轮换手册。

### 发布计划错误

若尚未广播，删除未批准计划并重新生成。若已广播：

- 未撤销对象使用更高 `object_version` 和更高 Root version 更正。
- 错误 Endpoint 先解绑再绑定。
- 已撤销对象永久失效，只能使用新的 `server_id`。
- 不能重新激活被撤销 Root。

### 链下配置错误

只可恢复满足以下条件的上一个制品：

1. Chain ID、合约地址和 code hash 与当前 finalized 状态一致。
2. Root、Resolver 和 Endpoint 仍为 ACTIVE/正确绑定。
3. Issuer 签名有效且身份未过期。

恢复后重新执行：

```bash
sha256sum --check deployments/sepolia/runtime-files.sha256
scripts/sepolia/09-run-registry-sync.sh
scripts/sepolia/10-acceptance-test.sh
```

## SQLite 恢复

优先让 Registry Sync 从空数据库按 finalized 链状态重建。若恢复备份，先在
隔离路径执行 `PRAGMA integrity_check`，再核验 snapshot 的五个固定字段。
恢复的 finalized 高度不得低于服务持久化的已批准高水位。

## 关闭事件

记录触发时间、影响、全部交易、配置 hash、恢复后的 finalized 高度和复测
结果。事故未完成独立复核前，不恢复 Wrapper 流量。
