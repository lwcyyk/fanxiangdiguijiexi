# Sepolia 预发布事故响应

## 分级

- **SEV-1**：疑似私钥泄露、未授权链上写入、Mainnet 连接、Wrapper 错误放行。
- **SEV-2**：双 RPC 分叉、Registry Sync 持续陈旧、mTLS/Token 失效、磁盘将满。
- **SEV-3**：单 RPC 限流、非关键指标缺失、预发布 DNS 查询部分失败。

## 首次响应

1. 记录 UTC 时间、Git commit、容器/镜像 ID、finalized 高度和全部告警。
2. SEV-1/2 先停止 Wrapper，必要时停止整个数据面，保留卷和容器。
3. 禁止删除日志、重建卷、覆盖 env 或重新发布身份。
4. 用第二 RPC 独立读取角色、Root、Resolver、Endpoint 和交易收据。
5. 扫描 Git 状态，确认没有秘密进入工作区或提交。

```bash
docker compose \
  --project-name ri-sepolia-preprod \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml stop wrapper
curl --fail http://127.0.0.1:9109/metrics
git status --short
git log -1 --oneline
```

## 场景处置

### Mainnet 或错误链

立即停止全部服务，不发送任何交易。保存脱敏 RPC 主机和 `eth_chainId` 响应，
修正秘密管理配置后重新执行 `00`。任何 Mainnet 交易尝试按 SEV-1 审计。

### 业务角色泄露

Governance 先撤销受影响角色，再向新地址授予。若泄露的是 Revoker，优先
撤销以防不可逆破坏。检查泄露窗口内全部 Registry 事件和交易 sender。

### Governance 泄露

若仍有另一个可信管理员，立即撤销受影响管理员。若是唯一管理员，不能在
链上自救；冻结该 Registry，部署新的治理实例并重新发布。不得继续把旧地址
描述为可信。

### Issuer/Agent 密钥泄露

提高对象版本、轮换 key ID、公钥和 Root version。Agent 私钥泄露时同时停止
对应 Agent。已撤销身份不能恢复。

### RPC 分歧或 finalized 异常

停止写链和 Wrapper。分别保存两个 RPC 的共同高度 block hash、runtime code
和 code hash。高水位回退或同高度 hash 变化未解释前，不删除 SQLite 或降低
校验策略。

### Registry Sync 陈旧

检查 RPC 状态、失败计数、磁盘、身份到期和链上撤销。修复后必须观察新的
成功时间和不低于原高水位的 finalized 高度。

### Trace/mTLS/Token 故障

保持 Wrapper 失败关闭。检查证书有效期、SAN、CA、文件权限、Token 长度、
Socket UID/GID 和 spool。禁止临时改为明文 HTTP 或共享 Token。

## 证据保存

保存到受限事件目录：

- `deployment.json`、`verification.json`、`roles.json`、计划和交易文件；
- 容器日志、指标、镜像 ID；
- 停止后的 SQLite 一致副本及 SHA-256；
- 两个 RPC 的脱敏响应；
- mTLS 证书指纹和有效期，不保存私钥；
- 时间线、操作人和审批记录。

## 恢复条件

- 根因明确并已消除。
- 双 RPC finalized 核验一致。
- 角色、身份、Root、Endpoint 和本地快照重新通过。
- 所有负向测试失败关闭。
- 两人复核恢复清单。
- Wrapper 恢复后持续观察 SERVFAIL、延迟、Trace spool 和磁盘。

关闭事件时记录残余风险和需要迁移到多签/HSM、正式监控或域名中心基础设施
的事项。
