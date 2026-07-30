# Sepolia 预发布验收清单

状态约定：`PASS`、`FAIL`、`BLOCKED`、`NOT RUN`。没有真实证据时不得写
`PASS`。

## 链与合约

- [x] Sepolia 真实部署，证据：`deployments/sepolia/deployment.json`
- [x] 双 RPC Chain ID 一致且非 Mainnet，证据：`verification.json`
- [x] finalized runtime bytecode/hash 一致，证据：`verification.json`
- [x] 部署区块、哈希和交易收据完整，证据：`deployment.json`

## 权限

- [x] 五类角色地址相互独立且非零，证据：`roles.json`
- [x] Governance 只保留管理员角色，证据：第二 RPC `hasRole`
- [x] Deployer 不持有任何角色，证据：第二 RPC `hasRole`
- [x] 授权和撤权交易全部成功，证据：`roles.json`

## 身份与发布

- [ ] 真实身份使用 Ed25519 签名并由公钥复验
- [ ] Root 为 ACTIVE
- [ ] Resolver Anchor 与签名对象完全一致
- [ ] Endpoint 绑定唯一且正确
- [ ] 计划哈希独立复算一致
- [ ] 五阶段交易完整，证据：`publication-transactions.json`

## Registry Sync

- [ ] `/healthz`、`/readyz`、`/metrics` 正常
- [ ] 指标包含真实 Chain ID、Registry、finalized 高度和同步数量
- [ ] `PRAGMA integrity_check` 返回 `ok`
- [ ] SQLite 身份、Root、Endpoint 与 finalized 状态一致
- [ ] Registry Sync 重启恢复成功

## 负向与数据面

- [ ] 错误 Chain ID/合约/code hash/Issuer 均失败关闭
- [ ] 身份篡改、Endpoint 未绑定、Root/Resolver 撤销均失败关闭
- [ ] finalized 回退和同高度哈希变化均被拒绝
- [ ] 快照陈旧、Sync/Agent/Trace 停止均使 readiness 失败
- [ ] mTLS 和 Token 错误均被拒绝
- [ ] UDP/TCP 正向 DNS 查询成功
- [ ] 任一身份链路失败时 Wrapper 返回 SERVFAIL

## 交付

- [ ] `deployment-manifest.json` 字段完整且不含 RPC Key
- [ ] 运行配置已按 SHA-256 清单同步
- [x] Git 跟踪文件和待提交内容扫描未发现所提供的私钥及密码
- [x] 已知差距已写入验收清单、安全说明和部署证据 README

## 当前结果

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 官方 Sepolia 维护状态 | PASS | 2026-07-30 检查 Ethereum 官方网络文档 |
| 临时双 RPC Chain ID/finalized | PASS | `deployments/sepolia/network-precheck.json` |
| Rust workspace | PASS | 41 项通过、1 项手工容量基线按设计忽略 |
| Python | PASS | 146 项通过 |
| Solidity | PASS | 14 项通过 |
| Rust release 镜像 | PASS | `resolver-identity-rust:sepolia-preprod` 构建成功 |
| Compose 配置 | PASS | Docker Compose v2 展开验证成功 |
| 真实部署输入 | BLOCKED | RPC、隔离 keystore、余额和 Issuer 已具备；真实 DNS/Agent 身份参数缺失 |
| Registry 合约部署 | PASS | `0x519c70babf33771b8e87c22fd3e2e1b1092e1e2a` |
| finalized 双 RPC 核验 | PASS | 高度 `11380319`，code hash `0x3ff1c0bc964b2751a4006fa9bc54f8a1e1bb04872f62fabaf3eef52132e0a2d3` |
| 五类角色拆分 | PASS | 8 笔授权/撤权交易成功，`adminCount=1` |
| 身份与五阶段发布 | BLOCKED | 缺少真实 DNS Endpoint、Agent URL 和 Agent 公钥 |
| Registry Sync 与 DNS 验收 | BLOCKED | 必须等待真实身份发布和现场 Resolver Trace |
