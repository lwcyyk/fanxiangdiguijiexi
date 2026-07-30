# Sepolia 预发布任务

## 已完成的准备核验

- [x] 记录当前分支、提交和工作区状态。
- [x] 检查合约、Python 发布工具、Rust Registry Sync/Store、Compose 和现有文档。
- [x] 通过 Ethereum 官方资料确认 Sepolia 仍处于维护状态。
- [x] 使用两个不同 RPC 主机实际执行 `eth_chainId` 和 finalized 查询。
- [x] 确认当前环境未提供部署秘密、账户和真实 DNS 身份参数。
- [x] 创建 Spec 驱动的需求、设计、任务、输入、验收和安全文档。

## 工程实现

- [x] 增加秘密路径忽略规则和公开示例文件。
- [x] 增加可广播的 Foundry 部署脚本。
- [x] 为 Registry 写入增加加密 JSON keystore 支持。
- [x] 为发布阶段增加增量、计划绑定的结构化交易收据。
- [x] 实现 `scripts/sepolia/00` 至 `12` 和公共安全函数。
- [x] 增加 Sepolia 运行配置的安全同步和 SHA-256 清单。
- [x] 增加部署、回滚、密钥轮换、重新发布和事件响应手册。
- [x] Registry Sync 指标增加 Chain ID、合约、code hash 和 finalized hash。

## 部署前验证

- [x] `cargo fmt --all --check`
- [x] `cargo test --workspace --locked`
- [x] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [x] `python3 -m pytest -q`
- [x] `forge fmt --check`
- [x] `forge build`
- [x] `forge test -vvv`
- [x] 构建固定标签 Rust 镜像。
- [x] 验证 Compose 展开配置。

## 真实 Sepolia 部署

- [x] 操作者提供两个独立 HTTPS RPC。
- [x] 操作者提供六类签名能力、余额和相互独立的地址。
- [ ] 操作者提供 Issuer 密钥和真实 DNS/Agent 身份参数。
- [ ] 部署 Registry 并等待 finalized。
- [ ] 使用双 RPC 核验 Chain ID、bytecode、code hash 和 finalized hash。
- [ ] 拆分角色并撤销 Governance 的四类业务角色。
- [ ] 签名并复验真实 V2 身份。
- [ ] 生成且独立复算发布计划哈希。
- [ ] 执行五阶段发布并归档全部交易。
- [ ] 同步链路运行配置和 SHA-256 清单。

## 运行与验收

- [ ] 单独启动 Registry Sync 并通过 health/readiness/metrics。
- [ ] 核验 SQLite 完整性、身份、Root、Endpoint 和链快照。
- [ ] 验证 Registry Sync 重启恢复。
- [ ] 完成错误链、合约、code hash、Issuer、身份篡改和陈旧测试。
- [ ] 使用专用身份完成不可逆撤销测试。
- [ ] 在真实 Trace 插件可用后启动 Agent、Trace Adapter、Wrapper。
- [ ] 完成 UDP/TCP DNS 正向和失败关闭测试。
- [ ] 生成最终部署清单和验收证据索引。
- [ ] 确认 Git 中不存在秘密。

> 当前身份发布阻断：Issuer 密钥已生成，但仍缺少真实 DNS Endpoint、Agent
> 地址和 Agent 公钥。Registry 部署与角色拆分可通过 `--registry-only` 预检先行；
> 身份发布、Registry Sync 和 DNS 全路径验收不得虚假勾选。
