# Sepolia 预发布部署需求

## 目标

把 `ResolverIdentityRegistryV1` 真实部署到仍受维护的 Ethereum Sepolia，
完成角色拆分、V2 身份签名与发布、双 RPC 核验、Rust Registry Sync 和
SQLite 快照验收。任何本地链、Mock 数据或示例身份都不能作为部署成功证据。

2026-07-30 的部署前核验结果：

- Ethereum 官方网络文档仍将 Sepolia 列为受维护的应用开发测试网：
  <https://ethereum.org/developers/docs/networks/>
- 两个不同主机的公共 RPC 实际执行 `eth_chainId` 均返回 `0xaa36a7`
  （十进制 `11155111`）。
- 正式部署仍必须使用操作者提供的两个独立 HTTPS RPC，再次执行相同核验；
  不能把上述临时公共端点当作生产 SLA 或长期配置。

## 边界

本规格覆盖：

1. Solidity 合约编译、测试、部署和可选浏览器源码验证。
2. Governance、Root Publisher、Resolver Publisher、Endpoint Manager、
   Revoker 五类权限的分离和链上核验。
3. Ed25519 Issuer 对真实 `DnsServerIdentityV2` 制品的离线签名与复验。
4. 发布计划的完整性校验和五阶段链上发布。
5. Sepolia finalized 状态的双 RPC 独立核验。
6. `ri-registry-sync` 到 SQLite 的原子同步、重启恢复和失败关闭测试。
7. Agent、Trace Adapter、Wrapper 在真实 Trace 插件具备时的分阶段启动。

本规格不声称：

- Sepolia 等同于 Ethereum Mainnet 或域名中心生产链。
- 公共互联网 Root、TLD、Authority 的物理服务器实例已经部署本项目 Agent。
- 在真实 Resolver Trace 插件缺失时已经完成 DNS 全路径生产验收。
- 单一测试网 EOA 等同于生产多签、HSM 或远程签名系统。

## 必需输入

### 网络与账户

- 两个独立提供方的 Sepolia HTTPS RPC。
- 一个仅用于部署的加密 keystore 和足够的 Sepolia 测试 ETH。
- Governance 地址及其可执行签名方式。
- 四个地址各不相同的业务角色 keystore。
- 可选的区块浏览器 API Key。

### 身份与 DNS

- 真实预发布 `server_id`、`operator_id`、角色、对象版本和有效期。
- 可路由的真实 DNS Endpoint、传输协议和端口。
- Recursive/Forwarder 对应的真实 HTTPS Agent URL。
- 每个 Agent 独立的 Ed25519 公钥。
- 与 EVM 账户隔离的 Issuer Ed25519 私钥和公钥。
- 真实 Resolver Trace 插件、Socket UID/GID、mTLS 证书和运行令牌。

## 输出

- `deployments/sepolia/deployment.json`
- `deployments/sepolia/verification.json`
- `deployments/sepolia/roles.json`
- `deployments/sepolia/identities-v2.unsigned.json`
- `deployments/sepolia/identities-v2.json`
- `deployments/sepolia/issuer-keys.json`
- `deployments/sepolia/registry-plan-v2.json`
- `deployments/sepolia/publication-transactions.json`
- `deployments/sepolia/deployment-manifest.json`
- `deploy/link/.env.sepolia` 及对应运行制品
- Registry Sync 日志、指标、SQLite 查询和正负向测试证据

所有包含 RPC 凭据、密码、私钥或临时签名材料的文件只能位于 Git 忽略路径。

## 失败条件

以下任一情况必须停止当前阶段并返回非零状态：

- 任一 RPC 返回 Mainnet Chain ID `1`，或两个 RPC Chain ID 不一致。
- RPC 不是 HTTPS、两个核验 RPC 不独立或 finalized 结果不一致。
- 账户为零地址、角色地址重复、余额不足或 keystore 地址与声明地址不符。
- 合约 runtime bytecode 为空，或两个 RPC 的 bytecode/hash 不一致。
- Governance 未撤销四种业务角色，或 Deployer 保留业务角色。
- 身份签名无效、使用示例地址、Endpoint 重复或 Agent 配置不合规。
- 发布计划哈希不匹配，阶段顺序错误或任一交易失败。
- finalized 高度回退、同高度区块哈希变化或链固定值不一致。
- Registry Sync 超时、SQLite 完整性失败或本地快照与链上不一致。
- Trace、mTLS、Token 或 Agent 不可用时 Wrapper 仍释放原始 DNS 响应。
- 缺少真实输入却尝试生成或宣称成功部署结果。
