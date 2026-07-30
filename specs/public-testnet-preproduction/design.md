# Sepolia 预发布部署设计

## 信任与部署拓扑

Governance 只持有 `DEFAULT_ADMIN_ROLE`。Root Publisher、Resolver Publisher、
Endpoint Manager 和 Revoker 分别使用独立测试网账户。Deployer 只广播构造
交易，构造参数直接传入 Governance 地址，因此不会自动获得业务权限。

Issuer Ed25519 密钥与 EVM 交易密钥完全分离。Issuer 私钥只在离线签名环境
读取；链路服务器只接收签名身份和 Issuer 公钥束。

## 合约与角色

部署对象是现有 `ResolverIdentityRegistryV1`，不在本次部署中更改其状态机。
构造函数暂时向 Governance 授予管理员和四类业务角色。配置阶段先把四类
角色授予独立账户，再从 Governance 撤销四类业务角色，最后通过第二 RPC 对
每个 `hasRole` 结果进行复核。

角色职责：

| 角色 | 写操作 |
| --- | --- |
| Governance | 授予/撤销角色，治理管理员 |
| Root Publisher | 发布 Root |
| Resolver Publisher | 发布或更新 Resolver Anchor |
| Endpoint Manager | 解绑、绑定 Endpoint |
| Revoker | 撤销 Root 或 Resolver |

## 身份发布

真实部署输入先生成 unsigned V2 制品。签名工具执行结构校验、Endpoint
规范化和 Ed25519 签名；随后使用独立提供的 Issuer 公钥重新验证全部对象。

`prepare` 以签名对象哈希构造 Merkle Root，并固定：

- 实测 Chain ID；
- Registry 合约地址；
- finalized runtime code hash；
- Root version；
- 前一批准计划（版本升级时）。

计划文件包含解绑和撤销差集。`plan_hash` 是对不含自身的规范化计划计算的
对象哈希，文件生成后不得手工修改。

## 五阶段写链

发布顺序固定为：

1. Root Publisher 发布 Root。
2. Resolver Publisher 发布/更新 Resolver Anchor。
3. Endpoint Manager 解绑旧 Endpoint。
4. Endpoint Manager 绑定当前 Endpoint。
5. Revoker 撤销从新计划移除的 Resolver。

每个阶段重新检查 Chain ID、合约 runtime code hash、调用账户角色、计划
哈希和前置链上状态。成功交易以结构化收据追加到
`publication-transactions.json`。每个阶段即使没有待写对象，也必须写入
`completed_phases`；只有五个阶段完整且全部实际交易 receipt 成功，后续运行配置
同步才允许继续。重复执行时，已满足的幂等操作不重复发
交易；状态冲突则立即失败。

## 双 RPC 与 finalized 核验

部署和写入使用主 RPC，所有关键结果用独立核验 RPC 复查。部署验证等待
合约进入 finalized 后再比较：

- Chain ID；
- 合约地址；
- 完整 runtime bytecode；
- runtime code hash；
- 同一 finalized 高度的 block hash。

两个端点主机名、提供方和凭据必须独立。部署清单只保存脱敏主机名。

## 链下配置同步

成功发布后才生成 `deploy/link/.env.sepolia`，并把签名身份和 Issuer 公钥束
复制为 Sepolia 专用制品。复制前后生成 SHA-256 清单。包含凭据的实际 env
文件保持 Git 忽略；公开部署结果、合约地址和 code hash可以提交。

公共测试网默认采用 `public-hybrid`。只有所有路径节点均由项目控制并实际
部署 Agent 时，才允许改为 `controlled-strict`。

## Registry Sync 与数据面

`ri-registry-sync` 首先单独启动。它从 `finalized` 标签读取；不支持时按
配置的确认数回退。每轮同步验证 Chain ID、runtime code hash、Root、Resolver
对象哈希、有效期、状态、Endpoint 绑定和 Issuer 签名。

SQLite 更新使用单个即时事务完成身份、Endpoint、快照和心跳写入。已持久化
高水位禁止 finalized 高度回退；旧检查点哈希和同高度新哈希发生变化时均
失败关闭。

只有 Registry Sync `/readyz` 成功后才启动 Agent 和 Trace Adapter，二者
就绪后才启动 Wrapper。Wrapper 对证据图引用的本地 Registry 快照再次核验。
缺少 Trace、快照陈旧、身份撤销、mTLS/Token 错误或 Agent 不可用时返回
`SERVFAIL`，不释放暂存的原始 DNS 响应。

## 回滚边界

合约撤销不可逆，不能“恢复”同一个已撤销身份。测试撤销后必须生成新的
`server_id`/对象并重新发布。链下配置可以回滚到最后一个已批准且仍与链上
ACTIVE 状态一致的制品；不能用旧文件覆盖新的链上事实。
