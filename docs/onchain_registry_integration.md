# 链上 Registry 集成

## 1. 后端关系

项目保留两个 registry 后端：

- `SQLiteRegistryBackend`
  - 本地测试替身。
  - 使用 SQLite 表模拟 resolver anchor、endpoint binding 和 root status。
  - 继续用于无需本地链的单元测试和快速原型验证。

- `Web3RegistryBackend`
  - 真实 Solidity 合约适配器。
  - 通过 Web3 读取和写入 `ResolverIdentityRegistryV1`。
  - 用于本地 Anvil 集成和后续测试网部署。

上层组件只依赖统一的 registry backend 行为：

- `get_resolver_anchor` / `get_anchor`
- `get_root_status`
- `lookup_resolver_by_endpoint` / `get_endpoint_binding`
- `publish_root`
- `publish_resolver`
- `update_resolver`
- `revoke_resolver`
- `revoke_root`
- `bind_endpoint`
- `unbind_endpoint`

`AdminPublisher`、`ResolverVerifier`、`QueryCoordinator` 不需要知道底层是 SQLite 还是 Web3。

## 2. Solidity 合约

合约文件：

```text
contracts/src/ResolverIdentityRegistryV1.sol
```

合约只保存轻量可信状态，不保存完整 `ResolverAuthenticityObject` JSON。

### ResolverAnchor

```solidity
struct ResolverAnchor {
    bytes32 resolverIdKey;
    bytes32 objectHash;
    bytes32 stateRoot;
    uint64 objectVersion;
    uint64 validUntil;
    Status status;
}
```

### RootRecord

```solidity
struct RootRecord {
    bytes32 stateRoot;
    Status status;
    uint64 publishedAt;
    uint64 version;
}
```

### 状态

```text
UNKNOWN
ACTIVE
SUSPENDED
REVOKED
EXPIRED
```

## 3. 权限模型

合约内置轻量 role-based access control，角色包括：

- `DEFAULT_ADMIN_ROLE`
- `ROOT_PUBLISHER_ROLE`
- `RESOLVER_PUBLISHER_ROLE`
- `REVOKER_ROLE`
- `ENDPOINT_MANAGER_ROLE`

构造函数会把全部角色授予初始 admin。

写操作权限：

- `publishRoot`：`ROOT_PUBLISHER_ROLE`
- `revokeRoot`：`REVOKER_ROLE`
- `publishResolver`：`RESOLVER_PUBLISHER_ROLE`
- `updateResolver`：`RESOLVER_PUBLISHER_ROLE`
- `revokeResolver`：`REVOKER_ROLE`
- `bindEndpoint`：`ENDPOINT_MANAGER_ROLE`
- `unbindEndpoint`：`ENDPOINT_MANAGER_ROLE`

## 4. Root / Resolver / Endpoint 状态变化

### Root

- `publishRoot(stateRoot, version)` 发布或更新 root。
- root version 必须单调递增。
- `revokeRoot(stateRoot)` 将 root 标记为 `REVOKED`。
- resolver 发布或更新时，其 `stateRoot` 必须是 `ACTIVE`。

### Resolver

- `publishResolver(...)` 创建 resolver anchor。
- `updateResolver(...)` 更新 resolver anchor，`objectVersion` 必须递增。
- `revokeResolver(resolverIdKey)` 将 resolver 标记为 `REVOKED`。
- 合约禁止零值 resolver key、object hash、state root 和明显无效的 `validUntil`。

### Endpoint

- `bindEndpoint(endpointKey, resolverIdKey)` 绑定 endpoint。
- endpoint 已绑定到不同 resolver 时，冲突绑定失败。
- `unbindEndpoint(endpointKey)` 解绑 endpoint。

## 5. 链上事件

合约事件：

- `RootPublished`
- `RootRevoked`
- `ResolverPublished`
- `ResolverUpdated`
- `ResolverRevoked`
- `EndpointBound`
- `EndpointUnbound`

事件包含足够字段用于应用层：

- 找到 `resolverIdKey`
- 找到 `stateRoot`
- 判断 `objectVersion`
- 失效本地可信缓存
- 写入审计日志

事件不输出完整身份对象、不输出私钥、不输出敏感配置。

## 6. Web3RegistryBackend

文件：

```text
src/resolver_identity/chain/web3_backend.py
```

能力：

- 从 ABI 创建合约对象。
- 校验 chain id。
- 校验 contract address。
- 检查 contract address 上存在 bytecode。
- 读取 resolver anchor。
- 读取 root status。
- endpoint lookup。
- 发布 root。
- 发布 / 更新 resolver anchor。
- 撤销 resolver。
- 撤销 root。
- 绑定 / 解绑 endpoint。
- 等待交易 receipt。
- receipt `status != 1` 视为失败。

安全规则：

- 私钥只通过环境变量名读取。
- 不把私钥写入配置、日志或测试输出。
- 读取和写入路径分离。
- chain id 或 contract address 错误时拒绝初始化。
- 交易失败必须 fail-closed。

可选依赖：

```bash
pip install -e '.[web3]'
```

## 7. 本地 Anvil 部署

合约测试：

```bash
cd contracts
forge fmt
forge build
forge test -vvv
```

本地 Anvil smoke 脚本：

```bash
PYTHONPATH=src python3 tools/run_anvil_integration.py
```

该脚本用于本地部署 smoke，不会部署测试网或主网，不修改系统 DNS 配置。

## 8. 事件驱动缓存失效

文件：

```text
src/resolver_identity/chain/event_watcher.py
```

`EventWatcher` 处理已解码事件：

- `ResolverRevoked`
  - `invalidate_resolver(...)` 或按 resolver key 失效。

- `RootRevoked`
  - `invalidate_root(state_root)`。

- `ResolverUpdated`
  - `invalidate_object_version(...)`，旧 object version 缓存失效。

- `EndpointUnbound`
  - endpoint 缓存失效。

- `EndpointBound`
  - 不直接标记可信，只写审计并提示刷新。

Watcher 特性：

- 保存 `last_processed_block`。
- 重启后可恢复状态对象。
- 重复事件幂等处理。
- 支持 confirmations 配置。
- 支持 reorg 安全回退。
- watcher 失败不会把未知状态当成可信。
- 所有处理写入审计日志。

## 9. 轮询兜底

保留现有轮询机制：

```text
POST /v1/cache/refresh
```

最终策略：

```text
事件监听：快速失效
周期轮询：纠正漏事件 / watcher 中断
hard TTL：最终安全边界
```

invalidate API 保留：

- `POST /v1/cache/invalidate/resolver/{resolver_id}`
- `POST /v1/cache/invalidate/root/{state_root}`

## 10. fail-closed 规则

以下情况必须拒绝：

- Web3 backend 初始化 chain id 不匹配。
- contract address 无效或没有 bytecode。
- 交易 receipt `status != 1`。
- root 非 `ACTIVE`。
- resolver 非 `ACTIVE`。
- endpoint binding 缺失或冲突。
- object hash 不一致。
- object version 不一致。
- Merkle proof 不匹配。
- issuer key 或签名验证失败。
- hard TTL 到期且无法读取链上状态。

## 11. 配置

示例配置：

```text
config/registry.local.example.yaml
```

只包含：

- RPC 环境变量名
- contract address
- chain id
- confirmations
- poll interval
- backend type

不得包含：

- 私钥
- 助记词
- 真实密钥
- 完整生产 RPC URL
