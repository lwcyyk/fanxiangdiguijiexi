# 多链 Registry 兼容层部署手册

## 1. 目标与边界

`ri-chain-adapter` 是 Registry Sync 与具体区块链之间的稳定兼容层。DNS 数据面
只接收统一的 `ChainSnapshot`，不再调用 EVM 或 Norn RPC。

```text
ri-registry-sync
        |
RegistryChainAdapter
        |------------------|----------------------|
        v                  v                      v
EvmRegistryAdapter  NornRegistryAdapter  ExternalRegistryAdapter
JSON-RPC/eth_call   gRPC/signed snapshot  standard HTTPS sidecar
```

新增区块链时实现以下三个方法即可：

```rust
#[async_trait]
pub trait RegistryChainAdapter {
    fn target(&self) -> &ChainTarget;
    async fn read_snapshot(...) -> AdapterResult<ChainSnapshot>;
    async fn block_hash(&self, number: u64) -> AdapterResult<String>;
}
```

新适配器必须提供稳定链身份、Registry 定位、实现/模式哈希、最终检查点、历史
区块哈希和完整 Registry 快照。无法提供历史区块哈希或可靠最终性语义的链不能
用于生产模式。

## 2. 已实现的适配器

| 适配器 | `RI_CHAIN_ADAPTER` | 链身份 | 最终性 | Registry 证明 |
|---|---|---|---|---|
| EVM | `evm` | `eip155:<chain-id>` | `finalized`，不支持时使用确认数 | 指定区块的 runtime code 与 `eth_call` |
| Go-Norn | `norn` | `norn-genesis:<block-hash>` | 双节点最低高度减确认数 | 已确认 `set` 交易、签名全量快照、Merkle Root |
| 标准 sidecar | `external` | 现场固定的原生链身份 | sidecar 提供的原生 finalized 检查点 | 双端点一致、签名标准快照、Merkle Root |

EVM 旧变量 `RI_WEB3_RPC_URL`、`RI_WEB3_CHAIN_ID`、
`RI_REGISTRY_CONTRACT_ADDRESS`、`RI_REGISTRY_CODE_HASH` 继续兼容。新部署应
使用统一的 `RI_CHAIN_*` 变量。

## 3. Go-Norn 版本与安全约束

适配器按
[Chain-Lab/go-norn](https://github.com/Chain-Lab/go-norn) 提交
`a7be734ac2e829e2076d06d45719d2716abd3d72` 的 `Blockchain` gRPC 协议实现。

该版本存在以下上游边界：

- 没有 chain ID RPC，因此必须固定高度 0 的创世块哈希；
- 没有 `finalized` 标签，因此使用双方最低 head 减确认数；
- `ReadContractAddress` 只能读取当前状态，不能指定高度；
- 原生 gRPC 服务没有 TLS 或鉴权；
- `SendTransactionWithData` 使用节点配置中的共识私钥签名。

生产预发布必须部署两个独立只读节点，并在每个节点前使用 mTLS 代理。代理只
允许：

```text
/Blockchain/GetBlockNumber
/Blockchain/GetBlockByNumber
/Blockchain/ReadContractAddress
```

明确拒绝：

```text
/Blockchain/SendTransactionWithData
```

Registry Sync 不包含任何 Norn 写方法。发布必须在隔离的 Publisher 主机上完成，
不能把共识私钥复制到链路服务器。

仓库的本地镜像还对该固定提交应用两项显式补丁：扩大 Registry 值的 Karmem
writer 并传播序列化错误；重启时从持久化链高度继续同步。补丁文件位于
`deploy/norn-local/patches/`，不能无审计地套用到其他提交。

## 4. Norn 快照协议

链上 `registry_address/registry_key` 保存
`resolver-identity-norn-registry-snapshot-v1` JSON。快照包含：

- Norn 本地链命名空间、创世块哈希；
- Registry 地址、键和固定 schema hash；
- 快照版本、签名检查点高度和哈希；
- 与 EVM 发布计划相同的 state root；
- 全部 Resolver anchor 和 Endpoint key；
- 发布/失效时间；
- 独立 Ed25519 快照签名。

固定 schema hash：

```text
0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499
```

适配器还会从已接受 finalized 高度反向扫描 `RI_NORN_MAX_SCAN_BLOCKS` 个区块，
解析 Go-Norn Karmem `DataCommand`，确认当前值确实来自最新的已确认 `set`
交易。当前值若只存在于未确认区块，Registry Sync 会失败关闭。

## 5. 生成签名快照

先使用已核验身份生成现有 V2 发布计划。Norn 快照复用其 entries 和 state root：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py prepare-norn-snapshot \
  --plan deployments/norn/registry-plan-v2.json \
  --expected-plan-hash 0x<approved-plan-hash> \
  --chain-id 20001 \
  --genesis-block-hash 0x<height-0-block-hash> \
  --registry-address 0x<20-byte-address> \
  --registry-key resolver-identity-registry-v2 \
  --snapshot-version 1 \
  --checkpoint-height <confirmed-height> \
  --checkpoint-hash 0x<confirmed-block-hash> \
  --valid-until <unix-seconds> \
  --issuer norn-registry \
  --key-id snapshot-key-1 \
  --private-key-file /secure/norn-snapshot-ed25519.key \
  --issuer-keys deploy/issuer-keys.json \
  --output deployments/norn/registry-snapshot-v1.json
```

离线复核：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py verify-norn-snapshot \
  --snapshot deployments/norn/registry-snapshot-v1.json \
  --issuer-keys deploy/issuer-keys.json
```

发布值必须是生成文件的原始 JSON 内容，不得重新排序、删除字段或手工编辑。
发布后等待配置确认数，再从两个只读节点分别读取地址/键并比较 SHA-256。

## 6. Norn 运行配置

从 [`.env.norn.example`](../../deploy/link/.env.norn.example) 创建现场配置。关键项：

```dotenv
RI_CHAIN_ADAPTER=norn
RI_CHAIN_RPC_URLS=https://norn-read-a:19001,https://norn-read-b:19001
RI_CHAIN_ID=20001
RI_NORN_GENESIS_BLOCK_HASH=0x<真实创世块哈希>
RI_CHAIN_REGISTRY_ADDRESS=0x<真实20字节地址>
RI_NORN_REGISTRY_KEY=resolver-identity-registry-v2
RI_NORN_SIGNER_ISSUER=norn-registry
RI_NORN_SIGNER_KEY_ID=snapshot-key-1
RI_CHAIN_REGISTRY_SCHEMA_HASH=0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499
RI_CHAIN_CONFIRMATIONS=<现场确认数>
RI_NORN_REGISTRY_START_HEIGHT=<首次发布区块或更早>
RI_NORN_MAX_SCAN_BLOCKS=<大于两次发布最大间隔>
```

`RI_CHAIN_ID` 是项目内部的非零链命名空间，不是 Norn 原生返回值。真实链身份
来自 `RI_NORN_GENESIS_BLOCK_HASH`。

生产 mTLS 客户端材料：

```dotenv
RI_NORN_TLS_CA_FILE=/run/tls/norn-ca.crt
RI_NORN_TLS_CLIENT_CERT_FILE=/run/tls/norn-client.crt
RI_NORN_TLS_CLIENT_KEY_FILE=/run/tls/norn-client.key
```

配置检查和启动：

```bash
docker compose \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml config --quiet

docker compose \
  --project-name ri-l01-norn \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml \
  up -d --no-build registry-sync

curl --fail http://127.0.0.1:9109/readyz
curl --fail http://127.0.0.1:9109/metrics
```

指标 `resolver_identity_registry_target_info` 应包含：

```text
adapter="norn"
chain_identity="norn-genesis:0x..."
registry_locator="norn:0x...#resolver-identity-registry-v2"
registry_schema_hash="0xadb0..."
```

## 7. 本地 Go-Norn 完整闭环

以下命令构建固定提交、生成两个真实节点、签名并发布 Registry 快照，然后从
两个 mTLS 只读端点运行 Rust Registry Sync：

```bash
scripts/norn/00-build.sh
scripts/norn/01-initialize.sh
scripts/norn/02-start.sh
scripts/norn/03-prepare-snapshot.sh
scripts/norn/04-publish-and-sync.sh
scripts/norn/05-negative-tests.sh
```

非秘密验收摘要位于忽略目录：

```text
deployments/norn-local/acceptance.json
deployments/norn-local/acceptance-negative.json
deployments/norn-local/evidence-v2.db
```

本地原生写端口仅绑定 loopback；`46555` 和 `46556` 是 mTLS 且拒绝写方法的
独立读取入口。这是适配器集成环境，不是生产共识网络。

## 8. 负向验收

逐项修改隔离测试实例配置，均应导致 `/readyz` 失败且 SQLite 不更新：

1. 错误创世块哈希；
2. 两个 RPC 返回不同区块哈希；
3. 两个 RPC 返回不同 Registry 值；
4. 当前值尚未进入确认区块；
5. 扫描窗口内没有 Registry `set` 交易；
6. 错误 schema hash；
7. 错误快照签名或不可信 key ID；
8. 被篡改 entries、state root 或 Endpoint；
9. 过期快照；
10. finalized 高度低于 SQLite 高水位；
11. 已保存高度的区块哈希发生变化；
12. 生产模式只有一个 RPC 或使用明文 `http://`。

## 9. 标准 Sidecar 扩展协议

Fabric、Cosmos、Substrate 或其他账本优先实现 sidecar 协议，无需修改
Registry Sync。机器契约：

```text
specs/multichain-registry-adapter/external-adapter-openapi.yaml
specs/multichain-registry-adapter/external-snapshot.schema.json
```

sidecar 必须实现：

```http
GET /v1/registry/snapshot
GET /v1/blocks/{number}
```

从已批准计划生成并复验标准快照：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py prepare-external-snapshot \
  --plan registry-plan-v2.json \
  --expected-plan-hash 0x<approved-plan-hash> \
  --driver fabric \
  --chain-identity fabric:channel-a:<immutable-genesis-id> \
  --registry-locator fabric:channel-a/identity-registry \
  --registry-schema-hash 0x<non-zero-32-byte-hash> \
  --generation 1 \
  --checkpoint-height <native-finalized-height> \
  --checkpoint-hash 0x<native-finalized-hash> \
  --valid-until <unix-seconds> \
  --issuer adapter-operator \
  --key-id adapter-key-1 \
  --private-key-file /secure/external-adapter-ed25519.key \
  --issuer-keys deploy/issuer-keys.json \
  --output external-registry-snapshot-v1.json

PYTHONPATH=src python3 tools/manage_v2_registry.py verify-external-snapshot \
  --snapshot external-registry-snapshot-v1.json \
  --issuer-keys deploy/issuer-keys.json
```

运行配置使用 [`.env.external.example`](../../deploy/link/.env.external.example)：

```dotenv
RI_CHAIN_ADAPTER=external
RI_EXTERNAL_DRIVER=fabric
RI_EXTERNAL_ADAPTER_URLS=https://adapter-a.internal,https://adapter-b.internal
RI_CHAIN_IDENTITY=fabric:channel-a:<immutable-genesis-id>
RI_CHAIN_REGISTRY_LOCATOR=fabric:channel-a/identity-registry
RI_CHAIN_REGISTRY_SCHEMA_HASH=0x<non-zero-32-byte-schema-hash>
RI_EXTERNAL_SIGNER_ISSUER=adapter-operator
RI_EXTERNAL_SIGNER_KEY_ID=adapter-key-1
RI_EXTERNAL_TLS_CA_FILE=/run/tls/external-ca.crt
RI_EXTERNAL_TLS_CLIENT_CERT_FILE=/run/tls/external-client.crt
RI_EXTERNAL_TLS_CLIENT_KEY_FILE=/run/tls/external-client.key
```

生产模式要求两个不同 HTTPS URL。两个 sidecar 的完整签名快照及指定历史块
哈希必须完全一致，否则不写 SQLite。sidecar 必须从原生链推导 finalized 状态；
只把任意 JSON 包装成标准响应不构成链适配。

## 10. 编写原生 Rust 适配器

1. 在 `ri-chain-adapter` 新增模块并实现 `RegistryChainAdapter`。
2. 定义不可混淆的 `chain_identity` 和 `registry_locator`。
3. 明确最终性类型、回滚窗口和历史块哈希来源。
4. 验证 Registry 实现或快照 schema，不只验证 RPC URL。
5. 把链上原始状态转换为完整 `RegistryRecord`，不要在主同步循环增加分支。
6. 在 `Settings` 工厂注册适配器和专用配置。
7. 增加正常、RPC 分叉、回滚、状态篡改、超时和响应体上限测试。
8. 在生产文档中记录该链相对于 EVM 的能力差距。

若目标链只能提供当前键值且没有历史区块、包含证明、签名快照或可信最终性，
该链只能作为开发适配器，不能通过生产门禁。
