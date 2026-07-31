# 多链 Registry 故障排查

## 启动立即失败

先检查明确选择和变量冲突：

```bash
test -n "${RI_CHAIN_ADAPTER:-}"
env | sort | grep -E '^RI_(CHAIN|WEB3|REGISTRY|NORN|EXTERNAL)_'
```

`RI_CHAIN_ADAPTER` 只能是 `evm`、`norn` 或 `external`。EVM 新旧变量同时
存在时必须相等。不要删除报错变量后依赖默认适配器，系统没有默认或回退。

## Registry Sync 不 Ready

```bash
curl --fail http://127.0.0.1:9109/healthz
curl --fail http://127.0.0.1:9109/metrics
docker compose --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml logs --since 15m registry-sync
```

按日志分类：

| 错误 | 核查 |
|---|---|
| chain identity mismatch | RPC/创世块是否属于批准网络 |
| Registry target changed | 是否误用旧 SQLite；不要就地换链 |
| checkpoint rollback/hash changed | 两个端点和本地高水位 |
| signature/signer mismatch | issuer 公钥包、issuer、key ID、轮换代际 |
| snapshot expired | 时钟同步、`valid_until`、发布流程 |
| response exceeds limit | Sidecar/Norn 返回体和 `RI_RPC_MAX_RESPONSE_BYTES` |
| endpoints disagree | 两个节点是否同步到同一已确认状态 |

失败期间不要删除 SQLite。确认配置错误后恢复批准配置，等待下一次成功同步。

## Norn

Norn 没有原生 finalized 标签。检查两个 mTLS 代理分别可达，最低 head 扣除
确认数后仍大于 0，扫描范围覆盖最近一次 Registry `set` 交易。单节点可用不算
成功；第二节点不可用或结果不同都应失败。

本地受控预发布补丁把单个 Registry value 限制为 48 KiB，并使用 64 KiB UDP
接收缓冲。发布前检查签名快照大小；超过限制时应拆分身份批次或重新设计
Norn 原生发布格式，不能放宽限制后继续使用 UDP gossip。

原生 gRPC 没有 TLS/鉴权。若代理允许
`/Blockchain/SendTransactionWithData`，立即停止验收并隔离端口。

## External

HTTP、重定向、一个 Sidecar、相同网络源、缺少 mTLS 都是配置错误。两个
Sidecar 必须返回字节语义一致的签名快照和历史检查点。调用方不能在请求或
响应中指定新的 RPC 地址。

## SQLite

```bash
sqlite3 /path/evidence-v2.db 'PRAGMA integrity_check;'
sqlite3 /path/evidence-v2.db \
  "SELECT meta_key,meta_value FROM ri_v2_meta
   WHERE meta_key LIKE 'registry_%' OR meta_key='cache_generation';"
```

迁移后 `schema_version` 为 `3`。旧 EVM v2 行会保留并转换为 typed metadata。
Norn/External 行的旧 EVM 三列为空/零，仅作兼容列，真实语义在中性列和
`snapshot_json` 中。
