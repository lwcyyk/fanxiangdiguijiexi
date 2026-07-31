# 多链 Registry 安全边界

## 证明范围

系统证明“本机已接受的 Registry 快照来自固定链目标，并满足该适配器声明的
最终性与签名规则”。它不证明公共 Anycast 背后的具体物理服务器，也不把
Go-Norn 受控预发布的确认数语义描述成 EVM 的原生 finalized。

## 运行边界

| 组件 | 允许访问 | 禁止访问 |
|---|---|---|
| Registry Sync | 固定 EVM RPC、两个 Norn 只读代理或两个固定 Sidecar、SQLite | 链写入、动态上游、适配器回退 |
| Agent | 本地 SQLite、Trace、同链相邻 Agent | 区块链 RPC、跨链路 Agent |
| Wrapper | 本地 SQLite、本机 Agent、配置的 R1 | 区块链 RPC、其他链路 |
| Trace Adapter | 本机 Resolver Socket、本机 Agent | 区块链 RPC |
| Norn Publisher | 隔离的写节点 | DNS 链路服务器 |

每个递归解析器服务器使用独立 SQLite、Agent 密钥、TLS 和 Token。只有第一跳
R1 部署 Wrapper。Norn 网络至少两个节点，节点数据目录和共识密钥独立；原生
gRPC 端口不出管理隔离区，mTLS 代理只开放三个读取方法并拒绝写方法。

## 失败关闭

以下任一情况不会覆盖最后有效快照：未知或缺失适配器、新旧变量冲突、目标
链身份/Registry/schema 变化、检查点回退、同高度不同哈希、generation 回退、
签名错误、过期、双端点不一致、响应超限或 RPC 不可用。事务失败时 finalized
高水位、同步成功时间和缓存 generation 均保持原值。

超过 `RI_REGISTRY_MAX_STALENESS_SECONDS` 后，Agent 和 Wrapper readiness
失败，DNS 查询返回 SERVFAIL。不得通过禁用验证维持流量。

## External Sidecar

External 不是任意 HTTP 代理。配置固定两个独立 HTTPS 源、链身份、Registry
定位、schema hash、签名者身份和 Ed25519 公钥，并强制 mTLS。客户端禁止
重定向，响应 schema 禁止上游 URL 字段。支持其他链意味着该链实现此协议，
不表示自动兼容所有区块链。
