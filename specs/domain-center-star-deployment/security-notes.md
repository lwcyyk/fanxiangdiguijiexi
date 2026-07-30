# 域名中心星型多服务器部署安全说明

## 1. 信任根

- Governance 管理角色授予和撤销；
- issuer Ed25519 私钥签署 `DnsServerIdentityV2`；
- EVM finalized 状态固定 Root、identity anchor、Endpoint 和撤销；
- 每个 Agent 的独立 Ed25519 密钥证明证据响应；
- mTLS 和分用途 Token 保护 Wrapper、Trace 和相邻 Agent 接口；
- Resolver 内部 Trace 是实际查询路径的事实来源。

任何一个信任根都不能用 qname、时间窗口、pcap 或 Mock 日志替代。

## 2. 密钥分布

Hub 治理隔离区持有：

- Governance、四类业务角色的签名能力；
- issuer 离线签名能力。

链路单元只持有：

- 本 unit 的 Agent 私钥；
- Agent 服务端和三个客户端用途的 TLS 私钥；
- Trace ingest、Wrapper 和同链 peer Token；
- issuer 公钥和签名 identity；
- 只读 RPC 配置。

链路服务器被入侵后不应获得 Registry 写权限或其他链路身份。

## 3. 文件和 Git

以下路径必须保持忽略：

```text
deployments/field/private/
deploy/field/private/
artifacts/field-deployment/private/
```

可提交内容不得包含私钥、Token、密码、RPC API key 或证书私钥。部署证据只记录
RPC 主机名、地址、哈希、交易、状态和脱敏错误。

## 4. 网络

- 默认拒绝未列出的链路间通信；
- Agent 和 metrics 不暴露公网；
- RPC 仅 HTTPS，Registry Sync 只读；
- SSH 只允许堡垒机；
- 日志只允许链路向 Hub 单向 TLS 上送；
- 同链 R1→R2 只允许明确的 DNS 和 Agent mTLS 流量。

## 5. 失败关闭

Trace、Agent、Registry freshness、identity、Root、Endpoint、DNSSEC 或证据图任一
不满足策略时，Wrapper 不得释放已暂存的原始 DNS 响应。回滚只能切回原 DNS 服务
入口，不能通过关闭验证继续把 Wrapper 留在生产路径。

## 6. 预发布差距

- Sepolia 不等同于生产联盟链或 Ethereum Mainnet；
- 测试网 Governance EOA 不等同于生产多签；
- 公共 DNS 服务 identity 不证明某一 Anycast 物理实例；
- 没有现场 Resolver Trace、真实网络隔离和压力结果时，不具备完整生产证明；
- 当前 SQLite 架构不支持共享存储和多主写入。
