# 生产架构：Rust V2 查询证据图

## 1. 目标与结论

生产数据面使用 Rust，Python 仅保留在低频管理面。系统验证的对象是一次 DNS
查询实际使用的 DNS 服务身份，包括递归解析器、转发器，以及在可观测范围内实际
访问的 Root、TLD 和权威服务。它不再使用静态配置推测一条固定递归链。

查询结果只有在以下条件同时成立时才放行：

1. 上游 DNS 返回结构有效的原始响应；
2. 本次解析的实际 Trace 已到达本链路 Agent；
3. 查询证据图中的所有节点身份、Registry 状态、端点绑定和签名通过；
4. `controlled-strict` 中每条边都有目标 Agent 对实际响应摘要的证明；
5. `public-hybrid` 中没有 Agent 的公共 Root/TLD/Authority 至少具备 Registry
   服务身份登记和 DNSSEC `SECURE` 证据；
6. challenge、摘要、有效期、最大节点数、最大边数、深度、环路和缓存来源均通过。

任一条件失败，Wrapper 丢弃原始响应并返回 `SERVFAIL`。

## 2. 生产组件

| 组件 | 实现 | 作用 |
| --- | --- | --- |
| `ri-wrapper` | Rust/Tokio | UDP/TCP DNS、并发/连接上限、证据与本地 Registry 复验 |
| `ri-agent` | Rust/Axum | Trace 查询、逐跳响应证明、递归子图合并和 Ed25519 签名 |
| `ri-trace-adapter` | Rust/Tokio | Unix Socket、UID 校验、持久落盘和批量 mTLS 续传 |
| `ri-chain-adapter` | Rust | 统一链身份、最终检查点、Registry 快照和回滚检测；内置 EVM/Norn |
| `ri-registry-sync` | Rust | 独立核验身份、适配器快照、Root 和 endpoint 后原子写入 SQLite |
| `ri-store` | Rust/SQLite | V2 身份、Trace、图和 Registry 快照；WAL、事务和代际失效 |
| Admin/Publisher | Python + Web3 | 低频制品签发和分角色合约写入，不进入 DNS 热路径 |
| Registry | Solidity | 身份锚、Root、端点绑定、撤销和角色隔离 |

Rust workspace 位于 `rust/`，单链路生产清单位于
`deploy/link/docker-compose.yml`。

## 3. 查询证据图

```text
client -> Wrapper -> R1
                    |
                    +-- actual query event --> Root
                    +-- actual query event --> TLD
                    `-- actual query event --> Authority

或：

client -> Wrapper -> R1 -> R2 -> Root/TLD/Authority
                    |     |
                    |     `-- R2 Agent 子图
                    `-- R1 Agent 合并并签名最终图
```

边表示“观察者 DNS 服务实际向目标端点发送了该 DNS 查询并收到该响应”，不是根据
规划图推导的逻辑关系。每条边保存自己的 query/response wire digest；DNS transaction
ID 在计算摘要前清零。中间 Root/TLD 响应摘要不要求等于最终客户端响应摘要。

Wrapper 为每个活动请求分配唯一内部 DNS transaction ID，并把该 ID 与清零 ID 后的
wire digest 共同计算成 `correlation_id`。Resolver 插件将其写入该解析上下文的全部
事件；每次 outbound 事件再按实际下一跳报文计算并记录 `target_correlation_id`，该值
成为下游解析器上下文的 correlation。Agent 只做精确 correlation 匹配，Wrapper 验证
完成后恢复客户端原 transaction ID。这样即使多个并发请求的 qname、query digest 和
response digest 完全相同，也不能相互借用 Trace。

Wrapper 在向 R1 发送请求前写入一次性查询上下文、登记时间和当时的 Trace 行边界。
Agent 的 Wrapper 端点只能占用登记时间与行边界之后产生的 final resolver response，
事件被一个请求占用后不能再被其他请求使用。内部 transaction ID 释放后还会进入
可配置冷却期，避免迟到事件在 ID 回绕后被新请求借用。相邻 Agent 请求携带父事件的
实际观察时间，目标 Agent 只在严格时间界限内匹配。相邻 Agent 调用独立的递归取证
端点；两类端点除 mTLS 外还使用互不相同的 bearer token，调用方不能通过 JSON
切换匹配模式。

R1 为迭代解析器时，R1 Trace 会形成 `R1 -> Root/TLD/Authority` 的观察边。R1
把请求转发给 R2 时，R1 Agent 获取 R2 的响应证明和 R2 子图，最终形成
`R1 -> R2 -> ...`。访问集合、最大深度和有向环检测阻断递归 Agent 环路。

## 4. 两种验证模式

### 4.1 `controlled-strict`

适用于域名中心完全控制的实验或专网：

- Recursive、Forwarder、Root、TLD、Authority 全部登记 V2 身份；
- 每个服务旁部署 Agent，并为 Agent 公钥、服务 URL 签发身份绑定；
- 每条边必须有目标 Agent 从本机 Trace Store 生成的响应证明；
- Authority 路径同时要求 DNSSEC `SECURE`。

该模式可以证明受控服务实例持有对应 Agent 私钥，并确实观察到匹配 DNS 响应。

### 4.2 `public-hybrid`

适用于访问公共 Root/TLD/Authority：

- Recursive 和 Forwarder 仍必须有 Agent，不能只靠 Registry 登记；
- 公共 Authority 可没有 Agent，但服务身份必须登记且 DNSSEC 为 `SECURE`；
- Anycast 只能声明服务身份，例如 `a.root-servers.net`，不能声称认证了某台物理机；
- DNSSEC 为 `INSECURE`、`BOGUS` 或 `INDETERMINATE` 时失败关闭。

## 5. Registry 一致性

`ri-registry-sync` 每轮执行以下操作：

1. 根据 `RI_CHAIN_ADAPTER` 选择 EVM、Go-Norn 或标准外部 sidecar；
2. 核对不可变链身份、Registry 定位和实现/schema 哈希；
3. 取得原生 finalized 检查点，或按适配器声明的确认数规则推导检查点；
4. 验证 identity issuer Ed25519 签名；
5. 核对 `resolverIdKey`、object hash、version、validUntil 和状态；
6. 核对 identity 所属 Root 状态；
7. 对每个完整 V2 endpoint 计算绑定键并核对合约映射；
8. 原子写入本地 SQLite，并在变化、撤销或不一致时推动缓存代际失效。

EVM 适配器固定 `eth_chainId` 和 runtime code hash，并在指定区块执行
`eth_call`。Go-Norn 适配器固定创世块哈希，通过两个 mTLS 只读节点核对已确认
`set` 交易和签名快照。其他链通过标准 sidecar 协议返回签名归一化快照和历史
块哈希；两个 sidecar 不一致时失败关闭。

链路主机只有只读 RPC 权限，不保存任何 Registry 写入私钥。
整批 identity 全部核验成功且区块哈希二次确认后才提交一个 SQLite 事务；低于已记录
finalized 高度的快照，以及同高度不同哈希的快照均被拒绝且不更新同步心跳。
新 finalized block 只刷新链证明位置，不自动失效缓存；只有 identity、Root、endpoint
或合约固定值的语义状态变化才推进本地缓存代际。同步心跳超时仍会使 Agent 失败关闭。

Wrapper 不仅验证 Agent 和 issuer 签名，还逐节点读取 Registry Sync 独立维护的同链路
SQLite 快照。身份对象、语义状态、证明区块顺序和同步心跳任一不一致都会失败关闭，
避免仅凭 Agent 自报的 `ACTIVE` 状态放行。
相邻 Agent 可以处于不同的 finalized 高度；只要合约部署、对象、Root、endpoint 和
状态语义一致，子图入口允许保留其独立签名的较早证明位置，不要求瞬时锁步。

## 6. Trace 真实性边界

`ri-trace-adapter` 接收换行分隔的 `TraceEventV2`，但它只是安全传输和批量接入层。
每条有效事件先写入独立 SQLite spool，Agent 批量确认成功后才删除；网络错误、
`408/425/429` 和服务端错误会持续重试并把退避上限限制为 5 秒，Adapter 重启后继续
上传。Agent 对单个事件返回 `400/409/413/422` 时，该事件进入
`trace_dead_letter`，不会阻塞后续有效事件；认证/授权等其他非瞬时错误使进程失败并
等待运维处理。spool 事件数有硬上限，spool 卷必须与 evidence 卷分别监测容量。
生产解析器必须通过其内部插件/探针生成事件，并满足：

- 同一次内部解析上下文使用同一 `trace_id`；
- 当前解析上下文所有事件使用进入该上下文的 `correlation_id`；
- 每个 outbound 事件按下一跳实际 transaction ID 和 wire digest 计算
  `target_correlation_id`；
- 记录 client final response、每次 outbound query/response 和 cache hit；
- query/response digest 来自原始 DNS wire message；
- DNSSEC 状态来自验证型解析器，不允许由 Wrapper 或客户端自报；
- target endpoint 来自实际 socket 目的地址；
- 事件不能依靠时间窗口、qname 或“最新相同摘要”猜测关联。

仅有 pcap 或普通 dnstap、但不能提供可靠内部解析上下文 ID 时，不能启用
“全路径已认证”的生产声明。这是现场 Resolver 集成的 P0 上线门禁。

## 7. 缓存命中

缓存命中时实际网络路径只有 R1，因此图包含 R1 单节点和 `CacheProvenanceV2`：

- source graph digest 必须存在于当前 Registry 代际；
- CacheHit 事件必须显式声明该 digest，禁止按“最近相同摘要”代替；
- DNS TTL、身份有效期和策略最大 TTL 均未到期；
- 任一身份/Root/endpoint 更新或撤销都会改变代际，使旧来源失效。

如果实际路径的下游递归解析器命中缓存，父图必须携带该下游 Agent 签名的单节点
缓存子图，并与父边的 correlation、query/response digest 和身份完全绑定。来源图中
任一身份到期都会使该缓存证明失效；来源图是否要求 DNSSEC 也会写入缓存来源并在
每一层递归缓存中传播，不能通过二次缓存把 `SECURE` 要求降级。

系统不会伪造本次未发生的 Root/TLD/Authority 网络边。

Trace 事件按 `event_id` 不可变写入，并由 `RI_TRACE_RETENTION_SECONDS` 周期清理。
证据图至少保留一个最大缓存 TTL 的宽限期，确保 CacheHit 引用的来源摘要仍可核对；
SQLite 所在卷仍必须配置容量与 inode 告警。

## 8. 隔离与可用性

每条链路使用独立 Wrapper、Agent、Trace Adapter、Registry Sync、SQLite 和密钥。
不同链路禁止 Resolver-to-Resolver、Agent-to-Agent 和数据库共享。只有同一实际
DNS 链内的相邻 Agent 才能通过 mTLS 通信。

当前支持单链路单主机/单 SQLite 数据单元，不支持把 SQLite 放到共享文件系统，也
不宣称多主机高可用。Trace Adapter 已有单机持久 spool；需要 HA 时仍应把
`ri-store` 和 spool 替换为具备跨主机一致性及故障转移能力的存储。

Agent 和 Wrapper 的 SQLite 操作运行在 Tokio 阻塞线程池；Agent 子图、Wrapper
证据图和 Registry JSON-RPC 响应均采用流式大小限制。Wrapper、Registry Sync 和
Trace Adapter 分别在 `9108`、`9109`、`9110` 暴露本机监控端口；Agent 指标位于其
mTLS `8443` 服务的 `/metrics`，采集器必须使用受信客户端证书。
