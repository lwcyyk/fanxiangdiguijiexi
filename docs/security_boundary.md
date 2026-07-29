# Rust V2 安全边界

## 系统证明什么

系统证明一次查询证据图中的 DNS 服务身份当前有效、端点和 Registry 锚一致，并且：

- 本地 Resolver Trace 观察到相应网络查询/响应；
- 受控目标 Agent 持有 identity 绑定私钥并观察到相同响应摘要；或
- 公共 Authority 服务身份已登记且验证型 Resolver 报告 DNSSEC `SECURE`；
- 证据与本次随机 challenge、活动请求唯一 correlation、DNS 摘要、时间窗和拓扑
  约束绑定。
- Wrapper 查询上下文只接受登记时间和行边界之后产生、且未被其他请求占用的 final
  response 事件；内部 transaction ID 释放后还需经过冷却期。

它比 V1 静态上游链更强，因为路径来自实际查询事件；但仍不是 DNS 执行的硬件远程
证明。

## 系统不证明什么

- 合法登记但已被攻陷的 Resolver 一定返回正确结果；
- 运营者不会恶意配置或伪造其受信 Trace 插件；
- 公共 Anycast 响应来自某台指定物理服务器；
- 没有 Agent 的公共 Authority 具备实例私钥身份；
- DNSSEC 没有覆盖的数据一定正确；
- TPM/TEE、进程二进制、内核或硬件状态可信；
- 普通 pcap/dnstap 的时间关联等同于可靠内部解析上下文。

`public-hybrid` 的结论必须表述为“服务身份登记 + DNSSEC”，不能表述为“物理 Root
服务器实例身份认证”。

## 信任根

- 离线/多签 Governance 和独立 Registry 角色；
- constructor 初始 Admin 在发布前只保留治理角色，四个业务角色属于互不相同账户；
- 固定 issuer Ed25519 公钥包；
- 固定 chain ID、Registry address、runtime code hash；
- finalized Registry 状态；
- 每个受控 DNS 服务 identity 中绑定的 Agent public key；
- 现场 Resolver 内部 Trace 生产插件和 DNSSEC 验证状态；
- 链路主机、Unix producer UID、mTLS CA、私钥和分用途 API token 保护。

Indexer、调用方提交的路径/匹配模式、DNS 客户端、自报时间和未签名 Agent 输出均
不可信。

## 失败关闭

下列任一情况返回 `SERVFAIL`：

- identity 缺失、签名错误、过期、暂停、撤销或版本/hash 不匹配；
- Root 非 ACTIVE、endpoint 未绑定、chain/address/code hash 不一致；
- Trace anchor、outbound event、response digest 或目标 endpoint 缺失；
- 查询上下文未登记、事件早于登记时间/行边界、超出逐跳观察时间约束、事件已被其他
  请求占用或调用端点/token 错误；
- `key_id`、algorithm、public key 或 Agent signature 不匹配；
- target response attestation 缺失或与本地事件不一致；
- 递归子图 entry、DNS digest、challenge 或签名不一致；
- 节点/边超限、不可达节点、重复 edge、环路或深度超限；
- 公共 Authority DNSSEC 非 `SECURE`；
- cache source graph 不在当前 Registry 代际、递归终止缓存子图缺失、DNSSEC 要求
  在递归缓存中被降级，或 TTL/任一来源 identity 已过期；
- Agent/Registry 响应超过配置大小、Trace spool 已满，或本次查询所需 Trace 事件
  已被隔离到 dead-letter；
- Agent/RPC/上游超时、Wrapper 过载或依赖未就绪。

原始 DNS 响应在完整验证前只保存在 Wrapper 内存，失败时不会泄漏给客户端。

## 星形隔离

L01/L02/L03 的 Resolver、Agent、数据库和密钥相互独立。Agent 子图通信只允许沿
同一条真实 DNS 链的相邻节点发生。中心 Hub 只承担治理、只读状态、制品和运维，
不进入客户端 DNS 数据面。

## 密钥泄漏

Agent 密钥泄漏会允许攻击者伪造该 Agent 签名，但仍受到 Registry、目标响应证明、
Trace 和相邻节点约束。issuer 或 Registry 高权限密钥泄漏影响更大，因此必须离线/
多签、分角色并与链路主机隔离。怀疑泄漏时由独立 Revoker 撤销，不能通过关闭验证
恢复可用性。

Wrapper、peer Agent 和 Trace token 只用于接口用途隔离，不能替代 mTLS。peer token
仅在同一实际 DNS 链内共享；任一链路 token 泄漏后必须轮换，且不得扩大到其他链路。
