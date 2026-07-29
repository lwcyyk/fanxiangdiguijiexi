# Rust V2 实施计划与当前状态

## 决策

数据面选择 Rust，而不是 C++。原因是本项目的主要风险来自并发网络 I/O、解析不可信
输入、密码学对象规范化、生命周期和错误路径。Rust/Tokio 在保持接近 C++ 性能的同时，
能在编译期排除大类内存和数据竞争问题。C++ 只在必须复用既有 C/C++ DNS 内核或团队
无法维护 Rust 时更合适。

Python 不被全部删除。Admin、制品生成和低频发布仍可使用 Python；DNS Wrapper、
Agent、Trace 接入、证据验证和 Registry 读取已迁移到 Rust。

## 已完成

- Rust workspace 和固定工具链；
- 与 Python V1 一致的 canonical JSON、SHA-256、Ed25519 跨语言向量；
- DNS 服务 V2 身份、角色、endpoint、Registry 引用、Trace 和查询证据图；
- `controlled-strict` 与 `public-hybrid` 策略；
- challenge、签名 key binding、时效、环路、深度、节点/边上限；
- Rust Agent、目标响应证明、R1/R2 子图递归合并、mTLS 服务端/客户端；
- Rust UDP/TCP Wrapper、DNS question 核对、TCP 慢连接/并发上限和 `SERVFAIL`；
- 活动请求唯一 transaction ID/correlation、登记时间/行边界、ID 冷却复用、逐跳
  target correlation 和客户端 ID 恢复；
- Trace Unix Socket、producer UID/GID、SQLite 有界持久队列、批量 mTLS、不可变
  事务写入和无效事件 dead-letter 隔离；
- 一次性查询上下文、事件占用和 Wrapper/peer/Trace 分用途接口令牌；
- 顶层与递归终止节点缓存来源图、TTL、DNSSEC 要求传播、全路径身份有效期和
  Registry 代际失效；
- finalized Registry 同步与 chain/address/runtime hash/anchor/root/endpoint 核验；
- Registry 整批原子提交、finalized 高度单调与同高度区块哈希保护；
- Wrapper 对 Agent 证据和独立本地 Registry 快照的双重复核；
- 可检测旧 endpoint/移除 resolver 的分角色差量发布计划工具；
- Agent/Wrapper SQLite 阻塞隔离、下游/JSON-RPC 响应大小上限和四组件指标；
- digest 固定、离线组装、非 root Rust 生产镜像、单链路 Compose 和 CI Rust 门禁；
- 单节点、缓存、严格失败、公共混合、R1->R2->Root、篡改/环路/撤销测试。

## 仍属于现场 P0

以下内容不能用仓库内模拟值替代，未完成前不得声明真实生产上线：

1. 为现场使用的 Resolver 编写或接入内部 Trace 生产插件。它必须提供可靠解析上下文
   ID，并按规范产生 `correlation_id`/`target_correlation_id`；仅按时间/qname
   关联 pcap 或普通日志不合格。
2. `public-hybrid` 必须从现场验证型 Resolver 获取可信 DNSSEC 状态。
3. 部署真实 Registry，使用治理多签和四个独立业务角色账户完成隔离。
4. 用两条独立信任路径核验 chain ID、address 和 runtime code hash。
5. 签发现场 TLS/mTLS 证书，配置主机防火墙和日志访问控制。
6. 接入真实 Prometheus/Alertmanager、主机磁盘和集中日志。
7. 完成真实数据库备份/异机恢复演练。
8. 以现场峰值 QPS、包大小、TCP 比例、缓存命中率和最大链深执行容量测试。

这里的“现场 P0”是明确的上线门禁，不是代码声称已经完成的事项。

## 后续阶段

| 阶段 | 目标 | 退出条件 |
| --- | --- | --- |
| A | Resolver Trace 插件 | 并发、缓存、重试、DNSSEC 场景不串 trace |
| B | 单链路 shadow | 不向客户端放行，证据图完整率和延迟达标 |
| C | 小流量试点 | 1%/10% 流量下错误预算、告警、回滚通过 |
| D | 单链路生产 | 峰值容量、备份恢复、撤销演练通过 |
| E | 多链路复制 | L01/L02/L03 隔离矩阵和独立密钥审计通过 |

高可用不在当前单主机 SQLite profile 内。HA 阶段需要替换存储和事件队列，不能通过
共享 SQLite volume 或简单增加 Wrapper 副本实现。
