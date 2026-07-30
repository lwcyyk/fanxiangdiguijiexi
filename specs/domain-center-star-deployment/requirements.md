# 域名中心星型多服务器部署需求

状态：已批准执行

基准分支：`master`；每次发布必须另外批准并固定 40 位 Git commit

实际工作分支：`main`（跟踪 `origin/master`）

编制日期：2026-07-30

## 1. 目标

在不改变 DNS 客户端报文格式的前提下，把现有 Rust V2 数据面、EVM
`ResolverIdentityRegistryV1` 和中心治理流程部署为：

- 一个不参与 DNS 查询转发的中心 Hub；
- L01、L02、L03 等相互隔离的完整链路单元；
- 每个入口链路单元独立运行 Wrapper、Agent、Trace Adapter、Registry Sync 和
  SQLite；
- 同一真实 DNS 链需要 R1 转发 R2 时，R2 使用独立 Agent、Trace Adapter、
  Registry Sync 和 SQLite，并且只允许同链相邻 Agent 通信；
- 先完成 Shadow 验收，再按批准比例切流；
- 高可用通过复制完整链路单元实现，不共享 SQLite。

## 2. 范围

本规格交付：

1. 中心 Hub、链路服务器、测试客户端的主机和网络规划；
2. 可提交的现场清单模板，以及不可提交的真实清单路径；
3. 清单结构、占位值、地址、端口、角色、证书、Token 和跨链路隔离校验；
4. 每条链路独立运行包的生成和 SHA-256 清单；
5. 单机分阶段安装、启动、健康检查和证据采集命令；
6. Prometheus 告警规则、Docker 日志轮转和磁盘监控要求；
7. SQLite 在线备份、隔离恢复演练、容量测试和回滚；
8. 一份现场实施与验收版完整手册；
9. 本机可以完成的代码、配置和安全门禁验证。

## 3. 不在本次代码中伪造的内容

- 现场主机、VIP、Resolver 后端、堡垒机或防火墙；
- 真实 mTLS 证书、Agent 私钥和三类 Token；
- 真实 Resolver 内部 Trace 插件及其事件；
- 尚未完成的 Root、Resolver identity、Endpoint 和撤销写交易；
- 现场 Prometheus、日志平台、备份存储和告警接收人；
- 现场峰值 QPS 和批准阈值；
- 公共 Anycast 某个物理实例的硬件级身份。

Sepolia Registry 部署、双 RPC finalized 核验和五类角色拆分已经真实执行，证据在
`deployments/sepolia/`。上述其余输入缺失时，必须继续完成本地实现和验证，但相应
现场任务保持阻断，不得用示例 IP、虚假证书、模拟 Trace 或 Mock RPC 声称部署完成。

## 4. 必需输入

### 4.1 发布输入

- 40 位 Git commit；
- 固定到 `sha256` digest 的 Rust 镜像；
- 镜像仓库及链路主机的拉取权限；
- 经批准的变更单号、观察窗口、切流阈值和回滚 RTO。

### 4.2 EVM 输入

- 两个由不同服务商提供的非 Mainnet HTTPS 只读 RPC；
- 两路 RPC 应具备现场批准的可用性和限流额度，写入请求不得依赖免费公共端点；
- 通过实际 RPC 获取的 chain ID；
- 非零 Registry 地址和 finalized runtime code hash；
- 已拆分的 Governance、Root Publisher、Resolver Publisher、Endpoint Manager、
  Revoker 地址；
- 签名 identities、issuer 公钥、不可变 Registry 发布计划和五阶段链上发布证据；
- 双 RPC 验证结果、角色配置结果、发布计划和发布交易记录的文件路径。

### 4.3 每个链路单元输入

- 唯一的 link ID、unit ID、Compose project、server ID 和 Agent key ID；
- 目标主机、管理网 IP、Wrapper IP/VIP、Resolver upstream 和端口；
- Resolver 进程 UID/GID、Trace Socket 目录和真实 Trace 插件版本；
- 独立 Agent 私钥、Wrapper/Trace/Peer Token 和 mTLS 文件；
- DNS、Agent、metrics、SSH、RPC、日志和监控防火墙关系；
- identity 和 issuer 公钥制品路径；
- Shadow 测试域名、容量目标和回滚入口。

## 5. 安全与隔离要求

- 真实现场清单、运行包、私钥、Token 和 RPC 凭据必须被 Git 忽略；
- 运行包不得包含 Governance、Publisher、Endpoint Manager、Revoker 或 issuer
  私钥；
- L01、L02、L03 不得复用 Agent 私钥、服务私钥、Wrapper Token 或 Trace Token；
- Peer Token 只允许同一 link ID 的相邻 Agent 共用；
- 跨链路 Resolver、Agent、SQLite、metrics 和管理端口默认拒绝；
- 镜像必须固定 digest，禁止 `latest` 和可移动标签；
- 链路配置必须拒绝 Mainnet chain ID、零地址、零哈希、文档保留 IP、
  `example.invalid` 和回环 upstream；
- Wrapper 服务地址不能与其 Resolver upstream 形成回路；
- 容器继续以 UID 10002、只读文件系统、`cap_drop: ALL` 和
  `no-new-privileges` 运行；
- Docker 日志必须有限额，数据盘必须被主机监控；
- 生产服务器禁止执行 `docker compose down -v`。

## 6. 启动和验收顺序

每条入口单元必须按以下顺序启动：

1. Registry Sync，并等待 `/readyz`；
2. Agent 和 Trace Adapter，并等待 Trace Socket 和 `/readyz`；
3. 真实 Resolver Trace 生产者；
4. Wrapper，并等待 `/readyz`；
5. UDP/TCP Shadow、负向、容量、备份恢复和回滚验收；
6. 1% → 10% → 50% → 100% 切流。

Compose 的 `service_started` 不能代替 readiness 门禁。

## 7. 失败条件

出现以下任一情况必须返回非零状态并停止后续阶段：

- 清单字段缺失、重复或仍为占位值；
- Git commit 与运行源码不一致；
- 镜像不是 digest 引用；
- chain ID 为 `1`、两个 RPC 主机相同或与 Registry 证据不一致；
- Registry 地址、code hash、identity、Root 或 Endpoint 核验失败；
- 现场 Agent 私钥导出的公钥与签名 identity 中的公钥不一致；
- Registry 计划哈希无效、五阶段发布记录不完整或发布交易失败；
- 任意跨链路秘密复用或 endpoint/port 冲突；
- TLS 私钥权限过宽、证书过期或密钥不匹配；
- 任一 `/readyz` 失败；
- Trace 缺失、串线、spool 持续增长或存在未处理 dead-letter；
- 负向测试释放原始 DNS 响应；
- SQLite `integrity_check` 失败；
- 容量、磁盘或回滚 RTO 未达到批准阈值。

## 8. 完成表述

只有 Registry、角色、真实身份、Registry Sync、真实 Trace、三条链路正负向测试、
隔离、监控、备份恢复、容量和回滚均有现场证据时，才能声明：

> 域名中心星型多链路部署完成。

如果缺少真实 Resolver Trace，只能声明：

> Registry 与链上查询闭环完成，DNS 全路径部署仍被 Trace 门禁阻断。
