# 生产部署模拟执行说明

> 文档状态：模拟执行，不是生产变更记录  
> 编制日期：2026-07-13  
> 适用版本：Git 提交 `4ac4444` 之后的生产基线  
> 重要说明：本文没有在本机或任何真实生产环境执行链上交易、防火墙变更、证书签发、流量压测或数据恢复。

## 1. 目的

本文说明 Resolver Identity 在真实生产环境中通常如何部署、每一步应看到什么结果、异常时系统会处于什么状态，以及什么情况下必须停止上线。

本文可以用于：

- 生产变更评审；
- 预生产演练脚本；
- 上线执行记录模板；
- 安全、网络、SRE 和链上治理团队之间的职责确认。

本文不能替代：

- 真实 RPC 和合约部署回执；
- 生产防火墙审批单；
- 企业 CA 签发记录；
- 监控平台中的实际告警；
- 真实备份恢复报告；
- 生产规格环境中的容量测试报告。

## 2. 模拟生产拓扑

以下地址全部为示例，不得写入真实 `.env.production`：

```text
DNS 客户端网段 10.20.0.0/16
        |
        | UDP/TCP 53
        v
生产主机 dns-gateway-01
  |- local-wrapper
  |- indexer
  |- event-watcher
  |- admin（仅管理网/localhost）
  `- SQLite 本地 Docker volume
        |
        +-- HTTPS JSON-RPC --> EVM RPC A / EVM RPC B
        |
        `-- mTLS --> R1 Agent --> mTLS --> R2 Agent
                        |                      |
                        v                      v
                   R1 Resolver            R2 Resolver
                                               |
                                               `-- 明确配置的 terminal upstream
```

模拟域名和地址：

| 对象 | 示例值 | 生产要求 |
|---|---|---|
| Wrapper 上游 R1 | `10.30.0.53:53/udp` | 必须是实际第一跳 |
| R1 Agent | `https://agent-r1.prod.example.com:8443` | 企业 CA 或专用 CA，要求 mTLS |
| R2 Agent | `https://agent-r2.prod.example.com:8443` | 由 R1 Agent 访问 |
| Terminal upstream | `10.30.2.53:53/udp` | 必须明确声明，不允许推测 |
| Admin | `127.0.0.1:8002` | 仅经堡垒机或管理隧道访问 |
| Metrics | `127.0.0.1:9108` | 仅本机 Prometheus Agent 访问 |
| Registry RPC | `https://rpc-a.prod.example.com` | TLS，另有独立 RPC B 做核验 |

## 3. 参与方和职责

| 角色 | 推荐持有方式 | 职责 |
|---|---|---|
| Registry Admin | 多签或离线治理账户 | 授予/撤销角色，不处理日常发布 |
| Online Publisher | 受限热钱包/HSM | 发布 root 和 resolver 对象 |
| Endpoint Manager | 独立运维账户 | 管理 endpoint binding |
| Revoker | 独立应急账户或多签 | 撤销 root/resolver |
| DNS Operations | 生产主机权限 | Wrapper、Agent、Indexer 运维 |
| PKI/Security | 企业 CA/KMS 权限 | mTLS、密钥轮换、审计 |
| SRE/On-call | 监控和告警权限 | 容量、可用性、恢复演练 |

### 3.1 当前版本的角色拆分约束

当前 `AdminPublisher` 使用一个 Web3 签名者依次执行：

1. `publishRoot`；
2. `publishResolver` 或 `updateResolver`；
3. `bindEndpoint` / `unbindEndpoint`。

因此当前可直接运行的最小权限模型是：

| 账户 | 实际角色 |
|---|---|
| Governance Admin | `DEFAULT_ADMIN_ROLE` |
| Online Publisher | `ROOT_PUBLISHER_ROLE`、`RESOLVER_PUBLISHER_ROLE`、`ENDPOINT_MANAGER_ROLE` |
| Emergency Revoker | `REVOKER_ROLE` |

这已经将治理、日常写入和紧急撤销分开，但 Online Publisher 仍同时具有 endpoint 权限。

如果组织政策要求 Publisher 与 Endpoint Manager 使用完全不同的私钥，必须先改造应用的分角色签名与发布工作流。不能简单移除 Online Publisher 的 `ENDPOINT_MANAGER_ROLE`，否则发布会在 endpoint binding 阶段失败。

## 4. 模拟变更窗口

推荐安排 90 至 150 分钟预生产变更窗口，并满足：

- 真实生产流量尚未切入；
- DNS 旧路径仍可立即恢复；
- Registry Admin、Revoker、网络、安全和 SRE 人员在线；
- 已冻结镜像 digest、Git commit 和合约 artifact；
- 所有命令输出写入受控变更记录，私钥内容不得进入日志。

模拟时间线：

| 时间 | 动作 | 负责人 |
|---|---|---|
| T-60 | 主机、镜像、密钥、RPC 预检 | DNS Ops / Security |
| T-45 | 部署 Registry，双 RPC 核验 | Chain Ops |
| T-35 | 授权并核对角色矩阵 | Governance |
| T-25 | 核对拓扑和 mTLS | Network / PKI |
| T-15 | 启动服务、监控和告警 | SRE |
| T-10 | 正向及 fail-closed 验收 | QA / Security |
| T-5 | 备份恢复验证、Go/No-Go | Change Manager |
| T+0 | 灰度 DNS 流量 | DNS Ops |
| T+30 | 扩大流量或回滚 | Change Manager |

## 5. 阶段一：发布物和主机预检

### 输入

- Git commit；
- 生产镜像 digest；
- 哈希锁定依赖文件；
- `.env.production`；
- issuer 公钥包；
- Docker secrets；
- 两个相互独立的 EVM RPC。

### 模拟命令

```bash
git status --short
git rev-parse HEAD
docker image inspect resolver-identity-prototype:0.1.0-production \
  --format '{{.Id}} {{.Config.User}}'
stat -c '%a %n' .env.production deploy/secrets deploy/secrets/*
docker compose --env-file .env.production \
  -f docker-compose.production.yml config --quiet
```

### 预期结果

- Git 工作区无未审查变更；
- 镜像 digest 与审批单一致；
- 镜像用户是 `resolver`；
- `.env.production` 和 secret 文件为 `0600`，secret 目录为 `0700`；
- Compose 配置可渲染；
- 不存在 `example.invalid`、RFC 5737 示例 IP、零地址或 `REPLACE` 字样。

### 停止条件

- 镜像只能用可移动标签识别，不能提供 digest；
- secret 出现在 Git、命令行参数或集中日志；
- SQLite volume 位于 NFS 或会被多主机同时挂载；
- Admin 端口将暴露到业务网或公网。

## 6. 阶段二：部署 Registry 和角色授权

### 6.1 部署

推荐构造函数中的 `initialAdmin` 直接使用治理多签，而不是日常发布热钱包：

```bash
cd contracts
forge create src/ResolverIdentityRegistryV1.sol:ResolverIdentityRegistryV1 \
  --rpc-url "$RPC_A" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --constructor-args "$GOVERNANCE_ADMIN"
```

真实执行时，私钥应通过受控 signer/HSM 注入，不应直接保存在 shell history。记录：

- 部署交易哈希；
- 区块号；
- 合约地址；
- 部署账户；
- constructor 参数；
- 合约 artifact SHA-256；
- 交易最终确认数。

### 6.2 角色授权

先从合约读取角色常量，禁止手工录入 role hash：

```bash
DEFAULT_ADMIN_ROLE=$(cast call "$REGISTRY" 'DEFAULT_ADMIN_ROLE()(bytes32)' --rpc-url "$RPC_A")
ROOT_PUBLISHER_ROLE=$(cast call "$REGISTRY" 'ROOT_PUBLISHER_ROLE()(bytes32)' --rpc-url "$RPC_A")
RESOLVER_PUBLISHER_ROLE=$(cast call "$REGISTRY" 'RESOLVER_PUBLISHER_ROLE()(bytes32)' --rpc-url "$RPC_A")
ENDPOINT_MANAGER_ROLE=$(cast call "$REGISTRY" 'ENDPOINT_MANAGER_ROLE()(bytes32)' --rpc-url "$RPC_A")
REVOKER_ROLE=$(cast call "$REGISTRY" 'REVOKER_ROLE()(bytes32)' --rpc-url "$RPC_A")
```

由 Governance Admin 多签提交以下调用：

```text
grantRole(ROOT_PUBLISHER_ROLE, ONLINE_PUBLISHER)
grantRole(RESOLVER_PUBLISHER_ROLE, ONLINE_PUBLISHER)
grantRole(ENDPOINT_MANAGER_ROLE, ONLINE_PUBLISHER)
grantRole(REVOKER_ROLE, EMERGENCY_REVOKER)
```

随后撤销 Governance Admin 的日常操作角色，只保留 `DEFAULT_ADMIN_ROLE`。不要撤销最后一个管理员；合约会拒绝该操作。

### 预期角色矩阵

| 账户 | Admin | Root | Resolver | Endpoint | Revoker |
|---|---:|---:|---:|---:|---:|
| Governance Admin | 是 | 否 | 否 | 否 | 否 |
| Online Publisher | 否 | 是 | 是 | 是 | 否 |
| Emergency Revoker | 否 | 否 | 否 | 否 | 是 |

每个单元格均使用 `hasRole(bytes32,address)` 从 RPC A 和 RPC B 分别读取并保存输出。

### 停止条件

- 部署账户或 Online Publisher 仍持有 `DEFAULT_ADMIN_ROLE`；
- Governance Admin 同时承担日常热钱包职责；
- Revoker 私钥与 Online Publisher 存储在同一主机；
- 任一角色读取结果与批准矩阵不一致。

## 7. 阶段三：独立核验链 ID、地址和代码哈希

在两个独立 RPC 上执行：

```bash
PYTHONPATH=src python3 tools/inspect_registry.py \
  --rpc-url "$RPC_A" --contract-address "$REGISTRY"

PYTHONPATH=src python3 tools/inspect_registry.py \
  --rpc-url "$RPC_B" --contract-address "$REGISTRY"
```

同时核对部署交易 receipt：

```bash
cast receipt "$DEPLOY_TX_HASH" --rpc-url "$RPC_A"
cast keccak "$(cast code "$REGISTRY" --rpc-url "$RPC_A")"
cast keccak "$(cast code "$REGISTRY" --rpc-url "$RPC_B")"
```

### 预期结果

- RPC A、RPC B 和部署 receipt 的 chain ID 一致；
- receipt 的 `contractAddress` 与配置一致；
- 两个 RPC 返回非空且完全相同的 runtime code；
- 两个 code hash 完全一致；
- `.env.production` 固定该 chain ID、地址和 code hash；
- 服务 `/readyz` 返回的 code hash 与记录一致。

任何不一致均为 No-Go，不能通过“选择看起来正确的一个 RPC”继续上线。

## 8. 阶段四：确认递归链路和终止边界

生产拓扑必须形成可审计的逐跳表：

| Hop | Resolver ID | Endpoint | Agent URL | 下一跳 | 类型 |
|---|---|---|---|---|---|
| R1 | `operator-a/r1` | `10.30.0.53:53/udp` | `https://agent-r1...` | R2 | recursive |
| R2 | `operator-b/r2` | `10.30.1.53:53/udp` | `https://agent-r2...` | T1 | recursive |
| T1 | 适用时登记 | `10.30.2.53:53/udp` | 无 | 无 | terminal |

逐项确认：

1. Wrapper 配置的第一跳与 R1 identity object endpoint 完全一致；
2. R1 identity object 绑定 R1 Agent 公钥；
3. R1 Agent 只声明实际可观测的 R2；
4. R2 是 recursive 时必须提供 R2 Agent URL；
5. 只有经过审批的端点可以写入 `TERMINAL_UPSTREAMS`；
6. recursive hop 和 terminal endpoint 不能重叠；
7. 端口、传输类型、SNI 和 ALPN 均属于 endpoint identity，不能只比较 IP。

### 异常表现

- 缺少 Agent：Wrapper 返回 `SERVFAIL`；
- 隐藏中间 resolver：系统无法凭空发现，属于拓扑可信边界；
- Agent 报告与 identity object 不一致：返回 `SERVFAIL`；
- config version 回滚：返回 `SERVFAIL`；
- 合法配置升级：切换窗口可能短暂 `SERVFAIL`，随后自动恢复，不能释放未验证答案。

## 9. 阶段五：Agent TLS/mTLS

### 证书模型

- 每个远程 Agent 前部署反向代理或 service mesh sidecar 终止 TLS；
- 服务端证书 SAN 必须覆盖实际 Agent DNS 名；
- Wrapper/R1 Agent 使用独立客户端证书；
- 服务端要求并验证客户端证书；
- 客户端固定企业 CA 或专用 CA；
- 私钥权限 `0600`，证书轮换应有重叠有效期；
- 禁止关闭证书校验或使用 `verify=false`。

当前应用提供客户端 CA 和 mTLS client cert/key 参数；远程 Agent 的服务端 TLS 应由反向代理或 service mesh 提供。

模拟配置：

```dotenv
RESOLVER_IDENTITY_AGENT_BASE_URLS=10.30.0.53:53:udp=https://agent-r1.prod.example.com:8443
RESOLVER_IDENTITY_AGENT_PLAINTEXT_HOSTS=agent-r1
RESOLVER_IDENTITY_AGENT_TLS_CA_FILE=/run/tls/ca.pem
RESOLVER_IDENTITY_AGENT_TLS_CLIENT_CERT_FILE=/run/tls/wrapper-client.crt
RESOLVER_IDENTITY_AGENT_TLS_CLIENT_KEY_FILE=/run/tls/wrapper-client.key
```

`agent-r1` 只能用于同一 Docker control network 的明文连接。任何跨主机或跨运营方连接必须使用 HTTPS。

### 验收场景

| 场景 | 预期 |
|---|---|
| 正确 CA、SAN、客户端证书 | 请求成功 |
| 未受信 CA | TLS 握手失败，DNS `SERVFAIL` |
| SAN 不匹配 | TLS 握手失败，DNS `SERVFAIL` |
| 客户端证书缺失/过期 | Agent 拒绝连接，DNS `SERVFAIL` |
| 将远程 Agent 改为 HTTP | 生产配置校验拒绝启动 |

## 10. 阶段六：主机防火墙和日志控制

### 目标策略

| 流量 | 策略 |
|---|---|
| 管理网到 SSH | 仅批准 CIDR |
| DNS 客户端到 UDP/TCP 53 | 仅服务网段 |
| 公网到 Admin 8002 | 拒绝 |
| 公网到 Metrics 9108 | 拒绝 |
| 主机到 RPC | 仅批准的 HTTPS RPC |
| Wrapper/Agent 到远程 Agent | 仅批准的 HTTPS 地址 |
| Resolver DNS egress | 仅批准的上游 IP/端口 |

真实变更前先导出当前规则并准备自动回滚任务：

```bash
sudo nft list ruleset > "/root/nftables-before-$(date -u +%Y%m%dT%H%M%SZ).conf"
sudo nft --check --file /etc/nftables.d/resolver-identity.nft
```

不要直接复制一份 `policy drop` 示例覆盖整机规则。规则必须与现有 SSH、容器 `DOCKER-USER` 链、监控、时间同步、DNS 和主机管理策略合并，并由第二个已登录管理会话验证，防止锁死远程管理。

### 日志要求

- Docker 日志使用 `journald` 或受限的 `json-file` rotation；
- Fluent Bit/Vector 将服务日志发送到 Loki/SIEM；
- Admin、Watcher、容器重启和 TLS 拒绝事件至少保留 90 天；
- DNS 查询日志按隐私政策采样或关闭，不默认持久化完整域名；
- 禁止记录 admin token、私钥、证书私钥和完整环境变量；
- 日志平台按最小权限授权并记录查询审计。

## 11. 阶段七：监控和告警

### 数据源

- Wrapper `http://127.0.0.1:9108/metrics`；
- Wrapper `/readyz`；
- Indexer、Agent、Admin `/readyz`；
- Docker EventWatcher health；
- node_exporter 的磁盘、内存、CPU、文件系统 inode；
- cAdvisor 或 Docker exporter 的重启和资源指标；
- EVM RPC synthetic probe；
- TLS 证书剩余有效期探针。

### 最低告警集

| 告警 | 建议条件 | 等级 |
|---|---|---|
| WrapperDown | `resolver_identity_up` 缺失 2 分钟 | Critical |
| ReadinessFailed | `/readyz` 连续失败 3 次 | Critical |
| WatcherStale | EventWatcher unhealthy 或心跳超过 15 秒 | Critical |
| DNSRejectSpike | 5 分钟 `SERVFAIL` 比例超过基线/阈值 | High |
| GateLatencyHigh | 5 分钟平均 gate latency 超预算 | High |
| DiskWarning | 数据卷可用空间低于 20% | Warning |
| DiskCritical | 数据卷可用空间低于 10% | Critical |
| ContainerRestartLoop | 15 分钟重启 3 次以上 | High |
| RPCErrors | 双 RPC probe 失败或 chain ID 不一致 | Critical |
| CertificateExpiry | 证书 30 天内过期 | Warning |
| CertificateExpiryCritical | 证书 7 天内过期 | Critical |

当前 Wrapper 指标能计算总查询、ALLOW/SERVFAIL、验证结果和平均 gate latency。严格 P95/P99 需要外部探针直方图或后续将应用 summary 改为 histogram，不能把平均值标成 P95。

### 告警验收

在预生产逐个触发：停止 Wrapper、停止 Agent、阻断 RPC、停止 Watcher、填充测试磁盘、使用临近过期测试证书。每条告警必须验证：

- 在规定时间内触发；
- 路由到真实 on-call；
- 包含环境、服务、主机和 runbook 链接；
- 恢复后自动关闭；
- 没有把 token 或私钥写入通知。

## 12. 阶段八：数据库备份和恢复演练

### 在线备份

```bash
sudo install -d -m 700 -o 10001 -g 10001 "$PWD/backups"
BACKUP="resolver_identity-$(date -u +%Y%m%dT%H%M%SZ).db"

docker run --rm \
  -v fanxiangdiguijiexi_resolver-data:/data \
  -v "$PWD/backups:/backup" \
  resolver-identity-prototype:0.1.0-production \
  tools/db_admin.py --db /data/resolver_identity.db \
  backup --output "/backup/$BACKUP"

docker run --rm \
  -v "$PWD/backups:/backup:ro" \
  resolver-identity-prototype:0.1.0-production \
  tools/db_admin.py --db "/backup/$BACKUP" verify
```

预期输出：`integrity=ok`、`schema_version=1`、`journal_mode=delete`、非空 SHA-256。

### 恢复演练

恢复演练应在隔离的临时 volume 和隔离网络完成，不能覆盖唯一生产数据库：

1. 记录备份 SHA-256 和开始时间；
2. 创建空白临时 volume；
3. 以 UID/GID `10001` 将备份恢复为 `resolver_identity.db`；
4. 使用与备份匹配的镜像执行 `db_admin.py verify`；
5. 在隔离 Compose project 中启动 Indexer 和 Watcher；
6. 核对 resolver object、proof、runtime state 和 watcher cursor；
7. 启动 Agent/Wrapper，执行正向 DNS 查询；
8. 执行一个未知 resolver 负向查询，确认 `SERVFAIL`；
9. 记录 RTO、备份时间与故障点之间的 RPO；
10. 删除临时环境，不修改生产 volume。

### 通过条件

- SHA-256 与备份记录一致；
- 完整性和 schema 校验通过；
- RTO/RPO 不超过业务目标；
- 恢复环境不会接受已撤销 resolver/root；
- issuer、Agent 和 Web3 私钥通过独立密钥备份恢复，不依赖数据库。

## 13. 阶段九：容量测试

容量测试只能在与生产规格一致的预生产环境进行，不能直接对生产 DNS 发起极限压测。

### 13.1 测试预算示例

真实值必须由业务方批准：

| 指标 | 示例预算 |
|---|---:|
| 预期峰值 | 1,000 QPS |
| 目标验证 | 1,500 QPS，持续 30 分钟 |
| 突发 | 2,000 QPS，持续 5 分钟 |
| P95 gate latency | 小于 200 ms |
| P99 gate latency | 小于 500 ms |
| 允许异常率 | 小于 0.1% |
| CPU | 持续低于 70% |
| 数据卷 | 测试期间无异常增长 |
| 最大递归 Agent 深度 | 业务批准值，例如 4 |

### 13.2 负载模型

使用 DNS-OARC 维护的成熟 DNS 压测工具 [`dnsperf`](https://www.dns-oarc.net/tools/dnsperf)，准备包含真实分布但已脱敏的查询集，并在测试机上先用 `dnsperf -h` 核对已安装版本的 transport 参数：

```bash
dnsperf -s "$STAGING_DNS_IP" -p 53 \
  -d queries.txt -Q 250 -l 300 -m udp

dnsperf -s "$STAGING_DNS_IP" -p 53 \
  -d queries.txt -Q 1000 -l 1800 -m udp

dnsperf -s "$STAGING_DNS_IP" -p 53 \
  -d queries.txt -Q 200 -l 300 -m tcp
```

按 cold cache、hot cache、10% cache miss、Agent 深度 1/2/最大值、单 RPC 故障、Agent 延迟和证书轮换分别测试。每个场景单独记录，不能只报告最高 QPS。

### 13.3 观测指标

- `resolver_identity_dns_queries_total` 按 decision；
- `resolver_identity_verifications_total` 按 accepted/cache；
- gate latency；
- DNS 客户端 P50/P95/P99；
- UDP timeout、TCP error、SERVFAIL；
- Wrapper/Agent CPU、RSS、线程、文件描述符；
- SQLite busy/lock、volume 增长；
- RPC latency/error；
- Agent 链深度和每跳 latency。

### 13.4 失败判定

- 任一未验证原始答案被释放；
- 错误率、P95/P99 或资源使用超过批准预算；
- 负载停止后内存不能回落；
- SQLite 持续锁等待或磁盘增长不可控；
- Agent/RPC 故障导致进程崩溃，而不是稳定 `SERVFAIL`；
- 最大链深度下无法在 verification deadline 内完成。

失败后先保存原始数据、火焰图/CPU profile、容器指标和日志，再定位瓶颈；不能仅提高 deadline 或 TTL 掩盖问题。优化后必须使用相同模型重新测量并记录前后差异。

## 14. 上线验收场景矩阵

| 场景 | DNS 表现 | 服务状态 | 操作结论 |
|---|---|---|---|
| 全部正常 | UDP/TCP 返回原始正确答案 | 全部 ready | 可灰度 |
| 未登记 R1/R2 | `SERVFAIL`，无原始答案 | 服务可保持 ready | 安全拒绝 |
| Agent 签名错误 | `SERVFAIL` | Agent 可能仍 health | 调查密钥/对象绑定 |
| Agent 不可用 | `SERVFAIL` | Wrapper 存活，相关 ready 失败 | 恢复 Agent |
| 单 RPC 不可用 | hot cache 可工作至 hard TTL | 告警 | 修复 RPC，不放宽 TTL |
| 双 RPC/Registry 不可用 | cold path `SERVFAIL` | ready 失败 | 停止放量 |
| Resolver revoked | `SERVFAIL` | Watcher 同步后缓存失效 | 符合预期 |
| Root revoked | `SERVFAIL` | Watcher 同步后缓存失效 | 符合预期 |
| Watcher 心跳过期 | 不应继续视为 ready | EventWatcher unhealthy | 停止放量 |
| mTLS 证书过期 | `SERVFAIL` | Agent 链不可用 | 证书轮换 |
| Registry code hash 改变 | 服务拒绝 ready/启动 | critical alert | 安全事件，禁止绕过 |
| 数据盘低于 20% | 功能可能正常 | Warning | 扩容/清理 |
| 数据盘低于 10% | 有写入失败风险 | Critical | 停止变更并扩容 |
| DB 完整性失败 | 不可信 | 服务停止 | 从已验证备份恢复 |
| 配置版本回滚 | `SERVFAIL` | fail-closed | 发布更高版本，禁止降级 |

## 15. 灰度与回滚

### 灰度顺序

1. 运维探针流量；
2. 1% 内部客户端；
3. 10% 低风险客户端；
4. 50%；
5. 100%。

每阶段至少观察一个完整告警窗口，并检查 DNS 成功率、SERVFAIL、latency、RPC、Agent、Watcher、磁盘和重启次数。

### 应用回滚

- 将 DNS 流量切回旧路径；
- 使用上一不可变镜像 digest；
- schema 不兼容时停止全部 writer，再恢复匹配备份；
- 不降低 resolver object version 或 Agent config version。

### Registry 回滚

链上合约不能像容器一样原地回滚。若合约身份需要替换：

1. 停止 Admin 写入和新流量；
2. 部署新合约；
3. 独立核验新地址/code hash；
4. 更新 pinned trust anchor；
5. 重新发布必要 identity；
6. 完整验收后切换。

已撤销 root/resolver 在当前合约中不能复活，应发布新的 root 或新的 resolver identity/version。

## 16. Go/No-Go 决策

只有以下项目全部有真实证据时才允许 Go：

- [ ] 镜像 digest、Git commit、SBOM 和依赖审计已归档；
- [ ] 合约部署 receipt 已最终确认；
- [ ] 两个独立 RPC 的 chain ID、地址和 code hash 一致；
- [ ] 角色矩阵符合审批，最后管理员仍存在；
- [ ] 所有 recursive hop/terminal boundary 已签字确认；
- [ ] mTLS 正向和错误证书场景已验证；
- [ ] 防火墙未暴露 Admin/Metrics，SSH 回滚通道有效；
- [ ] 监控和告警已真实触发并送达 on-call；
- [ ] 在线备份与隔离恢复演练通过；
- [ ] 峰值、突发、最大链深度容量测试通过；
- [ ] UDP/TCP 正向及全部负向场景通过；
- [ ] 未发现原始 DNS 答案绕过验证门；
- [ ] 回滚负责人、命令和旧路径均已确认。

任一项缺失即为 No-Go。不能用本文的模拟结果勾选真实生产 readiness checklist。

## 17. 真实执行记录模板

```text
变更编号：
环境：
执行日期：
执行人：
审批人：
Git commit：
镜像 digest：
合约地址：
部署交易：
Chain ID：
Runtime code hash：
RPC A 核验人/结果：
RPC B 核验人/结果：
角色矩阵证据：
拓扑审批附件：
TLS 证书序列号/到期日：
防火墙变更单：
告警触发记录：
备份 SHA-256：
恢复 RTO/RPO：
容量测试报告：
正向验收：
负向验收：
遗留风险：
Go/No-Go：
回滚是否执行：
最终结论：
```

## 18. 本次模拟结论

本仓库已经提供严格生产模式、不可变镜像、链上身份固定、fail-closed 验证、Watcher 健康检查、在线备份工具和本地安全/E2E 测试。

模拟分析表明，真实上线的主要外部工作是：

1. 使用治理多签和独立应急账户建立真实角色矩阵；
2. 从两个独立 RPC 固定 Registry 身份；
3. 由网络负责人签字确认逐跳拓扑和 terminal boundary；
4. 为跨主机 Agent 部署 mTLS 终止层；
5. 将主机、容器、应用、RPC、证书和磁盘接入统一告警；
6. 用隔离 volume 完成恢复演练；
7. 在生产等规格预生产环境完成容量预算验证。

当前版本若要求 Publisher 与 Endpoint Manager 严格使用不同私钥，还需要先完成分角色签名工作流改造。除此之外，本文所列步骤均可作为真实变更窗口的执行框架，但每一步必须由真实输出替换示例和模拟描述。
