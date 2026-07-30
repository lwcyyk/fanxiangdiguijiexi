# 反向递归解析器身份认证系统

## 域名中心星型多服务器完整部署方案

| 项目 | 内容 |
| --- | --- |
| 文档类型 | 现场实施与验收版 |
| 目标环境 | 域名中心星型网络 / 公共 EVM 测试网预发布 |
| 数据面 | Rust V2 |
| Registry | `ResolverIdentityRegistryV1` |
| 仓库 | `github.com/lwcyyk/fanxiangdiguijiexi` |
| 基准 | 使用批准的 40 位 commit；当前本地 `main` 跟踪 `origin/master` |
| 编制日期 | 2026-07-30 |
| 规格 | `specs/domain-center-star-deployment/` |

## 文档定位

当前仓库适合采用“中心 Hub + 多条相互隔离的完整链路单元”部署。每个入口链路
单元独立运行 Wrapper、Agent、Trace Adapter、Registry Sync 和 SQLite。当前版本
不支持共享 SQLite、多主机同写或把一个数据单元随意拆分到多台服务器。需要高可用
时，复制完整单元并在前端通过 DNS VIP 或四层负载均衡切换。

实施顺序固定为：

```text
先中心，后链路
  -> 先 L01，后 L02/L03
  -> 先 Registry Sync，后 Agent/Trace，再 Wrapper
  -> 先 Shadow，后容量和故障测试
  -> 最后按比例切流
```

真实部署必须使用现场 IP、证书、identity、EVM 固定值和 Resolver 内部 Trace。
示例文件、模拟日志和本地 Mock 只能验证工程流程，不能作为上线证据。

# 第 1 章 部署目标、现状与安全边界

## 1.1 部署目标

Wrapper 接收 DNS 请求并暂存 R1 返回的原始响应。R1 的内部 Trace 提供本次解析
实际发生的缓存命中和上游访问；Agent 构造并验证 `QueryEvidenceGraphV2`；
Registry Sync 从 finalized 链状态同步 identity、Root、Endpoint 和撤销状态；
Wrapper 对本地 Registry 快照二次核验。全部条件通过才释放原始响应，否则返回
`SERVFAIL`。

Hub 只负责治理、制品和运维，不转发客户端 DNS。各链路独立认证，避免一个链路的
故障、密钥泄漏或 SQLite 问题扩散。

## 1.2 仓库已有能力

| 能力 | 实现 |
| --- | --- |
| Rust Wrapper | UDP/TCP 入口、响应暂存、上下文登记、Agent 和 Registry 双重复验 |
| Rust Agent | 真实 Trace 证据图、相邻 Agent 响应证明、递归子图合并 |
| Trace Adapter | Unix Socket、生产者 UID、SQLite spool、mTLS 续传、dead-letter |
| Registry Sync | finalized 读取、链固定、回退/同高度哈希检测、SQLite 原子快照 |
| Solidity Registry | Root、Resolver anchor、Endpoint、撤销、五类角色 |
| 中心管理工具 | identity 签名、计划生成、五阶段发布、撤销 |
| 单链路 Compose | 非 root、只读文件系统、能力删除、资源限制、日志轮转 |
| 现场清单工具 | 多链路校验、秘密隔离、运行包生成、哈希清单 |

链路服务器只运行 Rust 服务。`tools/manage_field_deployment.py` 和
`tools/manage_v2_registry.py` 只在中心管理机低频运行，不进入 DNS 查询路径。

## 1.3 硬边界

以下情况立即阻断上线：

- chain ID、合约地址或 runtime code hash 是示例、零值或未经双 RPC 核验；
- identity 为空、未签名或 `server_id/key_id` 与运行配置不一致；
- Trace 只能按 pcap、qname、“最近请求”或宽松时间窗口猜测；
- L01/L02/L03 复用 Agent 私钥、TLS 私钥、Wrapper Token 或 Trace Token；
- 一个 SQLite volume 被两台主机共享；
- Wrapper、Agent、Trace Adapter 或 Registry Sync readiness 失败；
- 负向测试仍释放原始 DNS 响应；
- 没有已演练的原 DNS 入口和切回权限。

公共互联网使用 `public-hybrid`。只有 Root、TLD、Authority、Recursive 和
Forwarder 全部受控并部署 Agent 时，才使用 `controlled-strict`。公共 Anycast
identity 证明服务边界，不证明某个物理服务器。

## 1.4 实施里程碑

| 里程碑 | 完成标准 |
| --- | --- |
| M1 | 公共 EVM 测试网 Registry、五类角色、Root/identity/Endpoint 发布完成 |
| M2 | Hub 镜像、制品、只读 RPC、监控、日志和备份完成 |
| M3 | L01 安装、Registry Sync 和 SQLite 核验完成 |
| M4 | L01 真实 Resolver Trace 和完整 Shadow 验收完成 |
| M5 | L02/L03 独立复制和跨链路拒绝完成 |
| M6 | 容量、备份恢复、逐步切流和回滚完成 |
| M7 | 每条链路 A/B 完整单元完成 |

# 第 2 章 星型架构与服务器规划

## 2.1 总体拓扑

```text
                         ri-hub-mgmt-01
             Governance / Registry / Identity / Artifact
                              |
                         ri-hub-ops-01
              Prometheus / Alert / Log / Backup / Audit
                     /            |            \
              management     management     management
                   |              |              |
             L01 complete    L02 complete    L03 complete
                 unit            unit            unit
                   X--------------X--------------X
                     cross-link communication denied

client -> DNS VIP -> Wrapper -> R1 -> actual DNS chain
                         |
                      Agent <- Trace Adapter <- R1 internal Trace
                         |
                      SQLite <- Registry Sync <- HTTPS read-only RPC
```

Hub 是治理和运维中心，不是查询转发中心。各链路只通过受控管理通道连接 Hub。

## 2.2 主机规模

预发布至少 6 台：

| 主机 | 区域 | 职责 |
| --- | --- | --- |
| `ri-hub-mgmt-01` | 中心管理 | 构建、镜像、签名、Registry、发布计划 |
| `ri-hub-ops-01` | 中心运维 | Prometheus、告警、日志、备份、审计 |
| `ri-l01-r1-01` | L01 | R1 和完整入口单元 |
| `ri-l02-r1-01` | L02 | R1 和完整入口单元 |
| `ri-l03-r1-01` | L03 | R1 和完整入口单元 |
| `ri-test-client-01` | 测试 | Shadow、负向、容量、故障测试 |

接近正式生产时，每条链路准备 A/B 两个完整单元：

```text
client -> DNS VIP/L4 LB -> L01-A Wrapper -> R1-A + independent state
                       \-> L01-B Wrapper -> R1-B + independent state
```

A/B 不共享 SQLite、Trace spool、Agent 密钥、证书或 Token。

## 2.3 网络区域

| 区域 | 流量 | 端口 |
| --- | --- | --- |
| DNS 服务网 | Client→Wrapper、Wrapper→R1、同链 R1→R2 | UDP/TCP 53 |
| 管理网 | Agent、metrics、SSH、运维 | TCP 8443、9108-9110、22 |
| 外联区 | Registry Sync、镜像、日志 | TCP 443/6514 |
| 治理隔离区 | 多签、Publisher、Revoker、issuer | 链路服务器不可访问写入口 |

## 2.4 命名

```text
Compose project: ri-l01-r1
unit_id:         L01-r1-a
server_id:       operator/L01/r1
Trace Socket:    /run/resolver-identity/L01-r1
```

同机多 unit 时，必须分别设置 Compose project、Agent/metrics/DNS 端口和 Socket。
现场更建议一台主机只承载一个主要入口单元。

## 2.5 DNS 地址

| 链路 | Wrapper IP/VIP | R1 后端 | 管理网 |
| --- | --- | --- | --- |
| L01 | 现场分配 | 现场分配 | 现场分配 |
| L02 | 现场分配 | 现场分配 | 现场分配 |
| L03 | 现场分配 | 现场分配 | 现场分配 |

Wrapper 和 R1 不能同时监听同一 IP 的 UDP/TCP 53。
`RI_WRAPPER_UPSTREAMS` 必须指向 R1，不能指回 Wrapper。Shadow 使用单独 IP 或
1053。

# 第 3 章 上线前准备、证书与制品

## 3.1 必须收集

| 类别 | 真实数据 |
| --- | --- |
| 发布 | Git commit、版本、镜像 digest、变更单 |
| 链路 | link/unit、R1/R2 软件、监听、转发、终止边界 |
| EVM | 两个 HTTPS RPC、chain、Registry、runtime code hash、finality |
| identity | server/operator/role、Endpoint、Agent URL/公钥、有效期 |
| 网络 | Wrapper、R1/R2、管理网、监控、日志、堡垒机、防火墙 |
| 恢复 | 原 DNS 入口、切回权限、批准 RTO |

## 3.2 工具

链路服务器：

```bash
docker version
docker compose version
curl --version
dig -v
openssl version
sqlite3 --version
timedatectl status
df -h
```

还需要 `jq`、`sha256sum`、`rsync`、`nc`；容量主机安装 `dnsperf`。中心管理机另需
Python 3.10+ 和 Foundry。链路服务器不安装 Foundry，不保存 Registry 写私钥。

## 3.3 构建和固定镜像

```bash
git clone https://github.com/lwcyyk/fanxiangdiguijiexi.git
cd fanxiangdiguijiexi
git checkout <APPROVED_40_HEX_COMMIT>
git status --short

export IMAGE=registry.dns-center.local/resolver-identity-rust:<RELEASE>
docker build --pull -f docker/Dockerfile.rust -t "${IMAGE}" .
docker push "${IMAGE}"
docker image inspect "${IMAGE}" --format '{{index .RepoDigests 0}}'
```

把返回的 `name@sha256:...` 写入私有现场清单。禁止 `latest`。

## 3.4 每个 unit 的私有材料

清单中的 `private_material_dir` 必须具有：

```text
secrets/
├── agent_private_key
├── trace_ingest_token
├── agent_wrapper_token
└── agent_peer_token
tls/
├── agent.crt
├── agent.key
├── client-ca.crt
├── wrapper-client.crt
├── wrapper-client.key
├── trace-client.crt
├── trace-client.key
├── agent-client.crt
├── agent-client.key
└── agent-ca.crt
```

私钥和 Token 权限为 `0600` 或更严，运行包生成后为 `0400`。三种 Token 即使在同
unit 也不能相同。Peer Token 只允许同 link 的相邻 Agent 共用。L01/L02/L03 的
私钥、Wrapper Token 和 Trace Token不得复用。

Prometheus 访问 Agent `/metrics` 应另外签发每条链路独立的监控客户端证书，不复用
运行时 `agent-client.key`。

## 3.5 私有现场清单

```bash
install -d -m 0700 /secure/field
cp specs/domain-center-star-deployment/site-inventory.example.json \
  /secure/field/site-inventory.json
chmod 0600 /secure/field/site-inventory.json
```

填写真实值后执行：

```bash
python3 tools/manage_field_deployment.py validate \
  --inventory /secure/field/site-inventory.json
```

正式校验会拒绝 Mainnet、占位值、零地址、文档 IP、移动镜像标签、回路、端口冲突、
identity 不匹配、秘密权限过宽和跨链路复用。

## 3.6 停止条件

- 任何 EVM 固定值仍为空或为示例；
- identity/issuer 文件不是真实批准制品；
- 没有 Resolver 内部 Trace；
- 证书、私钥或 Token 未隔离；
- 回滚入口没有实际演练；
- 监控、日志、磁盘和备份没有负责人。

# 第 4 章 Hub、Registry 与身份发布

## 4.1 Hub 职责

| 功能 | 职责 |
| --- | --- |
| 治理 | Registry、Governance、角色授权 |
| identity | 参数收集、离线签名、Root 和发布计划 |
| 制品 | 测试、镜像 digest、每 unit 运行包、SHA-256 |
| RPC | 只读 HTTPS、请求限制、访问审计 |
| 运维 | Prometheus、Alertmanager、日志、备份、变更和应急 |

## 4.2 Sepolia Registry 闭环

使用已实现的规格驱动脚本，不用临时手工命令绕过角色和证据日志：

```bash
scripts/sepolia/00-preflight.sh
scripts/sepolia/01-test.sh
scripts/sepolia/02-deploy-registry.sh
scripts/sepolia/03-configure-roles.sh
scripts/sepolia/04-verify-deployment.sh
scripts/sepolia/05-sign-identities.sh
scripts/sepolia/06-prepare-publication-plan.sh
scripts/sepolia/07-publish-registry-plan.sh
scripts/sepolia/08-sync-runtime-config.sh
scripts/sepolia/09-run-registry-sync.sh
scripts/sepolia/10-acceptance-test.sh
```

`initialAdmin` 必须是 Governance，不是链路服务器或临时个人地址。

## 4.3 五类角色

| 角色 | 持有者 |
| --- | --- |
| `DEFAULT_ADMIN_ROLE` | Governance 多签 |
| `ROOT_PUBLISHER_ROLE` | Root Publisher |
| `RESOLVER_PUBLISHER_ROLE` | Resolver Publisher |
| `ENDPOINT_MANAGER_ROLE` | Endpoint Manager |
| `REVOKER_ROLE` | 独立 Revoker |

Governance 只保留 Admin；四个业务角色授予四个独立账户后，从 Governance 撤销。
Deployer 不保留业务角色。使用第二 RPC 调用 `hasRole` 并保存全部交易哈希。

## 4.4 双 RPC 核验

```bash
cast chain-id --rpc-url "${PRIMARY_RPC}"
cast chain-id --rpc-url "${VERIFY_RPC}"

PRIMARY_CODE="$(cast code "${REGISTRY_ADDRESS}" \
  --rpc-url "${PRIMARY_RPC}" --block finalized)"
VERIFY_CODE="$(cast code "${REGISTRY_ADDRESS}" \
  --rpc-url "${VERIFY_RPC}" --block finalized)"

test "${PRIMARY_CODE}" = "${VERIFY_CODE}"
cast keccak "${PRIMARY_CODE}"
cast keccak "${VERIFY_CODE}"
```

chain ID、runtime bytecode、code hash 和 finalized block/hash 均一致才继续。

## 4.5 identity 和发布计划

Recursive/Forwarder 必须有 Ed25519 Agent，`service_url` 必须为 HTTPS 并与证书
SAN、管理 DNS 和防火墙一致。

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py sign \
  --input deployments/sepolia/identities-v2.unsigned.json \
  --private-key-file "${ISSUER_PRIVATE_KEY_FILE}" \
  --output deployments/sepolia/identities-v2.json

PYTHONPATH=src python3 tools/manage_v2_registry.py prepare \
  --identities deployments/sepolia/identities-v2.json \
  --issuer-keys deployments/sepolia/issuer-keys.json \
  --root-version 1 \
  --chain-id "${CHAIN_ID}" \
  --contract-address "${REGISTRY_ADDRESS}" \
  --contract-code-hash "${REGISTRY_CODE_HASH}" \
  --output deployments/sepolia/registry-plan-v2.json
```

计划生成后不得手改。五阶段使用同一 plan hash：

```text
publish-root
publish-resolvers
unbind-endpoints
bind-endpoints
revoke-removed
```

## 4.6 Hub 监控

使用：

```text
deploy/field/prometheus/prometheus.yml.example
deploy/field/prometheus/resolver-identity-alerts.yml
deploy/field/docker/daemon-logging.example.json
```

替换模板值并为每条链路建立独立 Agent mTLS scrape job。接入 node exporter 或现场
等效主机监控，至少覆盖磁盘、inode、文件描述符、时间同步和容器重启。

# 第 5 章 单链路部署

## 5.1 生成运行包

中心管理机在干净的批准 commit 上执行：

```bash
scripts/field/00-preflight.sh /secure/field/site-inventory.json

scripts/field/01-render-bundles.sh \
  /secure/field/site-inventory.json \
  deployments/field/private

export RELEASE_ROOT="$PWD/deployments/field/private/<SITE>/<COMMIT12>"
scripts/field/02-verify-bundles.sh "${RELEASE_ROOT}"
```

每个 unit 得到独立 `.env`、identity、issuer keys、secret、TLS、Compose、脚本、
metadata 和 `SHA256SUMS`。RPC 完整 URL只在私有 `.env` 中；metadata 只记录主机名。

## 5.2 受控传输

从 Hub 到目标主机只走批准的 SSH/制品通道，并启用主机密钥校验：

```bash
export UNIT=L01-r1-a
export TARGET=ri-deploy@ri-l01-r1-01
export STAGE=/var/tmp/ri-field-${UNIT}

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "${TARGET}" \
  "install -d -m 0700 '${STAGE}'"
rsync -a --checksum --protect-args \
  -e 'ssh -o BatchMode=yes -o StrictHostKeyChecking=yes' \
  "${RELEASE_ROOT}/${UNIT}/" "${TARGET}:${STAGE}/"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "${TARGET}" \
  "cd '${STAGE}' && sha256sum --check metadata/SHA256SUMS"
```

禁止通过聊天软件传输秘密。

## 5.3 安装

目标主机先拉取固定镜像，再执行自包含安装脚本：

```bash
cd "${STAGE}"
set -a
. deploy/link/.env
set +a
docker pull "${RI_IMAGE}"

sudo scripts/03-install-link.sh "${STAGE}"
```

安装路径：

```text
/opt/resolver-identity/units/<unit>/releases/<commit>
/opt/resolver-identity/units/<unit>/current
```

脚本固定 `.env`、identity、secret 和 TLS 权限，不删除已有 release。

## 5.4 分阶段启动

```bash
export CURRENT=/opt/resolver-identity/units/L01-r1-a/current

sudo "${CURRENT}/scripts/04-start-link.sh" "${CURRENT}" registry-sync
sudo "${CURRENT}/scripts/04-start-link.sh" "${CURRENT}" control
```

此时启动或恢复真实 Resolver Trace 插件，确认：

```bash
test -S /run/resolver-identity/L01-r1/events.sock
curl --fail http://<L01_MANAGEMENT_IP>:9110/readyz
```

入口 unit 最后启动 Wrapper：

```bash
sudo "${CURRENT}/scripts/04-start-link.sh" "${CURRENT}" wrapper
```

`upstream` unit 的脚本会拒绝启动 Wrapper。Compose 的 `depends_on` 只表示进程启动，
不能替代本顺序。

## 5.5 基线验收

```bash
sudo "${CURRENT}/scripts/05-acceptance-test.sh" "${CURRENT}"
sudo "${CURRENT}/scripts/10-collect-evidence.sh" \
  "${CURRENT}" /secure/evidence/L01
```

脚本检查 Registry/Trace/Agent/Wrapper readiness、两个 SQLite
`integrity_check`、Registry 快照、dead-letter 和 UDP/TCP Shadow。

## 5.6 单链路防火墙

| 源 | 目的 | 端口 |
| --- | --- | --- |
| Client/VIP | Wrapper | UDP/TCP 53 |
| Wrapper | 本链 R1 | UDP/TCP 53 |
| Registry Sync | 只读 RPC | TCP 443 |
| Prometheus | 9108/9109/9110 | TCP，仅管理网 |
| Prometheus | Agent 8443 | TCP，专用 mTLS |
| Bastion | 链路主机 | TCP 22 |
| 链路主机 | 日志平台 | TCP 443/6514，单向 TLS |

# 第 6 章 R1→R2 与 Resolver Trace

## 6.1 R1 直接迭代

R1 内部 Trace 记录实际访问的 Root、TLD 和 Authority Endpoint、请求/响应摘要与
DNSSEC 状态。公共上游没有本方 Agent 时使用 `public-hybrid`，不能虚构远程子图。

## 6.2 同链 R1→R2

| R1 主机 | R2 主机 |
| --- | --- |
| Wrapper、R1、Agent、Trace、Sync、SQLite | R2、Agent、Trace、Sync、SQLite |
| 启动 Wrapper | `role=upstream`，不启动 Wrapper |

只放通：

```text
R1 Resolver -> R2 Resolver UDP/TCP 53
R1 Agent    -> R2 Agent    TCP 8443 mTLS + same-link peer token
```

R2 `agent.service_url` 使用 R1 可解析的管理网名称，并与证书 SAN 匹配，不能使用
另一 Docker 网络中的 `https://agent:8443`。

## 6.3 TraceEventV2

最低要求：

- 同一内部解析上下文使用同一 `trace_id`；
- 当前上下文全部事件使用 Wrapper 对应的 `correlation_id`；
- 每次 outbound 根据实际下一跳报文生成 `target_correlation_id`；
- 记录实际目标 IP、port、UDP/TCP 和规范化 wire digest；
- 记录 final response、outbound query/response、cache hit；
- DNSSEC 状态来自验证型 Resolver；
- Endpoint 来自实际 socket 目的地址。

关联算法：

```text
correlation_id =
  SHA-256(
    "dns-correlation-v2:"
    + transaction_id_hex
    + ":"
    + dns_wire_digest
  )
```

`dns_wire_digest` 对 transaction ID 两字节清零后的 DNS wire 计算 SHA-256。

## 6.4 缓存命中

Cache hit 只能声明当前解析器本次实际发生的路径。事件引用当前 Registry 代际中的
source graph digest，并受 DNS TTL、identity 有效期和策略最大 TTL 限制。identity、
Root 或 Endpoint 变化会推进代际，旧缓存证明失效。

## 6.5 Trace P0 门禁

必须覆盖并发相同 qname、冷/热缓存、重试、transaction ID 回绕、迟到事件、Socket
背压和重启续传。如果只能用 pcap、普通 dnstap、qname 或时间窗口推测链路，不能
声明“全路径认证完成”。

# 第 7 章 Shadow、容量、切流与回滚

## 7.1 Shadow

客户端不改生产入口：

```bash
dig @<WRAPPER_IP> -p 1053 <APPROVED_TEST_FQDN> A
dig @<WRAPPER_IP> -p 1053 <APPROVED_TEST_FQDN> A +tcp
```

正向至少覆盖 UDP/TCP、冷/热缓存、R1→R2、服务重启和 SQLite reconcile。

负向至少覆盖 Trace 缺失、Agent 停止、错误证书/Token、篡改 identity、撤销、
Endpoint 解绑、错误 chain/address/hash、RPC staleness、环路、超深路径和 spool
满。预期都是不释放原始响应并返回 `SERVFAIL`。

## 7.2 跨链路隔离

分别从 L01、L02、L03 主机执行：

```bash
sudo "${CURRENT}/scripts/06-isolation-test.sh" \
  /secure/field/site-inventory.json L01
```

该脚本核验其他 link 的 Agent、metrics 和 Wrapper TCP 端口不可达。UDP 和防火墙
规则仍需使用现场防火墙日志、ACL 命中和抓包证据补充。

## 7.3 容量

准备经批准的 `dnsperf` 查询集，在 Shadow 端口执行：

```bash
sudo "${CURRENT}/scripts/09-capacity-test.sh" \
  "${CURRENT}" /secure/test/queries.txt <TARGET_QPS> <DURATION_SECONDS>
```

目标至少为预期峰值的 1.5 倍，覆盖 UDP/TCP 比例、最大包、EDNS、冷/热缓存、最大
链深和 R1→R2。同步记录 P50/P95/P99、SERVFAIL、CPU、内存、FD、WAL、spool、
磁盘，以及 RPC/Agent/R1 延迟与容器重启。

脚本默认拒绝对端口 53 压测；只有批准维护窗口显式设置
`RI_CAPACITY_ALLOW_PRODUCTION_PORT=true` 才允许。

## 7.4 切流

```text
1% -> 10% -> 50% -> 100%
```

每阶段的观察时间、SERVFAIL、P95/P99、staleness、spool、dead-letter、CPU、内存、
磁盘和重启阈值必须先写入变更单。

## 7.5 回滚

出现 readiness 非 2xx、非预期 SERVFAIL、spool 持续增长、dead-letter、链固定
不一致、P99 超限、资源接近上限或跨链路通信时：

1. VIP/LB 切回原解析器入口；
2. 确认 Wrapper 已无客户端流量；
3. 停止 Wrapper；
4. 保留 Agent、Sync、Trace 取证；
5. 保存日志、metrics、镜像 digest、evidence 和 spool；
6. 分析后再停止其他服务。

```bash
cd "${CURRENT}"
set -a; . deploy/link/.env; set +a
docker compose \
  --project-name "${RI_FIELD_COMPOSE_PROJECT}" \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml \
  stop wrapper
```

普通回滚不撤销 identity。只有身份或 Agent 私钥确认泄漏时，由 Revoker 永久撤销。

# 第 8 章 运维、备份、高可用与最终验收

## 8.1 监控

| 来源 | 指标 |
| --- | --- |
| Wrapper 9108 | query、accepted、SERVFAIL、overload、upstream/verification failure、inflight、ready |
| Registry 9109 | last success、finalized block/hash、record、failure、target |
| Trace 9110 | pending、dead-letter、ready |
| Agent 8443 | graph request/failure、Trace ingest，mTLS |
| 主机 | CPU、内存、磁盘、inode、FD、网络、时间、容器重启 |

告警规则模板中的 1% SERVFAIL 和 15 秒 staleness 是默认值，现场应与批准 SLO 和
每个 unit 的配置一致。

## 8.2 日常检查

```bash
sudo "${CURRENT}/scripts/10-collect-evidence.sh" \
  "${CURRENT}" /secure/evidence/daily

cd "${CURRENT}"
set -a; . deploy/link/.env; set +a
docker compose \
  --project-name "${RI_FIELD_COMPOSE_PROJECT}" \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml \
  logs --since 15m registry-sync agent trace-adapter wrapper
```

## 8.3 在线备份和恢复演练

备份到加密的异故障域：

```bash
sudo "${CURRENT}/scripts/07-backup-link.sh" \
  "${CURRENT}" /mnt/encrypted-ri-backup
```

脚本使用 SQLite online backup，保存 evidence、spool、私有运行配置、identity、
issuer 公钥、unit metadata 和 SHA-256。

恢复只在隔离目录演练：

```bash
sudo "${CURRENT}/scripts/08-restore-drill.sh" \
  /mnt/encrypted-ri-backup/<site>/<unit>/<timestamp> \
  /srv/ri-restore-drill
```

恢复先做哈希和 `PRAGMA integrity_check`。真正恢复服务时先启动 Registry Sync
reconcile，旧备份不能让已撤销 identity 重新生效。

生产服务器禁止：

```bash
docker compose down -v
```

## 8.4 升级和回退

1. 新 commit 完成全部测试并构建固定 digest；
2. L01 Shadow 安装新的不可变 release；
3. 按 Sync→Agent/Trace→Wrapper 启动；
4. 回归和容量通过后逐步切流；
5. 镜像回退切回旧 release symlink 和旧 digest，不删除数据库；
6. identity 或 Endpoint 变化时生成新发布计划并按五阶段上链。

## 8.5 高可用

| 方案 | 判断 |
| --- | --- |
| 完整单元 A/B + VIP/LB | 推荐 |
| 双活分流、独立缓存和 SQLite | 需验证缓存差异和容量 |
| NFS/共享卷 SQLite | 禁止 |
| 替换 ri-store/spool 为一致性存储 | 后续架构研发 |

## 8.6 最终验收

使用：

```text
specs/domain-center-star-deployment/acceptance-checklist.md
```

必须有以下证据：

- 镜像 digest、Git commit、EVM 双 RPC、角色和发布交易；
- 每 unit identity、Endpoint、finalized snapshot 和 SQLite；
- Trace 插件版本、关联 ID、并发/缓存/重试；
- UDP/TCP、正向、负向、撤销和失败关闭；
- 跨链路拒绝、防火墙和 Token/证书隔离；
- Prometheus、日志、磁盘、dead-letter 告警触发；
- 峰值容量、在线备份、异机恢复和 VIP 回滚 RTO；
- A/B 单元未共享 SQLite。

只有全部有真实现场证据时，才能声明“域名中心星型多链路部署完成”。如果 Trace
插件仍未接入，只能声明“Registry 与链上查询闭环完成”。

# 附录 A 防火墙矩阵

| 源 | 目的 | 协议/端口 | 策略 |
| --- | --- | --- | --- |
| 本链 Client/VIP | Wrapper | UDP/TCP 53 | 允许 |
| Wrapper | 本链 R1 | UDP/TCP 53 | 允许 |
| R1 Resolver | 同链 R2 | UDP/TCP 53 | 按拓扑允许 |
| Wrapper | 本机 Agent | TCP 8443 | mTLS + Wrapper Token |
| Trace Adapter | 本机 Agent | TCP 8443 | mTLS + Trace Token |
| R1 Agent | 同链 R2 Agent | TCP 8443 | mTLS + Peer Token |
| Registry Sync | 只读 RPC | TCP 443 | TLS |
| Prometheus | metrics | TCP 9108-9110 | 仅管理网 |
| Prometheus | Agent | TCP 8443 | 每链专用 mTLS |
| 日志代理 | Hub 日志 | TCP 443/6514 | 单向 TLS |
| Bastion | 链路主机 | TCP 22 | 限来源 |
| L01 | L02/L03 Resolver/Agent/SQLite | 任意 | 拒绝 |
| 公网 | Agent/metrics/Docker API | 任意 | 拒绝 |
| 链路服务器 | Registry 写入口/签名服务 | 任意 | 拒绝 |

# 附录 B 常用工程验证

```bash
cd rust
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd ..

python3 -m pytest -q
python3 -m ruff check .

cd contracts
forge fmt --check
forge build
forge test -vvv
cd ..

docker build -f docker/Dockerfile.rust \
  -t resolver-identity-rust:field-validation .
docker compose \
  --env-file deploy/link/.env.example \
  -f deploy/link/docker-compose.yml config --quiet
```

# 附录 C 交付清单

每条链路最终交付：

- 批准 commit、镜像 digest、变更单；
- 私有 `.env`、签名 identity、issuer 公钥；
- 独立 Agent 私钥、三类 Token、mTLS 文件；
- 运行包和 `SHA256SUMS`；
- 防火墙变更、连通和跨链路拒绝证据；
- Registry finalized 和 SQLite 快照；
- Trace 插件版本及并发/缓存/重试测试；
- 正向、负向、容量、备份恢复和回滚报告；
- Prometheus、日志、告警和运维值班说明。

文档结束。
