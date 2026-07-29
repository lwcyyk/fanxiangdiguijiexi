# 真实服务器部署手册

文档状态：现场执行版

适用系统：Resolver Identity Rust V2

适用范围：域名中心星形架构中的单链路部署

生产入口：`deploy/link/docker-compose.yml`

## 1. 使用边界

本手册说明如何把当前仓库部署到真实服务器。每条 DNS 链路独立执行一次，例如：

```text
L01 -> ri-l01-r1
L02 -> ri-l02-r1
L03 -> ri-l03-r1
```

链路服务器只运行四个 Rust 程序：

| Compose 服务 | Rust 程序 | 作用 |
| --- | --- | --- |
| `wrapper` | `ri-wrapper` | 接收 UDP/TCP DNS 请求，验证通过后释放响应 |
| `agent` | `ri-agent` | 根据真实 Trace 构造并验证查询证据图 |
| `trace-adapter` | `ri-trace-adapter` | 接收 Resolver Trace，持久化并发送给 Agent |
| `registry-sync` | `ri-registry-sync` | 从链上同步并核验身份、Root、端点和撤销状态 |

链路服务器不需要 Python。Python 只在中心管理服务器低频执行身份签名和 Registry
发布，不进入 DNS 查询路径。新的生产链路不得使用：

```text
docker-compose.legacy-python.yml
docker-compose.multi-resolver.yml
docker/Dockerfile.legacy-python
docker/Dockerfile.python
```

## 2. 真实部署拓扑

```text
客户端
  |
  | UDP/TCP 53
  v
服务 IP/VIP -> Rust Wrapper -> 本链路递归解析器 R1 -> 实际 Root/TLD/Authority
                  |                    |
                  | mTLS              | 内部 Trace 生产插件
                  v                    v
               Rust Agent <- Rust Trace Adapter <- Unix Socket
                  |
                  v
              SQLite V2
                  ^
                  |
            Rust Registry Sync -> HTTPS 只读 RPC -> Registry 合约
```

中心管理服务器负责：

- 构建、扫描和发布 Rust 容器镜像；
- 部署 Registry 合约并拆分治理角色；
- 生成、签名和发布 `DnsServerIdentityV2`；
- 下发 issuer 公钥、签名 identity 和 TLS 制品；
- 集中监控、日志、备份和变更审计。

链路服务器负责：

- Wrapper、Agent、Trace Adapter 和 Registry Sync；
- 本链路独立 SQLite volume；
- 本链路 Agent 私钥、三类 token 和 mTLS 客户端/服务端证书；
- 连接本链路递归解析器和真实 Resolver Trace 生产插件。

L01、L02、L03 的 Resolver、Agent、数据库、token 和证书均不得互通或复用。

`controlled-strict` 只适用于所有目标均由本方控制的链路；Recursive、Forwarder、
Root、TLD 和 Authority 都必须具有可验证 Agent。连接公共互联网时使用
`public-hybrid`：Recursive/Forwarder 仍要求 Agent，公共 Root/TLD/Authority 使用
Registry 服务身份和 DNSSEC，只能声明认证服务身份，不能声明认证 Anycast 的具体
物理服务器。

同一链路中的部署单元不同：

| DNS 节点 | 启动组件 | 说明 |
| --- | --- | --- |
| Recursive/Forwarder 入口 | 四个组件全部启动 | Wrapper 是客户端 DNS 入口 |
| 受控 Root/TLD/Authority | `registry-sync`、`agent`、`trace-adapter` | 不启动 Wrapper |
| 公共 Root/TLD/Authority | 不部署本方组件 | 仅用于 `public-hybrid` |

受控上游节点分别使用独立 Compose project、server ID、Agent 私钥、TLS 证书、token、
Socket 目录和 SQLite volume。父级 Agent 只允许通过管理网 mTLS 调用同一实际 DNS
链中的目标 Agent，不能跨 L01/L02/L03 调用。

## 3. 上线前必须收集的参数

每条链路建立一份变更记录，至少填写：

| 参数 | 示例 | 说明 |
| --- | --- | --- |
| `RELEASE` | Git commit 或发布版本 | 必须与镜像构建来源一致 |
| `PROJECT` | `ri-l01-r1` | Compose project name，链路间唯一 |
| `RI_IMAGE` | `registry.example/ri@sha256:...` | 必须固定镜像 digest |
| `RI_VERIFICATION_MODE` | `controlled-strict` | 或 `public-hybrid` |
| `RI_AGENT_SERVER_ID` | `operator/L01/r1` | 必须与签名 identity 一致 |
| `DNS_BIND_ADDRESS` | `10.10.1.53` | Wrapper 服务 IP 或 VIP |
| `DNS_PORT` | `53` | Shadow 阶段可临时使用 `1053` |
| `RI_WRAPPER_UPSTREAMS` | `udp://10.10.1.54:53,tcp://10.10.1.54:53` | 本链路 R1，不能指回 Wrapper |
| `RI_WEB3_RPC_URL` | 现场 HTTPS RPC | 只读凭据 |
| `RI_WEB3_CHAIN_ID` | 现场链 ID | 双人独立核验 |
| `RI_REGISTRY_CONTRACT_ADDRESS` | Registry 地址 | 双人独立核验 |
| `RI_REGISTRY_CODE_HASH` | 32 字节 Keccak-256 | 对 finalized runtime code 计算 |
| Trace producer UID/GID | 现场 Resolver 进程 UID/GID | 用于 Unix Socket 权限 |
| 管理网 IP | 现场地址 | Agent 和 metrics 的受控监听地址 |
| 回滚入口 | 原 DNS VIP/原解析器地址 | 切流前必须实际验证 |

以下任一项没有真实值时停止部署：

- RPC URL、chain ID、Registry 地址或 runtime code hash 仍为占位值；
- `deploy/link/identities-v2.json` 为空或使用示例 identity；
- Resolver Trace 只能按时间、qname 或 pcap 猜测请求关联；
- TLS 证书、Agent 私钥或三类 token 尚未按链路隔离；
- 没有可操作的 DNS 流量回滚入口。

## 4. 服务器要求

### 4.1 中心管理服务器

需要：

- Linux；
- Git；
- Python 3.10 或更高版本，仅用于管理 CLI；
- Foundry，用于编译、测试和部署 Registry；
- Docker Engine 和 Docker Compose v2，用于构建镜像；
- 受控 keystore、硬件签名器或远程签名服务；
- 可访问私有镜像仓库和 EVM RPC。

中心管理服务器不能同时充当链路运行服务器，也不能把 Governance、Publisher、
Endpoint Manager、Revoker 或 issuer 私钥复制到链路服务器。

### 4.2 每台链路服务器

需要：

- 受支持的 64 位 Linux；
- Docker Engine 和 Docker Compose v2；
- `curl`、`dig`、`openssl`、`sha256sum`；
- 已启用的 NTP/Chrony 时间同步；
- 独立数据盘或满足容量测试结果的持久存储；
- 到本链路 R1、只读 RPC、监控和日志平台的必要网络；
- 现场 Resolver Trace 插件。

链路服务器不安装 Python、Foundry，也不保存任何 Registry 写入私钥。

上线前执行：

```bash
docker version
docker compose version
timedatectl status
df -h
sudo systemctl enable --now docker
```

Docker 日志必须启用轮转；不要使用无限增长的默认日志配置。现有
`/etc/docker/daemon.json` 需要由主机管理员合并修改，不能直接覆盖。

## 5. 中心管理服务器准备

### 5.1 取得并核对版本

```bash
git clone https://github.com/lwcyyk/fanxiangdiguijiexi.git
cd fanxiangdiguijiexi
git checkout <RELEASE_COMMIT>
git status --short
```

`git status --short` 必须为空。把 commit ID 写入变更记录。

### 5.2 构建并发布 Rust 镜像

```bash
export RELEASE=<RELEASE_VERSION>
export IMAGE=registry.example/resolver-identity-rust:${RELEASE}

docker build --pull \
  --file docker/Dockerfile.rust \
  --tag "$IMAGE" \
  .
docker push "$IMAGE"
docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}'
```

将最后输出的 `registry/repository@sha256:...` 作为链路 `.env` 中的 `RI_IMAGE`。
不得只使用可移动 tag。

### 5.3 部署 Registry 和发布身份

首次部署 Registry、拆分角色、签名 identity 和执行五阶段发布，按
[Rust V2 运行部署手册](production-deployment.md) 第 2、3 节执行。必须完成：

1. Governance 多签持有 `DEFAULT_ADMIN_ROLE`；
2. Root Publisher、Resolver Publisher、Endpoint Manager、Revoker 使用独立账户；
3. 从初始 Governance 地址撤销四个业务角色；
4. 两名操作人员从独立 RPC 核验 chain ID、合约地址和 runtime code hash；
5. 生成非空 `deploy/link/identities-v2.json`；
6. 生成真实 `deploy/issuer-keys.json`；
7. 五个角色操作使用相同且已审批的 `plan_hash`。

独立核验示例：

```bash
cast chain-id --rpc-url "$INDEPENDENT_RPC_URL"
RUNTIME_CODE=$(cast code "$REGISTRY_ADDRESS" \
  --rpc-url "$INDEPENDENT_RPC_URL" \
  --block finalized)
cast keccak "$RUNTIME_CODE"
```

将 `cast keccak` 的结果与构建制品和另一名操作员的结果比较。三项不一致时禁止
继续。

### 5.4 准备链路发布包

每条链路分别准备：

```text
deploy/link/.env
deploy/link/identities-v2.json
deploy/issuer-keys.json
deploy/link/secrets/agent_private_key
deploy/link/secrets/trace_ingest_token
deploy/link/secrets/agent_wrapper_token
deploy/link/secrets/agent_peer_token
deploy/link/tls/agent.crt
deploy/link/tls/agent.key
deploy/link/tls/client-ca.crt
deploy/link/tls/wrapper-client.crt
deploy/link/tls/wrapper-client.key
deploy/link/tls/trace-client.crt
deploy/link/tls/trace-client.key
deploy/link/tls/agent-client.crt
deploy/link/tls/agent-client.key
deploy/link/tls/agent-ca.crt
```

每个链路使用独立 Agent Ed25519 私钥、证书和 token。三个 token 必须不同。
`agent.crt` 至少包含 Compose 内部名称 `agent`；跨主机 Agent 调用时还必须包含
identity `agent.service_url` 所使用的管理网 DNS 名称。

发布包通过受控制品通道传输，记录 SHA-256。不得通过普通聊天工具传输私钥。

## 6. 链路服务器安装目录

以下以 L01 为例：

```bash
sudo groupadd --force --system ri-ops
sudo usermod --append --groups ri-ops,docker "$USER"

export RELEASE=<RELEASE_COMMIT>
export APP_ROOT=/opt/resolver-identity
export RELEASE_DIR=${APP_ROOT}/releases/${RELEASE}

sudo install -d -o root -g root -m 0755 "$RELEASE_DIR"
```

组变更后需要重新登录。`docker` 组等同主机 root 权限，只允许经过审批的部署账号
加入；日常只读监控账号不能加入。

把经过核验的仓库发布包解压到 `$RELEASE_DIR`，然后创建固定入口：

```bash
sudo ln -sfn "$RELEASE_DIR" "${APP_ROOT}/current"
cd "${APP_ROOT}/current"
```

确认必须文件存在：

```bash
test -f docker/Dockerfile.rust
test -f deploy/link/docker-compose.yml
test -f deploy/link/.env
test -s deploy/link/identities-v2.json
test -s deploy/issuer-keys.json
```

设置运行时文件权限：

```bash
sudo chown -R root:root deploy/link deploy/issuer-keys.json
sudo chmod 0755 deploy deploy/link
sudo chmod 0444 deploy/issuer-keys.json deploy/link/identities-v2.json
sudo chown root:ri-ops deploy/link/.env
sudo chmod 0640 deploy/link/.env
sudo chown 10002:10002 deploy/link/secrets/* deploy/link/tls/*.key
sudo chmod 0400 deploy/link/secrets/* deploy/link/tls/*.key
sudo chmod 0444 deploy/link/tls/*.crt
```

用 `namei -l` 检查所有父目录，确认容器 UID/GID `10002:10002` 可以读取所需文件。

## 7. DNS 地址和端口规划

Wrapper 不能和现有 R1 在同一个 IP 的 UDP/TCP 53 上同时监听。

推荐方案：

- R1 继续监听原解析器 IP，例如 `10.10.1.54:53`；
- Wrapper 使用新的服务 IP/VIP，例如 `10.10.1.53:53`；
- `RI_WRAPPER_UPSTREAMS` 指向 `10.10.1.54:53`；
- 客户端最终切换到 Wrapper 服务 IP/VIP。

Shadow 阶段没有额外 IP 时，可以暂时设置：

```text
DNS_BIND_ADDRESS=<链路服务器管理外的测试地址>
DNS_PORT=1053
```

验证完成并取得维护窗口后，再改为生产服务 IP 的 53 端口。若 R1 监听
`0.0.0.0:53`，必须先调整 R1 的监听地址或使用独立 Wrapper 主机，不能强行启动。

严禁把 `RI_WRAPPER_UPSTREAMS` 指向 `DNS_BIND_ADDRESS`，否则形成 DNS 环路。

## 8. 防火墙

默认拒绝未列出的通信：

| 源 | 目的 | 端口 | 要求 |
| --- | --- | --- | --- |
| 本链路客户端/VIP | Wrapper | UDP/TCP 53 | DNS 入口 |
| Wrapper | 本链路 R1 | UDP/TCP 53 | 只允许配置的 upstream |
| Agent | 同一真实 DNS 链的相邻 Agent | TCP 8443 | mTLS |
| Registry Sync | 只读 RPC | TCP 443 | TLS |
| 监控采集器 | metrics | TCP 9108/9109/9110 | 仅管理网 |
| 监控采集器 | Agent | TCP 8443 | mTLS |
| 链路主机 | 日志平台 | TCP 443/6514 | TLS 单向汇聚 |
| 堡垒机 | 链路主机 | TCP 22 | 限定来源 |

明确拒绝：

- L01 Resolver/Agent 到 L02/L03 Resolver/Agent；
- 其他主机直接访问 SQLite volume；
- 公网访问 Agent、metrics 或 Docker API；
- 链路服务器访问 Registry 写接口或签名服务。

如果 Agent 只供本机使用，保持 `AGENT_BIND_ADDRESS=127.0.0.1`。只有同一真实 DNS
链的相邻 Agent 位于不同主机时，才改成管理网 IP并增加精确防火墙规则。

## 9. 接入 Resolver Trace

真实部署前必须由 R1 的内部插件或受支持的原生接口产生 Trace。每条事件至少能够
可靠关联：

- 本次客户端查询的内部 `trace_id`；
- Wrapper 和 Resolver 约定的 `correlation_id`；
- 每次实际上游访问的 `target_correlation_id`；
- 实际目标 IP、端口、传输协议和 DNS wire digest；
- DNSSEC 验证结果或受控目标 Agent 响应证明。

不接受仅靠时间窗口、qname、最近相同响应或 pcap 推测关联。

创建 Socket 主机目录：

```bash
set -a
. deploy/link/.env
set +a

sudo install -d \
  -o 10002 \
  -g "$RI_TRACE_PRODUCER_GID" \
  -m 2770 \
  "$RI_TRACE_SOCKET_HOST_DIR"
```

Resolver Trace 生产进程的 UID/GID 必须与 `.env` 一致。Trace 插件最终连接：

```text
${RI_TRACE_SOCKET_HOST_DIR}/events.sock
```

Socket 尚未生成时先继续到第 11.2 节；Trace Adapter 启动后才会创建它。Resolver
插件必须在 Wrapper 切流前完成真实并发、缓存、重试和 transaction ID 复用测试。

## 10. 配置 `.env`

发布包中的 `.env` 应已由中心管理服务器生成。链路服务器只核对现场地址，不得再次
从 example 文件覆盖：

```bash
cd /opt/resolver-identity/current
sudoedit deploy/link/.env
sudo chown root:ri-ops deploy/link/.env
sudo chmod 0640 deploy/link/.env
```

至少修改：

```dotenv
RI_IMAGE=registry.example/resolver-identity-rust@sha256:<真实digest>
RI_VERIFICATION_MODE=controlled-strict
RI_AGENT_SERVER_ID=operator/L01/r1
RI_AGENT_KEY_ID=agent-key-L01-r1
RI_TRACE_PRODUCER_UID=<Resolver Trace进程UID>
RI_TRACE_PRODUCER_GID=<Resolver Trace进程GID>
RI_TRACE_SOCKET_HOST_DIR=/run/resolver-identity/L01-r1

RI_WEB3_RPC_URL=https://<只读RPC>
RI_WEB3_CHAIN_ID=<真实chain-id>
RI_REGISTRY_CONTRACT_ADDRESS=0x<真实合约地址>
RI_REGISTRY_CODE_HASH=0x<真实runtime-code-hash>

RI_WRAPPER_UPSTREAMS=udp://<R1-IP>:53,tcp://<R1-IP>:53
DNS_BIND_ADDRESS=<Wrapper服务IP>
DNS_PORT=53
```

远程 Prometheus 采集时，把三个 metrics bind address 改成管理网 IP并配置防火墙；
否则保持 `127.0.0.1`：

```dotenv
METRICS_BIND_ADDRESS=127.0.0.1
REGISTRY_METRICS_BIND_ADDRESS=127.0.0.1
TRACE_METRICS_BIND_ADDRESS=127.0.0.1
```

检查占位值和 Compose：

```bash
export PROJECT=ri-l01-r1
export ENV_FILE=deploy/link/.env
export COMPOSE_FILE=deploy/link/docker-compose.yml

if grep -Eq 'example\.invalid|0x0{40}|0x0{64}|<真实|<R1|<Wrapper' "$ENV_FILE"; then
  echo "配置仍包含占位值" >&2
  exit 1
fi

docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  config --quiet
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  config --images
```

输出的镜像必须是审批过的 digest。

## 11. 分阶段启动

### 11.1 拉取镜像

```bash
docker login registry.example
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  pull
```

### 11.2 启动 Registry Sync

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build registry-sync

until curl --fail --silent \
  "http://${REGISTRY_METRICS_BIND_ADDRESS:-127.0.0.1}:${REGISTRY_METRICS_PORT:-9109}/readyz"; do
  sleep 2
done

docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  logs --since 10m registry-sync
```

日志中的 chain ID、Registry 地址、runtime code hash、finalized block 和 identity
必须与变更记录一致。

### 11.3 启动 Agent 和 Trace Adapter

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build agent trace-adapter

test -S "${RI_TRACE_SOCKET_HOST_DIR}/events.sock"
curl --fail \
  "http://${TRACE_METRICS_BIND_ADDRESS:-127.0.0.1}:${TRACE_METRICS_PORT:-9110}/readyz"
```

使用 Agent mTLS 客户端证书核验：

```bash
sudo curl --fail \
  --cacert deploy/link/tls/agent-ca.crt \
  --cert deploy/link/tls/agent-client.crt \
  --key deploy/link/tls/agent-client.key \
  --resolve "agent:8443:${AGENT_BIND_ADDRESS:-127.0.0.1}" \
  https://agent:8443/readyz
```

此时启动 Resolver Trace 生产插件，并确认 Trace Adapter 的 pending 指标不持续增长、
dead-letter 为零、Agent 能取得真实查询事件。

### 11.4 最后启动 Wrapper

本节只在 Recursive/Forwarder 入口服务器执行。受控 Root/TLD/Authority 服务器在
第 11.3 节通过验收后停止，不启动 Wrapper。

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build wrapper

curl --fail \
  "http://${METRICS_BIND_ADDRESS:-127.0.0.1}:${METRICS_PORT:-9108}/readyz"
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  ps
```

任何 `/readyz` 非 2xx 都不得切流。

## 12. Shadow 验收

先从测试主机查询，不修改生产客户端：

```bash
dig @"$DNS_BIND_ADDRESS" -p "${DNS_PORT:-53}" example.com A
dig @"$DNS_BIND_ADDRESS" -p "${DNS_PORT:-53}" example.com A +tcp
```

至少验证：

1. UDP 和 TCP 正常查询；
2. 缓存冷、缓存热和重试；
3. 同时出现相同 qname/query 时不会串 Trace；
4. Trace 停止后返回 `SERVFAIL`；
5. Agent 停止后返回 `SERVFAIL`；
6. 错误证书、错误 token、未知 identity、撤销 identity 返回 `SERVFAIL`；
7. endpoint unbind、Root revoke、环路和超深路径返回 `SERVFAIL`；
8. 失败时不泄漏原始 DNS 响应；
9. RPC 短时故障和恢复符合 Registry staleness 策略；
10. 峰值 QPS、TCP 比例、最大包和最大链深满足容量目标。

负向测试结束后必须恢复正式身份状态，重新完成 readiness 和正向查询。

## 13. 生产切流

切流前：

- 原 DNS 入口保持可用；
- 已完成监控、日志、磁盘和容器重启告警测试；
- 已完成 evidence 和 Trace spool 备份恢复演练；
- 已记录当前镜像 digest、identity Root、Registry finalized block；
- 值班人员具备操作 VIP/负载均衡器/路由的权限；
- [生产就绪门禁](../production_readiness.md) 的 P0 全部有现场证据。

推荐按以下比例切流：

```text
1% -> 10% -> 50% -> 100%
```

每阶段至少观察：

- Wrapper、Agent、Registry Sync、Trace Adapter readiness；
- DNS 成功率、`SERVFAIL` 比例和 P95/P99；
- Trace pending、dead-letter 和丢弃量；
- Registry staleness/finality；
- CPU、内存、磁盘使用率和容器重启；
- 与原解析器抽样响应的一致性。

阈值必须在变更单中提前确定，不能在异常发生后临时放宽。

## 14. 回滚

以下任一情况立即停止扩流并回滚：

- 任一 readiness 失败；
- 非预期 `SERVFAIL` 超过批准阈值；
- Trace pending 持续增长或出现未处置 dead-letter；
- Registry chain/address/code hash 不一致；
- DNS P99 超过批准阈值；
- CPU、内存、磁盘或连接数接近容量上限；
- 出现跨链路通信或证书/token 复用。

回滚顺序：

1. 将 DNS VIP、负载均衡权重或路由切回原解析器入口；
2. 确认 Wrapper 已无客户端流量；
3. 停止 Wrapper；
4. 保留 Agent、Registry Sync、Trace Adapter 便于取证；
5. 保存日志、metrics、镜像 digest、数据库和 Trace spool；
6. 完成原因分析后再决定是否停止其余服务。

停止 Wrapper：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  stop wrapper
```

普通流量回滚不撤销 identity。只有身份或 Agent 私钥确认泄漏时，才由独立 Revoker
执行链上撤销。不得关闭身份验证后继续提供生产 DNS。

## 15. 日常运行

查看状态：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" ps
```

查看最近日志：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" logs --since 15m registry-sync agent trace-adapter wrapper
```

检查健康和指标：

```bash
curl --fail \
  "http://${METRICS_BIND_ADDRESS:-127.0.0.1}:${METRICS_PORT:-9108}/readyz"
curl --fail \
  "http://${REGISTRY_METRICS_BIND_ADDRESS:-127.0.0.1}:${REGISTRY_METRICS_PORT:-9109}/readyz"
curl --fail \
  "http://${TRACE_METRICS_BIND_ADDRESS:-127.0.0.1}:${TRACE_METRICS_PORT:-9110}/readyz"
curl --fail \
  "http://${METRICS_BIND_ADDRESS:-127.0.0.1}:${METRICS_PORT:-9108}/metrics"
curl --fail \
  "http://${REGISTRY_METRICS_BIND_ADDRESS:-127.0.0.1}:${REGISTRY_METRICS_PORT:-9109}/metrics"
curl --fail \
  "http://${TRACE_METRICS_BIND_ADDRESS:-127.0.0.1}:${TRACE_METRICS_PORT:-9110}/metrics"
```

停止整套服务但保留数据：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" down
```

生产服务器禁止执行 `docker compose down -v`，该命令会删除 evidence 和 Trace
spool volume。

## 16. 备份、恢复和升级

必须备份：

- evidence volume 中的 `evidence-v2.db`；
- trace-spool volume 中的 `trace-spool.db`；
- `.env` 的受控配置副本；
- identity、issuer 公钥包和 TLS 公共证书；
- 当前镜像 digest、Registry finalized block 和配置版本。

数据库使用 SQLite online backup 或一致性存储快照，并加密复制到另一故障域。
恢复必须在隔离服务器演练，执行 `PRAGMA integrity_check`，然后先启动 Registry Sync
重新 reconcile，确认已撤销身份不会被旧备份恢复为可用。

详细冷备份、恢复、升级和镜像回退命令见
[Rust V2 运行部署手册](production-deployment.md) 第 6、10、11 节。

## 17. 部署完成判定

只有以下条件全部满足，才能记录为“真实服务器部署完成”：

- 生产链路运行的是 digest 固定的 Rust 镜像；
- 容器内没有 Python，四个 Rust 程序以非 root 用户运行；
- Wrapper 使用独立服务 IP/VIP，且 upstream 不形成环路；
- Trace 来自真实 Resolver 内部上下文；
- Registry 三个固定值已双人独立核验；
- 身份、Root、endpoint、撤销状态与 finalized 链一致；
- mTLS、token、防火墙和跨链路隔离已做正反向实测；
- UDP/TCP 正向和全部关键负向测试通过；
- 监控、日志、磁盘告警、备份恢复和容量测试有现场记录；
- DNS 流量回滚在规定 RTO 内演练成功。

代码 CI 通过、容器能够启动或本机模拟成功，都不能单独视为真实生产部署完成。
