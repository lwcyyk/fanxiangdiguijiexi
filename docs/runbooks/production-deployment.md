# Rust V2 运行部署手册

## 0. 先确认部署边界

本手册用于域名中心星形架构中的单条 DNS 链路。L01、L02、L03 分别执行一次，
使用不同的 Compose project name、配置、证书、密钥、Socket 目录和数据卷。

新链路唯一部署入口：

```text
deploy/link/docker-compose.yml
docker/Dockerfile.rust
```

该 Compose 只运行以下 Rust 程序：

| 服务 | 程序 | 是否进入 DNS 查询路径 |
| --- | --- | --- |
| `wrapper` | `ri-wrapper` | 是 |
| `agent` | `ri-agent` | 是 |
| `trace-adapter` | `ri-trace-adapter` | 是 |
| `registry-sync` | `ri-registry-sync` | 是 |

链路服务器不安装、不启动 Python。仓库中的 Python 有两个用途：

1. 中心管理机低频执行 `tools/manage_v2_registry.py`，完成身份离线签名、发布计划和
   分角色合约交易；
2. 保留 V1 兼容测试，验证迁移前后的 canonical JSON、签名和历史攻击用例。

以下文件均是 V1 兼容或实验入口，不得用于新的生产链路：

```text
src/resolver_identity/
docker-compose.legacy-python.yml
docker-compose.multi-resolver.yml
docker/Dockerfile.legacy-python
docker/Dockerfile.python
tools/prepare_legacy_python.py
```

如果要求整个仓库完全没有 Python，必须先把 `manage_v2_registry.py` 的签名、计划、
角色发布和撤销能力重写为 Rust CLI。现在直接删除 Python 会破坏管理面和迁移回归，
但不会提高当前 Rust 查询数据面的性能。

## 1. 准备

要求 Linux、Docker Compose v2、外部 HTTPS EVM RPC、已部署 Registry、现场 CA、
受控 Resolver Trace 插件和加密异机备份位置。

链路服务器至少安装 Docker Engine、Docker Compose v2、`curl`、`dig`、`openssl`
和可靠的时间同步服务。`git` 只用于取得和核对版本，不是运行依赖；也可以由中心
管理机下发带 SHA-256 签名的发布包和容器镜像。

```bash
docker version
docker compose version
timedatectl status
df -h

export PROJECT=ri-l01-r1
export ENV_FILE=deploy/link/.env
export COMPOSE_FILE=deploy/link/docker-compose.yml
```

L02/R2 等实例必须修改 `PROJECT`，不能共用 project name。现场变更记录必须包含
Git commit、镜像 digest、配置版本和变更单号。

```bash
cp deploy/link/.env.example deploy/link/.env
cp deploy/link/identities-v2.example.json deploy/link/identities-v2.json
install -d -m 700 deploy/link/secrets deploy/link/tls
```

为每个链路和 DNS 服务生成独立 Agent Ed25519 私钥、Trace token、Wrapper token、
链内 peer token 和 mTLS 证书。三个 token 不得相同；peer token 只允许同一实际 DNS
链中的相邻 Agent 使用，不得跨 L01/L02/L03。
容器使用非 root UID/GID `10002`。运行时私钥和 token 应属于 `10002:10002` 且权限
为 `0400`，公共证书/CA 可为 `0444`；启动前用 `namei -l` 或等价工具确认目录路径
允许该 UID 读取。不要把 publisher/revoker/issuer 私钥复制到链路目录。
Compose 只向各容器挂载其自身证书和信任 CA，不得恢复为整个 `tls/` 目录共享挂载。

试运行环境可在 `umask 077` 下生成 Agent 私钥和三个独立 token；正式环境应由密钥
管理系统生成并审计：

```bash
umask 077
openssl rand -base64 32 | tr -d '\n' > deploy/link/secrets/agent_private_key
openssl rand -base64 48 | tr -d '\n' > deploy/link/secrets/trace_ingest_token
openssl rand -base64 48 | tr -d '\n' > deploy/link/secrets/agent_wrapper_token
openssl rand -base64 48 | tr -d '\n' > deploy/link/secrets/agent_peer_token
sudo chown 10002:10002 deploy/link/secrets/*
sudo chmod 0400 deploy/link/secrets/*
```

不要使用示例 identity 直接启动。`identities-v2.example.json` 中没有生产身份，
必须替换为中心签名、已经发布到 Registry 且覆盖本链路实际节点的 identity 集合。

Trace Socket 使用主机 bind mount。启动 Compose 前必须由 root 创建 `.env` 中的
`RI_TRACE_SOCKET_HOST_DIR`，并把 group 设置为 Resolver Trace 生产者的实际 GID：

```bash
sudo install -d -o 10002 -g <RI_TRACE_PRODUCER_GID> -m 2770 \
  /run/resolver-identity/L01-r1
```

`2770` 的 setgid 位保证 Adapter 创建的 `events.sock` 继承 producer group。
Resolver 进程使用 `.env` 中的 `RI_TRACE_PRODUCER_UID` 连接该 Socket；若 Resolver
也在容器中，必须以读写方式挂载同一主机目录。每个 DNS 服务使用不同目录。

单机部署保持 `AGENT_BIND_ADDRESS=127.0.0.1`。同一实际 DNS 链的相邻 Agent 位于
不同主机时，将它改成该主机管理网 IP，并只允许相邻 Agent 和 mTLS 监控采集器访问
`AGENT_PORT`。identity 的 `agent.service_url` 必须使用对端可解析且与证书 SAN 匹配
的管理网名称。

## 2. 生成和发布身份

本节只在中心管理机执行。链路服务器跳过 Python 环境安装。中心管理机使用独立
virtualenv，并从锁定依赖安装管理工具：

```bash
python3 -m venv .venv-management
. .venv-management/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements-production.lock
PYTHONPATH=src python tools/manage_v2_registry.py --help
```

首次部署 Registry 前，在隔离构建环境编译并测试合约：

```bash
cd contracts
forge build
forge test -vvv

export RPC_URL=https://rpc-gateway.example
export GOVERNANCE_MULTISIG=0x...

forge create src/ResolverIdentityRegistryV1.sol:ResolverIdentityRegistryV1 \
  --constructor-args "$GOVERNANCE_MULTISIG" \
  --rpc-url "$RPC_URL" \
  --keystore /secure/deployer-keystore \
  --broadcast
cd ..
```

部署账户仅用于首次部署，不得复制到链路服务器。正式环境应使用加密 keystore、
硬件签名器或受控远程签名器，命令历史中不得出现真实私钥或 keystore 密码。保存
输出中的交易哈希和合约地址，并由第二名操作人员从独立 RPC 核验部署结果。

Registry 首次部署时，constructor 的 `initialAdmin` 必须直接填写治理多签地址，不能
填写链路主机、发布者或临时个人账户。部署后、发布任何 Root 之前，在同一变更窗口：

1. 治理多签保留 `DEFAULT_ADMIN_ROLE`；向四个互不相同且不同于治理多签的账户分别
   授予 `ROOT_PUBLISHER_ROLE`、`RESOLVER_PUBLISHER_ROLE`、
   `ENDPOINT_MANAGER_ROLE` 和 `REVOKER_ROLE`；
2. 从治理多签撤销 constructor 自动赋予的四个业务角色，只保留
   `DEFAULT_ADMIN_ROLE`；
3. 分别用 `hasRole(role, account)` 从第二只读 RPC 核验；
4. 保存部署交易、授权/撤权交易、合约地址和 runtime code hash；
5. 未完成上述核验前禁止执行身份发布。

治理 Admin 有权重新分配角色，因此应使用有审批阈值的离线多签，而不是在线单私钥。
Publisher、Endpoint Manager 和 Revoker 的交易密钥必须分别运行
`manage_v2_registry.py`，不能共用环境或密钥文件。

先准备 unsigned `DnsServerIdentityV2` 文件，然后由 issuer 离线签名：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py sign \
  --input identities-v2.unsigned.json \
  --private-key-file /secure/issuer-private-key \
  --output deploy/link/identities-v2.json

# 以下三项必须先按第 3 节完成双人独立核验
CHAIN_ID=1
REGISTRY_ADDRESS=0x...
REGISTRY_CODE_HASH=0x...

PYTHONPATH=src python3 tools/manage_v2_registry.py prepare \
  --identities deploy/link/identities-v2.json \
  --issuer-keys deploy/issuer-keys.json \
  --root-version 1 \
  --chain-id "$CHAIN_ID" \
  --contract-address "$REGISTRY_ADDRESS" \
  --contract-code-hash "$REGISTRY_CODE_HASH" \
  --output registry-plan-v2.json
```

Root 版本 2 及以上必须保留前一份已批准计划，并显式传入：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py prepare \
  --identities deploy/link/identities-v2.json \
  --issuer-keys deploy/issuer-keys.json \
  --root-version 2 \
  --previous-plan registry-plan-v2-v1.json \
  --chain-id "$CHAIN_ID" \
  --contract-address "$REGISTRY_ADDRESS" \
  --contract-code-hash "$REGISTRY_CODE_HASH" \
  --output registry-plan-v2-v2.json
```

记录输出的 `plan_hash`。它同时固定 identity、Root、chain ID、合约地址、runtime
code hash、旧 endpoint 解绑和被移除 resolver 撤销列表。Root Publisher、Resolver
Publisher、Endpoint Manager 和 Revoker 分别核对该 hash，并使用各自的私钥文件
执行；工具还会在每个阶段与实时部署再次比对：

```bash
export RESOLVER_IDENTITY_ENVIRONMENT=production
export RESOLVER_IDENTITY_REGISTRY_MODE=web3
export RESOLVER_IDENTITY_ALLOW_HMAC_OBJECT_SIGNATURES=false
export RESOLVER_IDENTITY_ISSUER_KEYS_FILE=deploy/issuer-keys.json
export RESOLVER_IDENTITY_WEB3_RPC_URL=https://rpc-gateway.example
export RESOLVER_IDENTITY_WEB3_CHAIN_ID="$CHAIN_ID"
export RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS="$REGISTRY_ADDRESS"
export RESOLVER_IDENTITY_WEB3_CONTRACT_CODE_HASH="$REGISTRY_CODE_HASH"
export RESOLVER_IDENTITY_WEB3_ABI_PATH=contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json

PYTHONPATH=src python3 tools/manage_v2_registry.py publish-root \
  --plan registry-plan-v2.json --expected-plan-hash 0x...
PYTHONPATH=src python3 tools/manage_v2_registry.py publish-resolvers \
  --plan registry-plan-v2.json --expected-plan-hash 0x...
# Endpoint Manager：先释放被删除或迁移的旧绑定
PYTHONPATH=src python3 tools/manage_v2_registry.py unbind-endpoints \
  --plan registry-plan-v2.json --expected-plan-hash 0x...
PYTHONPATH=src python3 tools/manage_v2_registry.py bind-endpoints \
  --plan registry-plan-v2.json --expected-plan-hash 0x...
# Revoker：永久撤销已从新计划移除的 resolver
PYTHONPATH=src python3 tools/manage_v2_registry.py revoke-removed \
  --plan registry-plan-v2.json --expected-plan-hash 0x...
```

每条命令的环境中只配置当前角色的
`RESOLVER_IDENTITY_WEB3_PRIVATE_KEY_FILE`。合约权限错误必须中止，不得临时给一个
在线账户全部角色。发布工具使用 `registry-writer` 配置门禁，不要求或读取 Admin
token、issuer 私钥。
五个命令可以重试，但必须保持同一不可变 plan 文件和 expected hash；任何冲突都应
停止变更窗口。新 Root 激活到全部阶段完成期间，Registry Sync 可能因状态不一致而
失败关闭，这是预期行为，不得通过放宽校验绕过。

## 3. 独立核验

两名操作人员分别从部署交易/构建制品和第二只读 RPC/区块浏览器得到：

- chain ID；
- Registry checksum address；
- `keccak256(eth_getCode(address, finalized))`。

三项一致后写入 `deploy/link/.env`。`ri-registry-sync` 会在运行时再次本地计算。

## 4. 配置检查和启动

先确认 `.env` 已替换所有 example/zero 占位值，Socket 目录的 owner/group/mode
正确，并且同主机多实例使用不同的 Compose project name 和全部宿主机端口。以下以
project `ri-l01-r1` 为例：

```bash
set -a
. "$ENV_FILE"
set +a

if grep -Eq 'example\.invalid|0x0{40}|0x0{64}' "$ENV_FILE"; then
  echo "配置仍包含占位值" >&2
  exit 1
fi
test -s deploy/link/identities-v2.json
test -s deploy/issuer-keys.json

docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  config --quiet
```

小规模现场试运行可以从已经审核的源码构建：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  build --pull
```

正式环境推荐在中心 CI 构建、扫描并推送镜像，然后把 `.env` 中的 `RI_IMAGE` 固定为
私有仓库 digest，例如 `registry.example/ri@sha256:...`。链路主机只执行：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  pull
```

先只启动 Registry Sync：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build registry-sync

until curl --fail --silent \
  "http://127.0.0.1:${REGISTRY_METRICS_PORT:-9109}/readyz"; do
  sleep 2
done
```

确认日志中的 chain ID、合约地址、runtime code hash、finalized block 和全部
identity 均匹配，再启动 Agent 和 Trace Adapter：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build agent trace-adapter

test -S "${RI_TRACE_SOCKET_HOST_DIR}/events.sock"
```

此时必须让 Resolver Trace 插件连接 `events.sock` 并实际产生事件。没有可靠内部
`trace_id`、`correlation_id` 和 `target_correlation_id` 时，不得启动切流。

Agent `/readyz` 和 Trace Adapter `/readyz` 通过后，最后启动 Wrapper：

```bash
docker compose \
  --project-name "$PROJECT" \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  up -d --no-build wrapper
```

## 5. 验收

```bash
curl --fail http://127.0.0.1:9109/readyz
curl --fail http://127.0.0.1:9109/metrics
curl --fail http://127.0.0.1:9110/readyz
curl --fail http://127.0.0.1:9110/metrics
curl --fail http://127.0.0.1:9108/readyz
curl --fail http://127.0.0.1:9108/metrics
curl --fail --cacert deploy/link/tls/agent-ca.crt \
  --cert deploy/link/tls/agent-client.crt \
  --key deploy/link/tls/agent-client.key \
  --resolve agent:8443:127.0.0.1 https://agent:8443/readyz
dig @${DNS_BIND_ADDRESS} -p ${DNS_PORT:-53} example.com A
dig @${DNS_BIND_ADDRESS} -p ${DNS_PORT:-53} example.com A +tcp
```

随后逐项执行 Trace 停止、迟到 Trace/transaction ID 复用、错误证书、Agent 停止、
超大 Agent/RPC 响应、错误 identity、endpoint unbind、resolver revoke、Root revoke、
递归 Agent 环路、最大深度和无效 Trace 事件测试。验证失败项必须为 `SERVFAIL`，
无效 Trace 进入 dead-letter 后不能阻塞后续有效事件，并产生可定位指标/日志。

## 6. 备份与恢复

主数据库是 evidence volume 中的 `evidence-v2.db`；未上传 Trace 位于 trace-spool
volume 的 `trace-spool.db`。使用 SQLite online backup API 或 `sqlite3 .backup`
分别生成一致性备份，同时记录 SHA-256、应用镜像 digest、Registry finalized block、
cache generation 和 spool 待传数量。备份加密后移至另一故障域。

恢复演练必须在隔离主机：

1. 验证备份 SHA-256 和 `PRAGMA integrity_check`；
2. 使用相同或兼容 Rust 镜像启动 Registry Sync；
3. 等待 Registry 重新 reconcile；
4. 验证已撤销身份不会因旧备份恢复为可用；
5. 执行 UDP/TCP 正向和负向检查；
6. 记录 RTO/RPO。

## 7. 监控

至少告警：

- `resolver_identity_ready == 0`；
- `SERVFAIL` 和 verification failure 比例；
- inflight 接近 `RI_WRAPPER_MAX_INFLIGHT`；
- Agent/Registry Sync/Trace Adapter 重启；
- `resolver_identity_registry_failures_total` 增长或 last success 超时；
- `resolver_identity_trace_spool_pending` 持续增长；
- `resolver_identity_trace_dead_letter_total > 0`；
- Agent graph failure 比例和 Trace 摄入停止；
- RPC finality 落后和 Registry mismatch；
- volume 使用率 70%/85%；
- 备份超期和最近恢复演练超期。

## 8. 回滚和撤销

普通回滚把 DNS VIP 切回原入口并停止 Wrapper，不降低 identity/object/config 版本。
疑似 Agent 私钥泄漏时由独立 Revoker 执行：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py revoke-resolver \
  --server-id operator/L01/r1
```

永久撤销对象不能复活；轮换需使用新的 server identity 或按合约规则发布更高版本。

## 9. 日常运行命令

查看状态和最近日志：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" ps
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" logs --since 15m registry-sync agent trace-adapter wrapper
```

仅重启某个组件：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" restart trace-adapter
```

停止接收 DNS 流量：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" stop wrapper
```

停止整套服务但保留数据卷：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" down
```

禁止在生产主机执行 `down -v`，该命令会删除 evidence 和 Trace spool 数据卷。

## 10. 升级与回退

1. 先备份两个 SQLite 卷并记录当前 `RI_IMAGE` digest；
2. 在 shadow 链路验证新镜像；
3. 把 DNS VIP 切到备用入口，停止 Wrapper；
4. 修改 `.env` 中的 `RI_IMAGE` 为新 digest；
5. 依次启动 Registry Sync、Agent/Trace Adapter、Wrapper 并执行第 5 节验收；
6. 指标或负向测试异常时，停止 Wrapper，将 `RI_IMAGE` 改回旧 digest 后重新启动。

镜像回退不能回退或复活已经撤销的 identity，也不能降低 object/root/config 版本。

## 11. 冷备份与恢复

小规模试运行可在 DNS VIP 已切走后进行一致性冷备份：

```bash
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" stop wrapper trace-adapter agent registry-sync

EVIDENCE_VOLUME=$(docker volume ls -q \
  --filter "label=com.docker.compose.project=$PROJECT" \
  --filter "label=com.docker.compose.volume=evidence")
SPOOL_VOLUME=$(docker volume ls -q \
  --filter "label=com.docker.compose.project=$PROJECT" \
  --filter "label=com.docker.compose.volume=trace-spool")

sudo tar -C "$(docker volume inspect -f '{{.Mountpoint}}' "$EVIDENCE_VOLUME")" \
  -czf "evidence-${PROJECT}.tgz" .
sudo tar -C "$(docker volume inspect -f '{{.Mountpoint}}' "$SPOOL_VOLUME")" \
  -czf "trace-spool-${PROJECT}.tgz" .
sha256sum "evidence-${PROJECT}.tgz" "trace-spool-${PROJECT}.tgz" \
  > "backup-${PROJECT}.sha256"
```

备份加密后复制到另一故障域。恢复时必须保持服务停止，将归档恢复到新建空卷，核对
SHA-256 和 SQLite `PRAGMA integrity_check`，再按 Registry Sync 到 Wrapper 的顺序
启动。冷备份完成后服务仍处于停止状态；未执行第 4 节的分阶段启动和第 5 节验收前，
不得把 DNS VIP 切回。正式连续运行环境应接入 SQLite online backup 或存储快照，
不应依赖停机备份。

## 12. 常见故障

| 现象 | 优先检查 | 处理原则 |
| --- | --- | --- |
| Registry `/readyz` 503 | RPC、chain ID、合约地址/code hash、finality | 修正固定值，不允许跳过核验 |
| Agent `/readyz` 失败 | Registry 新鲜度、identity、mTLS、三个 token | 保持失败关闭 |
| `events.sock` 不存在 | Adapter 日志、主机目录 owner/GID/mode | 修复目录和 producer UID/GID |
| Trace spool 持续增长 | Agent 可达性、证书、token、dead-letter | 先停止切流，禁止删除未传事件 |
| DNS 全部 `SERVFAIL` | Trace 是否真实产生、身份/端点/Root 状态 | 不得通过关闭验证恢复流量 |
| UDP 正常、TCP 失败 | TCP 53 防火墙、连接上限、超时 | 修复网络或容量配置 |
| 某链路故障影响其他链路 | project/volume/端口或防火墙是否复用 | 立即隔离，恢复每链路独立部署 |

## 13. 上线完成标准

只有 [生产就绪门禁](../production_readiness.md) 的全部 P0 项都有现场证据后才能切换
正式 DNS VIP。代码测试通过、Compose 启动成功或模拟 Trace 成功，都不能代替真实
Resolver 插件、真实 Registry、mTLS、防火墙、监控、备份恢复和峰值容量验收。
