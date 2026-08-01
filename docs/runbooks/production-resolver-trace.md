# Knot Resolver 生产 Trace 接入手册

## 1. 适用范围

本实现只适配 Knot Resolver 6.3.0，上游源码固定为 Commit
`124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e`。不适用于 BIND、Unbound、
PowerDNS Recursor 或其他 Knot 版本。它是代码级生产候选，不表示任何真实域名中心
已经完成上线。

运行路径如下：

```text
客户端 -> Wrapper -> Knot Resolver -> 内部 C Hook -> ri-knot-trace-producer
                                                -> Trace Adapter -> Agent -> SQLite
```

Hook 和 Producer 不访问 Go-Norn、EVM 或 SQLite。Registry Sync 是唯一链客户端；
Wrapper 和 Agent 只读本机可信 SQLite。R1 使用 `first-hop`，R2/R3 使用 `upstream`，
后两者不得启动 Wrapper。

## 2. 关联与失败关闭

Knot 内部的 `(kresd PID, request UID)` 是进程内请求键；Producer 为每个请求生成随机
128 位 `trace_id`。`correlation_id` 绑定 Wrapper 实际转发的 DNS wire，不能由
qname、时间窗口、最近响应、pcap 或客户端 Transaction ID 单独推测。

每个事件必须严格递增并指向本 Trace 中更早的父事件。上游请求只能由完全匹配的
响应或超时终结。Hook 写入后必须收到 Producer、Trace Adapter 对持久 spool 的 ACK；
Socket 不可用、队列满、事件重复/乱序/篡改、Agent 不可用或 Registry 陈旧时返回
`SERVFAIL`，不得释放原始响应。

缓存事件使用规范化 cache-object digest：只清零 Transaction ID 和 RR TTL，仍绑定
DNS flags、name、type、class 与 RDATA。Trace Adapter 只能引用当前 Registry generation
中已有的精确来源图。来源不存在时整条 Trace 进入 dead-letter，readiness 失败。

## 3. 构建制品

构建机需要 Docker；目标服务器不编译源码。Knot 镜像构建会从固定 Commit 应用
[`0001-production-trace-hook.patch`](../../resolver-trace/knot/0001-production-trace-hook.patch)：

```bash
docker build --pull \
  --file docker/Dockerfile.knot-trace \
  --tag resolver-identity-knot-trace:rc .

docker build --pull \
  --file docker/Dockerfile.rust \
  --tag resolver-identity-rust:rc .

docker image inspect resolver-identity-knot-trace:rc \
  --format '{{index .RepoDigests 0}}'
```

镜像必须推送到内部仓库并在 Inventory 中填写完整 `name@sha256:<digest>`。分发修改版
Knot 时须保留 GPLv3 许可并按其要求提供对应源码和补丁。

## 4. 现场配置

每台 Resolver 服务器使用独立的 Server ID、Agent 私钥、mTLS 证书、三类 Token、
SQLite、Trace Socket 和数据目录。Resolver UID 默认 `10003`，Producer UID/GID 默认
`10002`，二者不能相同。Socket 目录由部署脚本以预期 group 和 setgid 权限创建。

关键非秘密变量：

```dotenv
RI_KNOT_IMAGE=registry.internal/resolver-identity-knot-trace@sha256:<digest>
RI_IMAGE=registry.internal/resolver-identity-rust@sha256:<digest>
RI_MANAGEMENT_BIND_ADDRESS=<本机管理网IP>
RI_KNOT_RESOLVER_UID=10003
RI_TRACE_PRODUCER_UID=10002
RI_TRACE_PRODUCER_GID=10002
RI_TRACE_SOCKET_HOST_DIR=/run/resolver-identity/L01-r1
RI_TRACE_MAX_CONTEXTS=65536
RI_TRACE_ACK_TIMEOUT_MS=100
RI_TRACE_CACHE_PROVENANCE_WAIT_MS=2000
RI_TRACE_WAIT_MILLIS=5000
RI_WRAPPER_AGENT_TIMEOUT_MS=7500
RI_WRAPPER_MAX_CONCURRENT_VERIFICATIONS=32
RI_WRAPPER_UPSTREAMS=tcp://<本机Knot地址>:53
```

Wrapper 到受控 Knot 固定使用单一 TCP Endpoint，使一个 Wrapper 请求对应一个完整
Resolver Trace；客户端入口仍支持 UDP/TCP，Knot 对权威上游仍实际使用 UDP、重试和
TCP 回退。Wrapper 可以并发暂存 DNS 响应，但最多同时向 Agent 提交 32 个验证请求，
避免 SQLite 单写者在突发流量下发生写锁饥饿；该值必须通过现场容量测试确定，不能
任意调高。Agent Trace 等待窗口为 5 秒，Wrapper Agent 超时为 7.5 秒，安装门禁会拒绝
前者不小于后者的配置。Inventory 校验会拒绝 UDP+TCP 双条目和非本机 Knot Endpoint。

## 5. 安装、升级与回滚

渲染时必须提供与 Release Commit 一致的脚本验收文件：

```bash
python3 tools/manage_norn_field_delivery.py render \
  --inventory /secure/field/inventory.yaml \
  --trace-acceptance specs/production-resolver-trace/acceptance.json \
  --output-root artifacts/field-deployment
```

安装器在首次安装前把现有 Resolver 配置保存到
`/opt/resolver-identity/state/resolver-config/`，不覆盖原文件。配置或 Compose 检查
失败时不重启 Resolver。程序版本目录为：

```text
/opt/resolver-identity/releases/<version>/
/opt/resolver-identity/current
```

```bash
./preflight.sh
sudo ./install.sh --config-dir /secure/rendered/<host>/config
./health-check.sh
sudo ./upgrade.sh --config-dir /secure/rendered/<host>/config
sudo /opt/resolver-identity/current/rollback.sh
```

回滚只切换程序和固定镜像 digest，不回滚 SQLite、Norn 数据或 Registry 状态。普通
`uninstall.sh` 保留数据和原配置备份；只有审批后的 `--purge-data` 才删除安装器拥有的
数据目录。

## 6. 启动顺序和检查

按 Registry Sync、Agent/Trace Adapter、Producer、Knot、Wrapper 的顺序启动。不能用
Compose `depends_on` 代替 readiness：

```bash
export COMPOSE_FILE=/opt/resolver-identity/current/docker-compose.yml
export ENV_FILE=/opt/resolver-identity/current/config/.env
export PROJECT="$(sed -n 's/^RI_FIELD_COMPOSE_PROJECT=//p' "$ENV_FILE")"

docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" config --quiet
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d registry-sync
# 等待管理网 <IP>:9109/readyz 成功
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d agent trace-adapter trace-producer
# 等待 8443/readyz、9110/readyz 和两个 Unix Socket 就绪
docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d resolver

# 仅 first-hop 执行；upstream 不得启用该 profile
docker compose --project-name "$PROJECT" --profile first-hop \
  --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d wrapper
```

`8443` 使用 mTLS；`9108`、`9109`、`9110` 只绑定管理 IP，并必须由主机防火墙限制为
监控采集器和堡垒机来源。Resolver 容器内以非 root 身份监听 `1053`，只在宿主 DNS
服务 IP 上发布为 `53/udp` 和 `53/tcp`。

监控至少覆盖 Trace pending、dead-letter、Agent 验证失败、Wrapper SERVFAIL、Registry
staleness、进程重启、SQLite WAL 和磁盘。dead-letter 非零必须告警并阻止扩流。

## 7. 可复核验收

验收必须使用真实打补丁的 `kresd` 和真实 DNSSEC 权威 Knot，不接受 Mock：

```bash
python3 tools/run_production_trace_acceptance.py \
  --kresd /opt/knot-trace/sbin/kresd \
  --knotd /usr/sbin/knotd \
  --kdig /usr/bin/kdig \
  --concurrency 128 \
  --output specs/production-resolver-trace/acceptance.json
```

脚本覆盖 UDP/TCP、并发同名和 ID 重复、UDP→TCP、超时重试、多上游、缓存、CNAME、
Resolver 重启、Socket/队列/Producer/Agent 故障、Registry 陈旧、身份撤销、Trace 篡改、
SQLite 完整性及安装/升级/回滚。只有全部通过、串线数为零、秘密扫描干净且临时资源
已清理时，脚本才写出 `production_trace_ready=true`。

## 8. 仍属现场门禁

代码验收不能替代真实链身份、mTLS PKI、防火墙、日志访问控制、监控告警、备份恢复、
峰值容量、VIP 灰度和回滚演练。任何一项缺失时只能进入 Shadow，不能宣称生产上线。
