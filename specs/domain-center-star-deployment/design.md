# 域名中心星型多服务器部署设计

## 1. 设计原则

中心 Hub 是治理和运维中心，不在 DNS 查询路径上。每个链路单元是独立安全域、
故障域和状态域。运行时只共享已签名的公开 identity、issuer 公钥和固定 Registry
参数，不共享 SQLite、运行私钥或 Token。

```text
                          Center Hub
      Governance / Registry / Identity / Artifact / Observability
              |                 |                 |
        management only   management only   management only
              |                 |                 |
           L01 unit           L02 unit           L03 unit
       Wrapper/R1/Agent   Wrapper/R1/Agent   Wrapper/R1/Agent
       Trace/Sync/SQLite  Trace/Sync/SQLite  Trace/Sync/SQLite

       L01 Resolver/Agent  -X-  L02/L03 Resolver/Agent/SQLite
```

## 2. 服务器角色

| 角色 | 推荐主机 | 运行内容 |
| --- | --- | --- |
| Hub 管理 | `ri-hub-mgmt-01` | 构建、镜像、身份签名、Registry 管理、计划发布 |
| Hub 运维 | `ri-hub-ops-01` | Prometheus、告警、日志、备份、审计 |
| 链路入口 | `ri-lXX-r1-01` | R1、Wrapper、Agent、Trace Adapter、Registry Sync、SQLite |
| 同链上游 | `ri-lXX-r2-01` | R2、Agent、Trace Adapter、Registry Sync、SQLite |
| 测试客户端 | `ri-test-client-01` | UDP/TCP Shadow、负向、容量和故障注入 |

高可用时复制整个链路入口单元为 A/B，通过外部 DNS VIP 或四层负载均衡切换。

## 3. 清单驱动

真实部署使用一个私有 JSON 清单作为唯一输入。清单只引用秘密文件，不内嵌秘密。
管理工具执行：

1. JSON 结构与类型校验；
2. 地址、URL、chain、合约、hash、镜像 digest 校验；
3. 链路、主机、Compose project、server ID、Socket 和端口唯一性校验；
4. Wrapper upstream 回路校验；
5. secret/TLS 文件存在性、权限和跨链路复用校验；
6. 为每个 unit 生成独立 `.env`、Compose、identity、issuer keys、secret 和 TLS
   目录；
7. 对运行包生成不泄漏秘密内容的 SHA-256 文件清单。

可提交的 `site-inventory.example.json` 只描述字段，必须在模板模式校验；正式生成
命令拒绝模板占位值。

## 4. 运行包

每个运行包保持与现有单链路 Compose 相同的相对目录：

```text
<unit>/
├── deploy/
│   ├── issuer-keys.json
│   └── link/
│       ├── .env
│       ├── docker-compose.yml
│       ├── identities-v2.json
│       ├── secrets/
│       └── tls/
├── metadata/
│   ├── unit.json
│   └── SHA256SUMS
└── scripts/
```

运行包目录和归档均属于敏感部署制品，默认写到被 Git 忽略的
`deployments/field/private/`。

## 5. 数据流

```text
client
  -> Wrapper (holds original response)
  -> R1 resolver
  -> actual Root/TLD/Authority or same-link R2

R1 internal trace
  -> local Unix Socket
  -> Trace Adapter spool
  -> Agent
  -> QueryEvidenceGraphV2

Registry Sync
  -> HTTPS read-only RPC
  -> finalized Registry state
  -> atomic local SQLite snapshot

Wrapper
  -> mTLS Agent verification
  -> local Registry re-verification
  -> release response or SERVFAIL
```

R1→R2 时只有 R1 Agent 到同链 R2 Agent 的管理网 mTLS 通道被允许。公共
Root/TLD/Authority 使用 `public-hybrid`，不能虚构远程 Agent 或物理实例身份。

## 6. Hub 和链路边界

Hub 持有 Registry 写入能力和 issuer 离线签名能力；链路服务器只持有读取链状态和
运行本链路所需材料。Hub 发布包经过 SHA-256 核对后传输，链路主机再次核验。

链路服务的启动脚本按 Registry Sync → Agent/Trace Adapter → Resolver Trace →
Wrapper 执行。脚本将检查 readiness、Socket、SQLite 和 Compose 状态，不依赖
`depends_on` 作为健康判断。

## 7. 运维设计

- Wrapper、Registry Sync 和 Trace Adapter metrics 分别使用 9108、9109、9110；
- Agent `/metrics` 使用 8443 mTLS；
- Prometheus 只从管理网采集；
- Docker `json-file` 日志设置最大文件大小和保留数量；
- 主机采集磁盘、inode、文件描述符、时间同步和容器重启；
- evidence 和 trace spool 使用 SQLite online backup；
- 恢复演练只写入隔离目录，先做 `PRAGMA integrity_check`，不覆盖在线数据；
- 普通回滚只切回原 DNS 入口，不撤销 identity。

## 8. 证据位置

本地实现证据写入：

```text
artifacts/field-deployment/
```

真实现场证据写入私有目录：

```text
deployments/field/private/<site>/<timestamp>/
```

只允许脱敏后的摘要、哈希、测试状态和已知缺口进入可提交的验收文档。
