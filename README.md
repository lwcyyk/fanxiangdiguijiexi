# DNS 全路径服务身份认证

本项目在不修改客户端 DNS 报文格式的前提下，先验证一次查询实际使用的 DNS
服务身份，再决定是否向客户端释放原始响应。验证范围包括 Recursive、Forwarder，
以及可观测的 Root、TLD 和 Authoritative 服务。

## 当前架构

生产数据面已迁移到 Rust：

```text
client -> Rust Wrapper -> Recursive R1
             |                 |
             |                 `-> actual Trace -> Root/TLD/Authority
             `-> Rust Agent -> signed QueryEvidenceGraphV2
```

- `ri-wrapper`：UDP/TCP DNS、帧/问题核对、资源上限、证据与 Registry 双重复验；
- `ri-agent`：从实际 Trace 构图、目标响应证明、R1/R2 子图递归合并、mTLS；
- `ri-trace-adapter`：Unix Socket、producer UID、SQLite 持久队列、批量 mTLS 续传；
- `ri-knot-trace-producer`：绑定 Knot Resolver 6.3.0 内部请求 UID，输出严格有序、
  持久确认的真实查询事件，不使用 qname 或时间窗口关联；
- `ri-chain-adapter`：统一链身份、最终检查点、Registry 快照和历史区块哈希接口，
  已实现 EVM、Go-Norn，并通过标准 Sidecar 协议扩展新的链适配器；
- `ri-registry-sync`：通过多链适配器完成 identity/root/endpoint 核验和原子同步；
- `ri-core`：canonical JSON、SHA-256、Ed25519、V2 模型和安全策略；
- `ri-store`：SQLite WAL、事务、Registry 代际和缓存来源。

Python V1 代码仍保留用于管理面、合约发布、历史实验和迁移回归，不再作为 V2 DNS
查询热路径。Solidity Registry 继续提供身份锚、Root、端点绑定、撤销和角色隔离。

> **部署入口：** 新部署只能使用 `deploy/link/docker-compose.yml` 和
> `docker/Dockerfile.rust`。`docker-compose.legacy-python.yml`、
> `docker-compose.multi-resolver.yml`、`docker/Dockerfile.legacy-python`、
> `docker/Dockerfile.python` 及 `src/resolver_identity/` 都属于 V1
> 兼容/测试范围，不得部署到新的 DNS 生产链路。链路服务器不需要安装 Python；
> Python 只在中心管理机低频执行身份签名和分角色 Registry 发布。

## 验证模式

`controlled-strict` 用于完全受控环境。Recursive、Root、TLD、Authority 均部署
Agent，每条实际 DNS 边都必须取得目标 Agent 的响应证明，并要求 DNSSEC `SECURE`。

`public-hybrid` 用于公共互联网。Recursive/Forwarder 仍必须有 Agent；公共
Root/TLD/Authority 使用“Registry 服务身份 + DNSSEC”。Anycast 只能认证服务身份，
不能声称认证具体物理实例。

两种模式都使用逐请求随机 challenge、DNS wire digest、Ed25519、Registry finalized
快照、环路/深度/规模限制和失败关闭。调用方不能提交或自报路径。

## Rust 构建与测试

要求 Rust 1.97：

```bash
cd rust
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Rust 测试覆盖 Python canonical/signature 兼容、严格/混合策略、篡改、撤销、环路、
请求登记时间与事件一次性绑定、事务 ID 冷却复用、递归缓存 DNSSEC 来源、Trace
持久续传/无效事件隔离、`R1 -> R2 -> Root` 子图合并和 DNS `SERVFAIL`。

Python 与合约回归：

```bash
python3 -m pytest -q
cd contracts && forge test -vvv
```

## 单链路生产配置

生产镜像和 Compose：

- `docker/Dockerfile.rust`
- `deploy/link/docker-compose.yml`
- `deploy/link/.env.example`
- `deploy/link/tls/README.md`
- `deploy/link/secrets/README.md`

配置检查：

```bash
cp deploy/link/.env.example deploy/link/.env
cp deploy/link/identities-v2.example.json deploy/link/identities-v2.json
docker compose \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml \
  config --quiet
```

V2 身份和分角色发布：

```bash
PYTHONPATH=src python3 tools/manage_v2_registry.py --help
```

工具按同一 approved plan hash 执行 `publish-root`、`publish-resolvers`、
`unbind-endpoints`、`bind-endpoints` 和 `revoke-removed`。版本 2 及以上计划必须
引用前一份已批准计划，才能计算被移除的 endpoint 和 resolver。最后一步以及
`revoke-resolver`/`revoke-root` 使用独立 Revoker 账户。链路主机不得保存任何写入
私钥。

## 文档

- [中文技术介绍](docs/项目技术介绍.md)
- [生产架构](docs/production_architecture.md)
- [Rust V2 实施状态](docs/rust_v2_implementation_plan.md)
- [星形域名中心部署](docs/star_topology_field_deployment.md)
- [星型多服务器完整现场手册](docs/runbooks/domain-center-star-multiserver-deployment.md)
- [星型多服务器部署规格](specs/domain-center-star-deployment/requirements.md)
- [真实服务器部署手册](docs/runbooks/real-server-deployment.md)
- [运行部署手册](docs/runbooks/production-deployment.md)
- [Sepolia 预发布部署](docs/runbooks/sepolia-preproduction-deployment.md)
- [Sepolia 部署规格](specs/public-testnet-preproduction/requirements.md)
- [多链 Registry 兼容层](docs/runbooks/multichain-registry-adapter.md)
- [多链适配器规格](specs/multichain-registry-adapter/requirements.md)
- [Knot Resolver Trace 运行手册](docs/runbooks/production-resolver-trace.md)
- [Knot Resolver Trace 规格](specs/production-resolver-trace/requirements.md)
- [生产就绪门禁](docs/production_readiness.md)
- [安全边界](docs/security_boundary.md)
- [V2 API](docs/api.md)

## 真实上线边界

仓库已具备 Rust V2 数据面和单链路集成基线，但真实生产上线仍必须完成现场 P0：

1. 现场 Resolver 必须使用已验收的 Knot Resolver 6.3.0 集成；其他 Resolver 需另行适配；
2. 部署真实 Registry 并拆分治理/发布/端点/撤销角色；
3. 独立核验 chain ID、contract address 和 runtime code hash；
4. 配置现场 TLS/mTLS、防火墙、日志和磁盘告警；
5. 完成真实备份恢复、撤销、故障和峰值容量演练。

普通 pcap、按时间/qname 关联的日志或没有上下文 ID 的 dnstap 不能作为“全路径已经
认证”的生产证据。上述现场门禁未关闭前，只能进入单链路集成和 shadow 阶段，不能
仅凭示例 Compose 宣称已完成真实生产上线。

## 目录

- `rust/`：Rust V2 数据面和测试
- `contracts/`：Solidity Registry 和 Foundry 测试
- `src/resolver_identity/`：Python V1/管理面
- `tools/`：发布、测试和运维工具
- `deploy/link/`：单链路 Rust 生产 profile
- `deploy/field/`：星型多服务器监控和日志模板
- `scripts/field/`：现场预检、运行包、启动、验收、备份和容量脚本
- `docs/`：当前 V2 架构、安全、部署和验收文档
