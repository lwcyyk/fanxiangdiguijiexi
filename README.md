# 基于区块链带外身份索引的递归解析器身份认证

本仓库实现一套应用层递归解析器身份认证系统，并提供本地 Web3 多解析器测试环境和单机生产部署基线。

目标：在不修改 DNS 协议、DNS 报文格式或操作系统网络栈的前提下，通过应用层本地 DNS 验证封装器、链下 SQLite Indexer、本地可信缓存与链上可信锚，验证递归解析器身份后再释放 DNS 响应。

## 当前实现状态

当前主闭环支持本地 Web3/Anvil E2E；生产严格模式使用外部 EVM Registry、Ed25519、逐请求 challenge、Agent TLS/mTLS 和受保护管理面：

```text
client
  -> local-wrapper
  -> resolver-r1
  -> resolver-r2
  -> authoritative/external DNS
```

正常 DNS 查询链路保持不变；带外身份认证链路采用“逐跳分布式认证 + 结果向上汇总”模型：

1. wrapper 只直接认证第一跳 R1 的 identity object、Merkle proof、链上 anchor、endpoint binding 和 root status；
2. wrapper 从已验证 R1 identity object 中读取 R1 Agent Ed25519 public key；
3. wrapper 调用 R1 Agent 的 `/v1/verification-chain`，验证 R1 对整条链路摘要的签名；
4. R1 Agent 只负责发现并认证自己的相邻上游 R2：R1 Agent 查询 Indexer/Registry，验证 R2 identity object，并签名 `R1 -> R2` 的 `HopVerificationResult`；
5. 如果 R2 还有递归上游，R1 Agent 调用 R2 Agent；R2 Agent 同样只认证自己的相邻上游 R3，并返回签名链路结果；
6. 认证结果按 `R3 -> R2 -> R1 -> wrapper` 方向回传，每一级 Agent 都签名自己的 hop result 和 chain summary；
7. wrapper 验证 R1 Agent 签名、每一级 downstream chain 签名、每个 hop 的 `VERIFIED` 状态和链路完整性；
8. 全部 hop 均通过认证才释放原始 DNS 响应，否则返回 SERVFAIL。

系统不会猜测不可观测的隐藏中间解析器，也不会修改 DNS 报文。

## 已实现能力

- `ResolverAuthenticityObjectV1` 身份对象模型
- canonical JSON、object hash、lookup key
- 开发兼容 HMAC 与生产 Ed25519 签名/验签；生产模式强制禁用 HMAC
- Agent Ed25519 public key 绑定到 resolver identity object
- SQLite Indexer：保存完整对象、lookup index、Merkle proof、缓存、审计
- Solidity `ResolverIdentityRegistryV1`
- `Web3RegistryBackend`：读取/写入 Anvil 或外部 EVM 合约，并固定 chain ID 和 runtime code hash
- `AdminPublisher`：发布 root、resolver anchor、endpoint binding
- `ResolverVerifier`：fail-closed 身份认证
- trusted cache：cold/hot path、TTL、撤销失效
- `EventWatcher`：Web3 event polling、reorg rollback、漏事件 reconcile
- UDP/TCP DNS wrapper 与本地 DoH route
- Resolver Identity Agent：身份、upstream、challenged verification chain、健康和深度就绪接口
- 逐跳分布式 Agent 链路认证：每级 Agent 只认证相邻 upstream，并签名 `HopVerificationResult` / `VerificationChain`
- Docker Compose 多服务 E2E：Anvil、R1、R2、Agent、Indexer、event-watcher、wrapper
- 生产加固：Web3 超时与合约字节码哈希固定、Agent TLS/mTLS、幂等发布恢复、SQLite 在线备份/版本检查、深度就绪探针、SBOM 与非 root 镜像门禁

## 安装与测试

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,web3]'
```

基础验证：

```bash
python3 -m compileall src tests tools
python3 -m pytest tests -q
cd contracts && forge test -vvv
```

生产部署使用严格模式、外部 EVM Registry、Ed25519 issuer 信任包、请求 challenge、持久化撤销代次和受保护管理面。入口文档：

- `docs/api.md`
- `docs/production_architecture.md`
- `docs/runbooks/production-deployment.md`
- `docs/production_readiness.md`
- `docs/production_simulated_execution.md`
- `docs/security_boundary.md`
- `docs/security_attack_experiment_report.md`
- `docker-compose.production.yml`

准备生产密钥材料：

```bash
PYTHONPATH=src python3 tools/prepare_production.py
```

生成后必须编辑 `.env.production` 并完成 readiness checklist；示例值不能用于真实流量。

Docker Compose Web3 多解析器端到端：

```bash
cd /home/lwc/fanxiangdiguijiexi
python3 tools/run_multi_resolver_e2e.py
```

该 E2E 会自动：

- 启动 Anvil、CoreDNS R1/R2、Agent、Indexer、event-watcher、wrapper；
- 部署 `ResolverIdentityRegistryV1`；
- 动态写入 Web3 合约地址；
- 使用 `Web3RegistryBackend` 发布 R1/R2 身份和 endpoint binding；
- 通过 UDP/TCP 查询 `example.test A`；
- 验证 R1/R2 均可信时返回 `203.0.113.10`；
- 验证 R1/R2 未登记、Agent 错误、Agent 不可用、签名错误、链上撤销、root 撤销等场景均返回 SERVFAIL。

## 本地运行组件

发布 demo resolver 身份：

```bash
PYTHONPATH=src python3 -m resolver_identity.admin.cli publish-demo \
  --resolver-id operator-a/resolver-01 \
  --ip 1.1.1.1 \
  --transport udp
```

启动 Indexer API：

```bash
PYTHONPATH=src python3 tools/run_indexer.py --port 8001
```

启动 Admin API：

```bash
PYTHONPATH=src python3 tools/run_admin.py --port 8002
```

启动 Wrapper HTTP API / 本地 DoH：

```bash
PYTHONPATH=src python3 tools/run_wrapper_api.py --port 8000
```

启动 UDP/TCP DNS wrapper：

```bash
PYTHONPATH=src python3 tools/run_wrapper.py --udp-port 1053 --tcp-port 1053
```

启动 Resolver Identity Agent：

```bash
PYTHONPATH=src RESOLVER_IDENTITY_AGENT_PRIVATE_KEY_B64=<base64-raw-ed25519-private-key> \
python3 tools/run_agent.py --port 8010
```

## Agent 信任模型

Agent 响应不是自证可信。wrapper 只直接信任“已验证 R1 identity object 绑定的 R1 Agent public key”所能验证的 R1 Agent 输出：

1. R1 endpoint 已通过链上/Indexer 身份认证；
2. R1 resolver identity object 的 `attestation.agent.public_key` 绑定了 R1 Agent Ed25519 public key；
3. 生产 Wrapper 通过 `POST /v1/verification-chain` 发送随机 challenge，R1 Agent 响应用对应私钥签名；
4. R1 Agent 返回的 `VerificationChain` 中，`R1 -> R2` 的 `HopVerificationResult` 也由 R1 Agent 签名；
5. 每个 downstream chain 必须能由上一级已验证 hop evidence 中携带的 Agent public key 验签；
6. 每个 Agent 只认证自己的相邻上游 resolver，不由 wrapper 代替所有 resolver 做递归认证；
7. endpoint、resolver_id、issued_at、expires_at、health/config version 和 chain loop/max-depth 检查均通过。

任一条件失败，链路认证失败，DNS 响应不放行。

## 运行实验

```bash
PYTHONPATH=src python3 tools/run_experiments.py all
```

可单独运行：

```bash
PYTHONPATH=src python3 tools/run_experiments.py functional
PYTHONPATH=src python3 tools/run_experiments.py malicious
PYTHONPATH=src python3 tools/run_experiments.py tamper
PYTHONPATH=src python3 tools/run_experiments.py replay
PYTHONPATH=src python3 tools/run_experiments.py cache --iterations 100
PYTHONPATH=src python3 tools/run_experiments.py revoke
PYTHONPATH=src python3 tools/run_experiments.py root-revoke
PYTHONPATH=src python3 tools/run_experiments.py multi
PYTHONPATH=src python3 tools/run_experiments.py oob
```

## 边界与限制

- 不修改 DNS 协议和 DNS 报文格式。
- 不修改系统 DNS 配置。
- 仓库不附带真实 EVM 部署；生产运营方必须部署合约并独立核验 chain ID、地址和 runtime code hash。
- 不引入 DNSSEC、TPM、TEE 或查询证明。
- 不证明权威 DNS 的真实性。
- 不阻止“已合法登记但恶意返回错误答案”的 resolver。
- 不猜测不可观测或不合作的隐藏中间解析器。
- 当前生产 profile 是单机 SQLite，不支持多主机共享、水平扩容或高可用。

## 目录

- `contracts/` — Solidity 合约与 Foundry 测试
- `src/resolver_identity/` — Python 实现
- `tests/` — 单元/集成/实验测试
- `tools/` — 本地演示与 E2E 脚本
- `docs/` — 当前 API、安全边界、生产架构、验收和运维文档
