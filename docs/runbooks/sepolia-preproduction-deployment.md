# Sepolia 预发布部署手册

## 1. 适用范围

本手册用于把 `ResolverIdentityRegistryV1` 真实部署到 Ethereum Sepolia，
完成角色拆分、V2 身份发布、Rust Registry Sync 和 SQLite 验收。

Sepolia Registry 与链上查询闭环完成，不等于 DNS 全路径生产完成。公共
Root/TLD/Authority 未部署受控 Agent，或真实 Resolver Trace 插件未接入时，
必须使用 `public-hybrid` 并把数据面验收标为阻断。

2026-07-30 已通过 Ethereum 官方网络文档确认 Sepolia 仍受维护，并用两个
公共 RPC 实测 Chain ID 为 `11155111`。正式执行仍必须用部署方的两个独立
HTTPS RPC 重新核验。

## 2. 主机前置条件

- Linux x86_64，时间同步正常，磁盘至少预留 20 GiB。
- `git`、Rust/Cargo、Python 3、Foundry、Docker Engine/Compose。
- `jq`、`curl`、`sqlite3`、`openssl`、`sha256sum`、`dig`。
- 出站仅允许两个 RPC、Agent 上游和必要的 DNS 网络。
- 本机 `127.0.0.1:9108-9110` 不对外暴露。
- Registry Sync 镜像由本仓库固定基础镜像构建，不在脚本中在线执行安装器。

检查：

```bash
git status --short
git branch --show-current
git rev-parse HEAD
docker version
forge --version
cargo --version
python3 --version
```

## 3. 秘密和账户

创建本地目录：

```bash
mkdir -p secrets/sepolia deployments/sepolia/private
cp .env.sepolia.example .env.sepolia.local
chmod 600 .env.sepolia.local
chmod 600 secrets/sepolia/*
```

`.env.sepolia.local` 至少设置：

```dotenv
RI_TESTNET_RPC_URL=https://<primary-provider>
RI_TESTNET_VERIFY_RPC_URL=https://<independent-provider>
GOVERNANCE_ADDRESS=0x...

DEPLOYER_KEYSTORE_FILE=secrets/sepolia/deployer.json
DEPLOYER_KEYSTORE_PASSWORD_FILE=secrets/sepolia/deployer.password
GOVERNANCE_KEYSTORE_FILE=secrets/sepolia/governance.json
GOVERNANCE_KEYSTORE_PASSWORD_FILE=secrets/sepolia/governance.password
ROOT_PUBLISHER_KEYSTORE_FILE=secrets/sepolia/root-publisher.json
ROOT_PUBLISHER_KEYSTORE_PASSWORD_FILE=secrets/sepolia/root-publisher.password
RESOLVER_PUBLISHER_KEYSTORE_FILE=secrets/sepolia/resolver-publisher.json
RESOLVER_PUBLISHER_KEYSTORE_PASSWORD_FILE=secrets/sepolia/resolver-publisher.password
ENDPOINT_MANAGER_KEYSTORE_FILE=secrets/sepolia/endpoint-manager.json
ENDPOINT_MANAGER_KEYSTORE_PASSWORD_FILE=secrets/sepolia/endpoint-manager.password
REVOKER_KEYSTORE_FILE=secrets/sepolia/revoker.json
REVOKER_KEYSTORE_PASSWORD_FILE=secrets/sepolia/revoker.password

ISSUER_PRIVATE_KEY_FILE=secrets/sepolia/issuer-private.key
ISSUER_PUBLIC_KEY_FILE=secrets/sepolia/issuer-public.key
ISSUER_ID=<real-issuer-id>
ISSUER_KEY_ID=<real-key-id>
RI_UNSIGNED_IDENTITIES_SOURCE=deployments/sepolia/private/identities-v2.unsigned.json
```

六个 EVM 地址必须不同。Deployer 只部署；Governance 只治理；四个业务角色
分别签名。Issuer Ed25519 密钥不能复用任何 EVM 或 Agent 密钥。

当前自动写链路径使用加密 JSON keystore。生产多签或远程签名器应由治理
系统执行同一 calldata，并把最终交易收据导入证据清单，不能退回裸私钥。

## 4. 真实身份输入

参考：

```text
specs/public-testnet-preproduction/deployment-input.example.json
```

把真实 unsigned V2 身份保存到
`deployments/sepolia/private/identities-v2.unsigned.json`。要求：

- Endpoint 是真实预发布 DNS IP/端口，不是文档保留地址。
- Recursive/Forwarder 绑定真实 HTTPS Agent。
- 每个 Agent 使用独立、非零的 32 字节 Ed25519 公钥。
- `valid_from` 不晚于当前时间 5 分钟，`valid_until` 至少剩余 24 小时。
- Endpoint 全局唯一；anycast 字段一致；对象版本为正数。

## 5. 部署前测试

```bash
scripts/sepolia/01-test.sh
scripts/sepolia/00-preflight.sh
```

`00` 会从两个 RPC 实时读取 Chain ID、拒绝 Mainnet、核验 RPC 主机不同、
keystore 地址、角色分离和余额。默认最低余额是：

- Deployer：`0.02 ETH`
- Governance 和四个业务角色：各 `0.005 ETH`

这是预检下限，不是费用承诺。余额不足时先从正规 Sepolia faucet 获取测试
ETH，不购买或出售测试币。

## 6. 部署与 finalized 核验

```bash
scripts/sepolia/02-deploy-registry.sh
scripts/sepolia/04-verify-deployment.sh
```

部署构造参数固定为 `GOVERNANCE_ADDRESS`。`04` 最长等待 30 分钟，直到合约
runtime code 进入两个 RPC 的共同 finalized 高度，然后比较完整 bytecode、
code hash 和 block hash。

核对：

```bash
jq . deployments/sepolia/deployment.json
jq . deployments/sepolia/verification.json
```

不得从 Forge 控制台输出手抄地址。正式地址以双 RPC finalized 证据为准。

## 7. 角色拆分

```bash
scripts/sepolia/03-configure-roles.sh
jq . deployments/sepolia/roles.json
```

脚本幂等执行：

1. 给四个独立账户授予对应业务角色。
2. 从 Governance 撤销四种业务角色。
3. 用第二 RPC 验证 Governance 只保留管理员角色。
4. 验证 Deployer 没有业务角色。

第二 RPC 追块允许等待 180 秒。不得因为短时延迟跳过核验。

## 8. 身份签名和计划审批

```bash
scripts/sepolia/05-sign-identities.sh
scripts/sepolia/06-prepare-publication-plan.sh
jq . deployments/sepolia/plan-summary.json
```

把 `plan_hash`、`state_root`、身份数、Endpoint 数、解绑数和撤销数交给两个
独立复核人。批准后不要编辑 `registry-plan-v2.json`。重新执行：

```bash
PLAN_HASH="$(jq -r .plan_hash deployments/sepolia/registry-plan-v2.json)"
PYTHONPATH=src python3 - \
  deployments/sepolia/registry-plan-v2.json "$PLAN_HASH" <<'PY'
import sys
from pathlib import Path
from tools.manage_v2_registry import load_plan
load_plan(Path(sys.argv[1]), sys.argv[2])
PY
```

## 9. 五阶段发布

```bash
scripts/sepolia/07-publish-registry-plan.sh
jq . deployments/sepolia/publication-transactions.json
```

阶段固定为 Root、Resolver、解绑 Endpoint、绑定 Endpoint、撤销已移除
Resolver。每阶段重新检查网络、runtime code hash、角色和计划。收据增量写入
私有断点文件，完成后按交易哈希去重汇总；中断后可安全重跑。

## 10. 配置同步

补齐 `.env.sepolia.local` 的真实链路参数：

```dotenv
RI_AGENT_SERVER_ID=<server-id>
RI_AGENT_KEY_ID=<agent-key-id>
RI_TRACE_PRODUCER_UID=<resolver-process-uid>
RI_TRACE_PRODUCER_GID=<shared-socket-gid>
RI_TRACE_SOCKET_HOST_DIR=/run/resolver-identity/<link>
RI_WRAPPER_UPSTREAMS=udp://<real-resolver-ip>:53,tcp://<real-resolver-ip>:53
DNS_BIND_ADDRESS=<wrapper-service-ip>
DNS_PORT=53
```

执行：

```bash
scripts/sepolia/08-sync-runtime-config.sh
cd "$(git rev-parse --show-toplevel)"
sha256sum --check deployments/sepolia/runtime-files.sha256
```

实际 `.env` 含 RPC URL，只能保留在受控服务器且已被 Git 忽略。

## 11. Registry Sync

```bash
scripts/sepolia/09-run-registry-sync.sh
curl --fail http://127.0.0.1:9109/healthz
curl --fail http://127.0.0.1:9109/readyz
curl --fail http://127.0.0.1:9109/metrics
```

指标必须包含 Chain ID、Registry、runtime code hash、finalized 高度和哈希、
身份数、成功时间和失败数。日志证据保存在 Git 忽略的 private 目录。

## 12. Registry 和 SQLite 验收

```bash
scripts/sepolia/10-acceptance-test.sh
jq . deployments/sepolia/sqlite-verification.json
jq . deployments/sepolia/acceptance-results.json
```

脚本会停止 Sync、复制一致数据库、执行完整性和链固定值查询、重启并验证
高水位恢复。随后确认错误 Chain ID、错误合约、错误 code hash、错误 Issuer
和身份篡改均失败关闭。

只有真实 Trace 插件、mTLS、Token 全部就绪时才设置：

```dotenv
RI_RUN_FULL_DATA_PLANE=true
RI_ACCEPTANCE_DNS_NAME=<controlled-test-name>
RI_ACCEPTANCE_DNS_TYPE=A
```

再次执行 `10`，它才会按 Agent、Trace Adapter、Wrapper 顺序启动并进行
UDP/TCP DNS 查询。否则清单会保留明确的 DNS 数据面阻断项。

## 13. 撤销测试

专用测试 `server_id` 必须明显包含 `test`：

```dotenv
RI_REVOCATION_TEST_SERVER_ID=<dedicated-test-server-id>
RI_CONFIRM_REVOCATION_TEST=IRREVERSIBLY_REVOKE_SEPOLIA_TEST_IDENTITY
```

```bash
scripts/sepolia/11-revoke-test-identity.sh
```

撤销不可逆。恢复流程是生成不包含旧测试身份的新版本计划，必要时使用新的
`server_id`，完成 `05` 至 `07` 后执行：

```bash
scripts/sepolia/12-restore-test-state.sh
```

## 14. 日常检查

```bash
docker compose \
  --project-name ri-sepolia-preprod \
  --env-file deploy/link/.env \
  -f deploy/link/docker-compose.yml ps
curl --fail http://127.0.0.1:9109/readyz
curl --fail http://127.0.0.1:9109/metrics
sha256sum --check deployments/sepolia/runtime-files.sha256
```

监控至少告警：最后同步时间、失败数增长、finalized 高度停滞、磁盘余量、
容器重启、Wrapper SERVFAIL 比例、Trace spool 深度和证书到期时间。

## 15. 完成声明

`deployment-manifest.json` 只有在 `10` 完成后生成。所有链上字段有真实值、
Registry Sync/SQLite 和负向测试通过时，可以声明：

```text
Sepolia Registry 和链上查询闭环部署完成
```

只有数据面测试也为 `PASS` 时，才能进一步声明预发布 DNS 数据面闭环完成；
这仍不等同于域名中心正式生产验收。
