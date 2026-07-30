# Sepolia Registry 重新发布手册

## 适用场景

- 新增、更新或移除 Resolver。
- Endpoint 迁移。
- Issuer/Agent 密钥轮换。
- 身份有效期续期。
- 前一次撤销测试后的新身份集合。

## 准备变更

从当前已批准的签名身份复制到 private 工作区。更新时：

- 已存在 Resolver 的 `object_version` 必须增加。
- `valid_until` 必须仍在未来。
- Endpoint 不能被两个 Resolver 共享。
- 移除 Resolver 前确认撤销不可逆。
- 被撤销的 `server_id` 永远不能复用。

设置：

```dotenv
RI_UNSIGNED_IDENTITIES_SOURCE=deployments/sepolia/private/identities-v2.unsigned.json
RI_PREVIOUS_PLAN_FILE=deployments/sepolia/archive/<old-plan>.json
RI_ROOT_VERSION=<old-root-version-plus-one>
```

先把当前公开计划复制到只读归档并记录 SHA-256。

## 生成和审批

```bash
scripts/sepolia/05-sign-identities.sh
scripts/sepolia/06-prepare-publication-plan.sh
jq . deployments/sepolia/plan-summary.json
```

独立复核：

- target Chain ID/合约/code hash；
- previous plan hash；
- Root version 和 state root；
- 每个对象版本/hash/有效期；
- Endpoint 解绑/绑定差集；
- Resolver 撤销清单。

批准后冻结计划文件。

## 发布

```bash
scripts/sepolia/07-publish-registry-plan.sh
scripts/sepolia/08-sync-runtime-config.sh
scripts/sepolia/09-run-registry-sync.sh
scripts/sepolia/10-acceptance-test.sh
```

发布工具幂等，但不得改变阶段顺序。失败交易必须先分析原因；不能跳到下一
阶段。完成后保存新计划、交易、runtime hash 清单和最终 SQLite 证据。

## 失败处理

- Root 已发布但 Resolver 阶段失败：修复签名账户/余额后重跑同一批准计划。
- Endpoint 冲突：不要强制覆盖；确认旧 owner 并用计划内解绑动作处理。
- 对象已永久撤销：创建新 `server_id` 和新身份，重新审批。
- runtime code/Chain ID 变化：立即停止，按事故响应流程处理。
