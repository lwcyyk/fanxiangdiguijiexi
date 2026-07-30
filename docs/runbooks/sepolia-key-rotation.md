# Sepolia 密钥轮换手册

## EVM 业务角色

为目标角色创建只用于 Sepolia 的新加密 keystore，确认地址不同且有测试
ETH。轮换顺序必须是“先授予、核验、再撤销”：

```bash
ROLE="$(cast keccak ROOT_PUBLISHER_ROLE)"
cast send "$REGISTRY_ADDRESS" 'grantRole(bytes32,address)' "$ROLE" "$NEW_ADDRESS" \
  --rpc-url "$RI_TESTNET_RPC_URL" \
  --keystore "$GOVERNANCE_KEYSTORE_FILE" \
  --password-file "$GOVERNANCE_KEYSTORE_PASSWORD_FILE"
cast call "$REGISTRY_ADDRESS" 'hasRole(bytes32,address)(bool)' "$ROLE" "$NEW_ADDRESS" \
  --rpc-url "$RI_TESTNET_VERIFY_RPC_URL"
```

新地址完成一次受控操作验证后，再撤销旧地址并通过第二 RPC 确认为 `false`。
更新 `.env.sepolia.local`，重跑角色脚本以刷新公开证据。旧 keystore 进入
受控归档，不删除事故审计所需材料。

## Governance

合约禁止撤销最后一个管理员。Governance 轮换：

1. 现管理员向新 Governance 授予 `DEFAULT_ADMIN_ROLE`。
2. 第二 RPC 确认 `adminCount >= 2` 且新地址持有管理员角色。
3. 新 Governance 完成一笔独立核验操作。
4. 新 Governance 撤销旧管理员。
5. 确认新 Governance 不长期持有四个业务角色。

生产应使用多签/HSM；测试网 EOA 是明确的预发布差距。

## Issuer Ed25519

Issuer 轮换不是替换公钥文件即可。必须：

1. 离线生成新 Ed25519 密钥和新 `key_id`。
2. 先向公钥束加入新公钥，保留仍在有效身份中引用的旧公钥。
3. 所有身份提高 `object_version`，改用新 `key_id` 重新签名。
4. 使用上一计划生成更高 Root version，完成五阶段发布。
5. Registry Sync/SQLite 验收通过后再切换运行制品。
6. 旧身份全部过期或撤销后才从信任束移除旧公钥。

Issuer 私钥不得进入链路服务器。

## Agent Ed25519

每个 Agent 独立轮换：

1. 在 Agent 主机生成新密钥，私钥权限 `0600`。
2. 提高对应身份对象版本并更新 `agent.key_id/public_key`。
3. 签名、发布、同步新身份。
4. 确认 Agent 使用新私钥且 readiness 正常。
5. 完成正向和错误旧签名测试后销毁旧运行副本。

## mTLS

新旧证书应短暂重叠。先部署新 CA/客户端信任，再轮换服务端证书，最后移除
旧信任。每一步都测试 Agent、Trace Adapter 和 Wrapper 双向认证；不得通过
关闭证书校验恢复服务。
