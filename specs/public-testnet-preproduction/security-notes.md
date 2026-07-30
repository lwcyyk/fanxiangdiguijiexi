# Sepolia 预发布安全说明

## 秘密边界

- 私钥、助记词、keystore 密码、RPC Key、Token 和 mTLS 私钥不得进入 Git。
- 裸私钥不得作为命令行参数或普通 `.env` 值传递。
- 自动化优先使用硬件/远程签名器；当前仓库脚本的自动执行路径使用加密
  JSON keystore 和权限为 `0600` 的密码文件。
- EVM 账户与 Issuer/Agent Ed25519 密钥相互独立。
- 测试网账户和密钥不得在 Mainnet 复用。
- 实际秘密只允许存放在 `.env.sepolia.local`、`secrets/sepolia/`、
  `deployments/sepolia/private/` 或宿主机秘密管理系统。

## RPC 安全

- 两个 RPC 必须使用 HTTPS、不同主机和独立提供方。
- 每次写操作前实时读取 `eth_chainId`，Chain ID `1` 无条件拒绝。
- 已知 Sepolia Chain ID 只作为期望值；不能代替实际 RPC 查询。
- 清单只记录 RPC 主机名，URL 路径、查询参数、用户信息和 API Key 全部省略。
- 公共免费 RPC 只适合预检，不能视为可用性或速率 SLA。

## 权限安全

- Governance、四个业务角色和 Deployer 地址必须相互分离。
- Deployer 不接收业务角色；Governance 在授权后撤销自身四类业务角色。
- 若 Governance 暂用 EOA，必须记录为预发布差距；生产应迁移至多签/HSM 或
  有审计能力的远程签名系统。
- Revoker 操作不可逆。撤销测试只能使用专门创建的测试身份。

## 身份安全

- Issuer 私钥只离线签名，链路主机只保存公钥束。
- Recursive/Forwarder 必须绑定使用独立 Ed25519 密钥的 HTTPS Agent。
- 禁止文档保留地址、`example.invalid`、零公钥和示例身份进入真实计划。
- Endpoint 必须唯一归属；有效期、版本和 anycast 字段必须自洽。

## 测试网与生产差距

- Sepolia ETH 没有资产价值保证，不能购买、出售或与生产资金混用。
- Sepolia 的验证者集合、重组风险、RPC 限额和可用性不代表生产环境。
- 测试网 Governance EOA 不等同于生产多签。
- `public-hybrid` 只核验可登记服务身份和 DNSSEC/现有信任边界；没有在公共
  Root/TLD/Authority 实例部署 Agent 时，不能宣称物理实例全路径认证。
- 域名中心上线还需要真实 Trace 插件、mTLS PKI、防火墙、监控、备份恢复和
  峰值容量测试，Sepolia 链上闭环不能替代这些验收。

## 当前输入审计

2026-07-30 检查当前进程环境时，用户列出的 RPC、Governance、五个 keystore、
Issuer 密钥和 Explorer API Key 均未设置。该事实只记录“是否存在”，未读取
或打印任何秘密内容。真实部署在这些输入具备前保持阻断。
