# 域名中心星型多服务器部署验收

## 1. 本地工程门禁

- [x] 现场清单模板通过模板校验但不能通过真实部署校验
- [x] 真实校验拒绝 Mainnet、零值、示例地址、占位值和移动镜像标签
- [x] 多链路运行包保持独立 `.env`、secret、TLS、Socket、project 和 volume
- [x] SHA-256 清单能够发现任意运行包文件篡改
- [x] Agent 私钥导出公钥与签名 identity 一致
- [x] 双 RPC、角色、发布计划和五阶段交易证据必须相互一致
- [x] TLS CA 链、证书密钥配对和 Agent service URL SAN 进入运行包门禁
- [x] Python、Rust、Solidity 和 Shell 检查通过
- [x] Docker 镜像构建和 Compose 配置通过
- [x] Git 跟踪文件不包含私钥、Token、密码或真实 RPC 凭据

## 2. Hub 验收

- [ ] 镜像固定到批准 commit 和 digest
- [x] Registry 经两个独立 RPC finalized 核验
- [x] 五类角色拆分，Deployer 不持有角色
- [ ] identity、Root、Endpoint 和撤销状态与 finalized 状态一致
- [ ] 发布包在 Hub 和目标主机的 SHA-256 一致
- [ ] Prometheus、日志、备份和审计责任人明确

## 3. 每条链路验收

- [ ] 容器 UID 10002、只读文件系统、能力删除和日志轮转有效
- [ ] Wrapper 服务 IP/VIP 与 Resolver upstream 不形成环路
- [ ] Registry Sync `/readyz` 和 SQLite 快照核验通过
- [ ] Agent mTLS、三类 Token 和交叉拒绝测试通过
- [ ] Trace Socket UID/GID、pending、dead-letter 和重启续传通过
- [ ] 真实 Trace 提供可靠 `trace_id`、`correlation_id` 和
  `target_correlation_id`
- [ ] Wrapper `/readyz`、UDP 和 TCP Shadow 通过
- [ ] 冷缓存、热缓存和 R1→R2（如适用）通过
- [ ] Trace/Agent/Registry/证书/Token/撤销/解绑负向测试均失败关闭
- [ ] 跨链路 Resolver、Agent、SQLite 和 metrics 被明确拒绝

## 4. 运维验收

- [ ] Wrapper、Agent、Registry Sync、Trace Adapter 指标已采集
- [ ] 磁盘、inode、文件描述符、时间同步和容器重启已采集
- [ ] readiness、SERVFAIL、staleness、spool、dead-letter 和磁盘告警已触发
- [ ] evidence 和 trace spool 在线备份完成
- [ ] 异机隔离恢复和 `PRAGMA integrity_check` 完成
- [ ] 峰值 1.5 倍 QPS、UDP/TCP、最大包、链深和故障注入容量测试完成
- [ ] VIP 回滚在批准 RTO 内完成
- [ ] A/B 单元不共享 SQLite

## 5. 当前执行结果

执行时间：2026-07-30

| 项目 | 结果 |
| --- | --- |
| Python/Ruff | `151 passed`，Ruff 通过；2 个第三方弃用提示 |
| Rust | 41 个测试通过，1 个手工 release 容量基线 ignored；fmt/clippy 通过 |
| Solidity | 14/14 通过；保留 2 个 `block.timestamp` 预期 lint 提示 |
| Shell | ShellCheck 0.9.0 和 `bash -n` 通过 |
| Docker | 镜像 `sha256:33b92d4f6716feb7cee23c2cf78894f6882e59db86f956f6440bdb0be6b74698` 构建通过 |
| Compose | 四服务配置通过，日志上限均为 `50m × 5` |
| 双链路包 | L01/L02 独立 CA、证书、秘密、Compose 和 SHA-256 核验通过 |
| 供应链负向 | 占位值、Mainnet、文档 IP、回路、秘密复用、符号链接和篡改均被拒绝 |
| Sepolia 状态 | [ethereum.org 网络文档](https://ethereum.org/developers/docs/networks/)仍列为维护中的应用开发测试网；两个公共 RPC 实测 chain ID 均为 `11155111` |
| Sepolia Registry | PASS：`0x519c70babf33771b8e87c22fd3e2e1b1092e1e2a` |
| Runtime code hash | PASS：`0x3ff1c0bc964b2751a4006fa9bc54f8a1e1bb04872f62fabaf3eef52132e0a2d3` |
| 五类角色 | PASS：8 笔交易成功，双 RPC finalized 区块 `11380411` |
| 2026-07-30 重复只读复核 | PARTIAL：Chain ID/finalized 可读；免费 RPC 在连续读取中出现 TLS EOF/HTTP 500，新增有界重试并要求现场使用两路有 SLA 的 RPC |
| Root/identity/Endpoint | BLOCKED：缺少真实 DNS Endpoint、Agent URL 和 Agent 公钥 |
| 现场正式预检 | 失败关闭：缺少私有 `site-inventory.json` |

Registry 合约证据位于 `deployments/sepolia/`。第 2 节剩余发布项以及第 3-4 节
仍需要真实 identity、Hub、链路服务器、Resolver Trace、证书和网络证据，因此保持
未勾选。
