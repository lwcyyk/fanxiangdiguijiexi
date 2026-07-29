# Rust V2 生产就绪门禁

所有方框必须由真实现场证据关闭。示例配置、模拟日志或本机 Anvil 结果不能代替。

## P0

- [ ] 现场 Resolver 插件生成可靠内部 `trace_id`，按规范生成 `correlation_id` 和
  `target_correlation_id`，并通过并发相同报文、缓存和重试测试。
- [ ] Root、TLD、Authority 事件来自实际 socket 目标，不是静态配置推测。
- [ ] `public-hybrid` 的 DNSSEC 状态来自验证型 Resolver。
- [ ] 所有 Recursive/Forwarder 有 Agent；受控严格模式下所有 Authority 也有 Agent。
- [ ] Registry 已部署，chain ID、address、runtime code hash 由两人通过独立路径核验。
- [ ] Governance、Root Publisher、Resolver Publisher、Endpoint Manager、Revoker
  使用独立账户；链路主机没有写入私钥。
- [ ] 初始治理账户的 Root/Resolver/Endpoint/Revoker 业务角色已撤销，并从第二 RPC
  逐项核验 `hasRole`。
- [ ] 三个发布角色确认同一 `registry-publication-plan-v2` hash，且计划固定的
  chain ID/address/runtime code hash 与实时后端一致。
- [ ] Root 版本 2 及以上计划引用前一份已批准计划；旧 endpoint 已解绑，被移除的
  resolver 已由独立 Revoker 撤销，五阶段执行记录完整。
- [ ] Agent、Wrapper、Trace Adapter 和相邻 Agent mTLS 正向/反向测试通过。
- [ ] Wrapper、peer Agent、Trace 三类 token 各自独立，交叉调用均返回 401；各容器
  只能读取自身私钥文件。
- [ ] L01/L02/L03 防火墙默认拒绝，跨链路 Resolver/Agent/SQLite 实测不可达。
- [ ] Rust CI、Python 兼容测试、Foundry、Compose 和非 root 镜像门禁全部通过。
- [ ] UDP/TCP 正向查询通过；未知身份、错误签名、Trace 缺失、Agent 停止、撤销、
  Root 撤销、endpoint unbind、环路和超深均返回 `SERVFAIL`。
- [ ] Prometheus、Alertmanager、集中日志、主机磁盘和容器重启告警已触发验证。
- [ ] Wrapper/Registry Sync/Trace Adapter 的 `9108/9109/9110` 指标已采集，Agent
  `/metrics` 使用 mTLS 采集；Trace dead-letter 告警和处置流程已演练。
- [ ] evidence 与 Trace spool SQLite 在线备份、校验、异机恢复和恢复后续传/撤销
  同步演练完成。
- [ ] 按现场峰值 QPS、最大包、TCP 比例、链深、冷/热缓存完成容量测试。
- [ ] DNS VIP 回滚在规定 RTO 内完成，未使用关闭验证作为回滚手段。

## 立即阻断上线

- Trace 通过时间窗口、qname、最新相同摘要或 pcap 猜测关联；
- 公共 Anycast 被描述为已认证具体物理服务器；
- example/zero 地址、占位公钥、共享 Agent 私钥或共享 TLS 证书仍存在；
- Agent URL 使用未认证 HTTP；
- Wrapper/peer/Trace token 复用，或 peer token 跨独立链路复用；
- SQLite 被多主机或多个写入单元共享；
- Registry code hash、chain ID、对象 hash、Root 或 endpoint 任一不一致；
- Wrapper `/readyz` 非 2xx；
- 负向测试泄漏原始 DNS 响应；
- 没有磁盘余量告警、备份恢复证据或峰值容量结果。
- Trace socket 主机目录未使用预期 producer GID/setgid 权限，或 dead-letter
  未监控、未清零且没有批准的处置记录。

## 当前仓库状态

Rust 数据面和自动化测试基线已实现。真实 Resolver Trace 插件、真实链和角色账户、
现场证书/防火墙/监控、备份恢复与容量数据仍是现场 P0。因此仓库代码可以进入
单链路集成和 shadow 阶段，但不能仅凭当前仓库宣称已经完成真实生产上线。
