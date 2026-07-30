# 域名中心星型多服务器部署任务

## A. 规格与仓库审查

- [x] 核对当前分支、提交和工作区
- [x] 核对单链路 Compose、Rust 数据面和 Sepolia Registry 自动化
- [x] 记录 `main` 跟踪 `origin/master` 的分支名称差异
- [x] 编写需求、设计、任务、清单模板、验收和安全规格

## B. 清单和运行包

- [x] 实现结构化现场清单校验器
- [x] 实现占位值、Mainnet、零地址、文档 IP 和 upstream 回路拒绝
- [x] 实现 unit/project/server ID/Socket/端口唯一性校验
- [x] 实现秘密权限和跨链路复用检查
- [x] 实现每个链路单元的独立运行包生成
- [x] 实现运行包 SHA-256 清单和二次核验
- [x] 为校验器和生成器增加单元测试

## C. 现场自动化

- [x] 增加现场预检脚本
- [x] 增加运行包渲染和验证脚本
- [x] 增加链路主机本地安装脚本
- [x] 增加 Registry Sync → Agent/Trace → Wrapper 分阶段启动脚本
- [x] 增加 readiness、SQLite 和 UDP/TCP Shadow 验收脚本
- [x] 增加跨链路隔离测试脚本
- [x] 增加 SQLite 在线备份和隔离恢复演练脚本
- [x] 增加基于现场目标的容量测试脚本
- [x] 增加证据汇总脚本

## D. 运维配置

- [x] 为 Compose 增加有限 Docker 日志轮转
- [x] 增加 Prometheus 采集模板和核心告警规则
- [x] 增加主机磁盘、inode 和容器状态告警要求
- [x] 增加现场防火墙矩阵和服务器登记模板

## E. 文档

- [x] 编写星型多服务器完整现场部署与验收手册
- [x] 修正手工命令与现有 Sepolia 自动化之间的重复或不安全用法
- [x] 说明直接迭代、R1→R2、public-hybrid 和 controlled-strict 的边界
- [x] 说明 Shadow、容量、切流、回滚、备份恢复和 A/B 完整单元高可用

## F. 本地执行与验证

- [x] 校验清单模板
- [x] 用临时测试材料生成并核验多链路运行包
- [x] 执行 Python 单元测试和 Ruff
- [x] 执行 ShellCheck
- [x] 执行 Rust fmt/test/clippy
- [x] 执行 Foundry fmt/build/test
- [x] 构建 Rust 镜像并校验单链路 Compose
- [x] 扫描 Git 跟踪文件，确认无秘密进入仓库

## G. 真实现场执行

- [ ] 获得真实服务器/IP/VIP/Resolver/SSH 清单
- [ ] 获得真实 TLS、Agent 私钥、三类 Token 和身份制品
- [ ] 完成公共测试网 Registry、角色和身份发布
- [ ] 在 Hub 安装镜像、监控、日志和备份目标
- [ ] 部署 L01 并接入真实 Resolver Trace
- [ ] 完成 L01 正向、负向、容量、备份恢复和回滚
- [ ] 独立复制 L02/L03 并验证跨链路拒绝
- [ ] 按 1% → 10% → 50% → 100% 切流
- [ ] 建设每条链路 A/B 完整单元

> G 组任务只有获得真实现场连接、证书、身份和网络输入后才能完成；本地不得用
> 示例值勾选。
