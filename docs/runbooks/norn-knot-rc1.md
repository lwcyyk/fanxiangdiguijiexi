# Go-Norn + Knot Resolver RC1 验收手册

整体版本：`0.3.0-norn-knot-rc1`。

本候选版本由多链 Registry 适配层、Go-Norn 六服务器交付包和 Knot Resolver 6.3.0
内部 Trace 组成。Registry Sync 是唯一 Norn 客户端；Wrapper 与 Agent 只读取本机
可信 SQLite。R1 使用 `first-hop`，R2/R3 使用 `upstream` 且不启动 Wrapper。

最终验收顺序：

1. 在 Source Commit 运行 Rust、Python、Foundry、六套 Compose 和依赖审计。
2. 从零运行多链 Norn 双节点验收。
3. 使用 Knot Resolver 6.3.0、固定上游 Commit 和 128 并发运行真实 Trace 验收。
4. 将该 Trace 证据传给六服务器现场交付验收，生成五个镜像 digest 和三个安装包。
5. 运行 `tools/finalize_norn_knot_rc.py finalize`，扫描包、示例配置、验收和 Manifest。
6. 创建 Evidence Commit 后运行 `verify-evidence-diff`，禁止业务源码在验收后变化。

Manifest 中的 `real_server_deployed=false` 和
`production_traffic_enabled=false` 在现场 Shadow 验收与正式变更审批前不得修改。
