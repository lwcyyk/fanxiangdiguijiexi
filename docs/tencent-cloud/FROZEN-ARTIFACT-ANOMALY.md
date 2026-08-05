# 冻结发布工件缺陷报告（core program anomaly）

- **日期**: 2026-08-05
- **发布**: resolver-identity 0.3.0-norn-knot-rc1（release candidate）
- **冻结源码提交**: `928ed0e69fcf71149f4e224124b6a21e7c34aca0`（未改动）
- **部署目标**: 腾讯云 2C/2GiB 研究实验室（7 台主机）
- **结论**: **STOP（core program anomaly）** —— 冻结的 Rust OCI 镜像中 `ri-agent`（以及同工作区构建的 `ri-wrapper`）二进制在启动时**确定性 panic**，导致任一解析节点（R1/R2/R3）无法被 wizard 激活，正向 DNS 端到端验证与 fail-close 验证在该冻结工件下**不可达成**。

## 1. 现象（经验证据）

在真实部署的 `ri-r3` 上，wizard `activate` 于 `agent_trace_ready` 门禁超时（RUN002 → E004），`current` 指针回滚，状态保持 `staged`。

部署中的 `ri-r3-agent-1` 容器持续崩溃循环：

```
restarts=19  exit=101
thread 'main' (1) panicked at
 /usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.42/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually,
or make sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
```

每次重启 panic 完全相同（确定性，非 OOM、非环境抖动）。

## 2. 根因

1. **源码**：`rust/crates/ri-agent/src/main.rs:246` 使用 `rustls::ServerConfig::builder()`（默认 provider 路径），全文件无 `CryptoProvider::install_default()`。`ri-wrapper` 同构（客户端 `ClientConfig::builder()`）。
2. **构建配置**：`docker/Dockerfile.rust` 执行 `cargo build --locked --release --workspace`。Cargo workspace 特性统一（feature unification）会把 `tonic` 的 `tls-ring`（→ `ring`）与 `rustls` 默认特性（→ `aws-lc-rs`）同时带入单一 `rustls` crate。
3. **依赖图**：冻结提交的 `rust/Cargo.lock` 中同时存在 `ring` 与 `aws-lc-rs`，`rustls = 0.23.42`。二者皆被特性启用时，rustls 0.23 的进程级 CryptoProvider 自动选择在 `crypto/mod.rs:249` **确定性 panic**（这正是 rustls 0.23 的明确行为）。
4. **镜像内容**：本地标签 `offline/resolver-identity/rust:ri-68ec104256119bd3`，原始 OCI manifest digest `sha256:68ec104256119bd3cee736bc2ebb1f327370d31df3598606d7668ce84eda7244`，配置 digest `sha256:3e4a31ccd54b799c67449342f9dd4225599cdc02bb18d81cf365f739456a366f`，归档 `rust.oci.tar` sha256 `34471fee2b260fa3d496a454298ef2881d27c4460b1991ee29ab19b5c4ca5b28`。仅存在此一个 rust 归档，无替代工件。

## 3. 为何冻结时的“通过”从未暴露该缺陷

- 冻结验收脚本 `tools/run_norn_field_acceptance.py` 的 `execute()` **从不执行 DNS 查询**。
- `start_agents_and_check_boundaries` **仅 docker-inspect 容器配置**（对崩溃循环容器同样“通过”）。
- 因此“agent 可启动并对外提供 `:8443/readyz`”从未被冻结验收所要求，缺陷被冻结进发布。

## 4. 影响面

- wizard 激活门禁 `agent_trace_ready`（lifecycle.py：probe `https://<RI_FIELD_HOST_ID>:8443/readyz`）**无法满足** → 任何解析节点不能进入 `complete`。
- 进而：R1 wrapper 首次跃点验证、R1→R2→R3 agent 链式验证、client→R1→R2→R3→AuthDNS 正向 e2e、最小 fail-close 场景，**均不可执行**。
- 数据面（解析链路）整体不可用；控制面（norn 双节点、管理端注册链、测试权威 DNS）已验证可用。

## 5. 处置

按既定工作风格，命中 `core program anomaly` 停止条件：**停止自动执行流水线，如实报告，不修改冻结核心逻辑、不重建 OCI 归档、不降级/绕过 readiness 门禁**。

已完成的其余部署状态见 `evidence/tencent-cloud/runtime/deployment-state.json`；本缺陷的经验证据见 `evidence/tencent-cloud/runtime/core-program-anomaly-agent-rustls.md`。

## 6. 建议修复（超出本次部署范围，供参考）

在后续（非冻结）构建中任选其一，并在该修复发布后重新构建 rust 镜像、重做 `activate`：

- 方案 A（最小）：在 `ri-agent`/`ri-wrapper` 的 `main()` 最前 `CryptoProvider::install_default(rustls::crypto::ring::default_provider())`（或 aws-lc-rs），消除默认 provider 自动选择歧义。
- 方案 B：`docker/Dockerfile.rust` 改为按 crate 构建（`--workspace --exclude` 或逐 crate），避免 tonic `tls-ring` 把 `ring` 灌入共享 `rustls`。
- 方案 C：移除 tonic 的 `tls-ring` 特性，仅保留单一 provider。

修复后的重放路径已就绪（无返工）：R1/R2/R3 的云绑定主机包、preflight、OCI 导入、渲染配置、注册表签名身份材料均已就绪，重新执行 `deploy/tencent-cloud/scripts/setup-resolver.sh <r1|r2|r3> activate` 即可。
