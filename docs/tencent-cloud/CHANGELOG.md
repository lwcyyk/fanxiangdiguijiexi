# 变更日志（腾讯云研究实验室部署）

按时间顺序记录腾讯云 resolver-identity 研究实验室的部署变更。RC1 发布物在
`deploy/tencent-cloud/packages/resolver-identity-domain-center-easy-install-0.3.0-norn-knot-rc1/`
保持冻结、逐字节不变；RC2 是新增交付目录，不覆盖 RC1。

## 0.3.0-norn-knot-rc2（2026-08-05）

**修复**（`fix/rustls-crypto-provider-rc2` 分支，提交 `fc6cc19`）：

- `ri-agent`、`ri-wrapper` 在启动最前调用共享的
  `ri_core::tls::install_rustls_crypto_provider()`，显式安装进程级
  CryptoProvider（`rustls::crypto::ring::default_provider()`），消除 rustls
  0.23.42 在同时启用 `ring` 与 `aws-lc-rs` 特性时的确定性启动 panic
  （`crypto/mod.rs:249`）。无 unwrap、无特性自动推断、冲突 provider 不静默接受。
- 全部二进制审计：`ri-agent`、`ri-wrapper`、`ri-trace-adapter` 已在 main()
  入口初始化；`ri-registry-sync`、`ri-knot-trace-producer` 无 TLS 构建路径。
- 回归测试：`ri-core/src/tls.rs` 单元测试、`ri-agent/tests/agent_startup.rs`、
  `ri-wrapper/tests/wrapper_startup.rs`、Docker 镜像启动烟测全部通过
  （94 passed + 1 ignored）。
- 验收覆盖缺口修复：`tools/run_norn_field_acceptance.py` 现在要求存活容器、
  `RestartCount == 0`、非 101 ExitCode、日志无 panic 标记、真实 /healthz 与
  /readyz 就绪等待以及最小 mTLS 请求。

**OCI 镜像**：

- 新增 `deploy/tencent-cloud/oci/rc2/rust-data-plane-oci-rc2.tar`
  （sha256 `3fdcfd73...`）。从冻结 RC1 `rust.oci.tar`（sha256 `34471fee...`）
  派生，仅追加一层替换五个数据面二进制；RC1 归档逐字节未改动。
- 镜像 manifest digest `sha256:02034f7402...`，导入引用
  `offline/resolver-identity/rust:ri-02034f740200fb52`。
- 验证：OCI 布局有效、归档自检精确引用自身 blobs、敏感信息扫描干净、
  R3 主机 `docker load` + 容器烟测通过（restarts=0、exit=0、panic=0、
  /healthz ok、/readyz 503 fail-close、metrics 计数正确）。
- glibc 基线：RC2 二进制在官方 `rust:1.97.0-bookworm`（glibc 2.36）构建，
  最大 GLIBC 符号 2.34，与 RC1 基线一致。

**交付包**：

- 新增 `deploy/tencent-cloud/packages/resolver-identity-domain-center-easy-install-0.3.0-norn-knot-rc2/`。
- 仅重新生成 R1/R2/R3 云绑定主机包（携带 RC2 rust 镜像）。
- Management / Norn A / Norn B 主机包逐字节沿用 RC1 原始包
  （`e3f33455...` / `a5e1c183...` / `72a623c0...`），未重新生成。
- 交付校验：`release_authentic=true`、`signature_valid=true`、
  `trust=trusted_pinned_fingerprint`（固定指纹 `256f76e7...`）。

**配置**：

- `deploy/tencent-cloud/config/site-inventory.json`：release 升为 rc2 /
  `fc6cc19` / 清单 `8d438471...`；`images.rust` 改为
  `offline/resolver-identity/rust:ri-02034f740200fb52`。
- 重新渲染 `config/hosts/ri-r1|r2|r3/config/.env`（RI_IMAGE 指向 RC2），
  management / norn-a / norn-b / authdns 配置保持不变。
- 主机绑定不变：R1=ri-r1/1.13.159.107/10.206.16.14，
  R2=ri-r2/118.195.130.7/10.206.16.17，R3=ri-r3/118.195.189.105/10.206.16.7。

**部署状态**：

- management / norn-a / norn-b / 测试权威 DNS / 注册表数据 / 身份材料 /
  链数据 / 证据数据库均保持可用。
- R3 处于 staged（RC1 曾激活失败并回滚）；R1/R2 未安装。RC2 部署顺序为
  R3（canary）→ R2 → R1，禁止并行激活。

## 0.3.0-norn-knot-rc1（2026-08-05，冻结）

- 冻结源码提交 `928ed0e69fcf71149f4e224124b6a21e7c34aca0`。
- 发布物 `resolver-identity-domain-center-easy-install-0.3.0-norn-knot-rc1/`，
  冻结不改动。
- 缺陷记录：`docs/tencent-cloud/FROZEN-ARTIFACT-ANOMALY.md` 与
  `evidence/tencent-cloud/runtime/rustls-provider-rc1-reproduction/`。
