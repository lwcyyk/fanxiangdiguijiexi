# RC15 Service-Level Stable Image Matrix

本矩阵冻结域名中心服务级稳定镜像组合。事实来源仅为：R1 回滚后稳定运行状态、RC15 Cache Recovery Evidence、`docker inspect`、每个镜像顶层 OCI 层内 binary SHA-256、已存在 OCI/build evidence 与 stable worktree 源码。不凭 RC 版本字符串推断。

冻结决定：每个 service 固定自己的已验证 OCI，允许同一角色携带多个 OCI archive；不合并为统一 Rust OCI。

## Frozen matrix（正式交付以 OCI 内嵌 binary 为准）

| Service | Image manifest | Archive | Embedded binary SHA-256 | Source/build evidence | Provenance |
|---|---|---|---|---|---|
| `resolver` | `sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8` | `knot-trace.oci.tar` | `122767e45f2de8d6760659dbcb424bb2506168bbca0b23e2390cd6319a667f7b` (`kresd`) | Knot OCI + Resolver acceptance；upstream Knot commit `124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e` | partial，交付 OCI 存在 |
| `trace-producer` | `sha256:ba61776ddb2eb0948b7c3cf4b1ffb04cac66b3a2e9da773a09c58e9449d0954c` | `rust-data-plane-rc15-reconnect-strict.oci.tar` | `d1eba1c7780926fc6d3f6c868c496ff335f88a2feb5f9ef84391334ce604c752` | reconnect fix `3181db37799f18f4af6f0fef4df7dd87364721af`，两次独立离线重建一致；Cache Recovery 证明按需重连 | partial，`producer_reconnect_present=true` |
| `registry-sync` | `sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80` | `rust-data-plane-oci-rc14.tar` | `7be62dc1b6a7c71fc975481036be3a2ac548dda67b4e10f037afdfc0d0352545` | RC14 OCI digest record（commit `c022d17546b92d399562810c526d5fd7932ae50c`） | partial，交付 OCI 存在 |
| `agent` | `sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f` | `rust-data-plane-oci-rc15-service.tar` | `1c7a3348062b14ab172449378336c13d789c31e3b8e7db6aaf64d8134b1e02fd` | RC15 service OCI A/B 确定性构建；stable 源码 `3181db37799f18f4af6f0fef4df7dd87364721af` | partial，交付 OCI 存在 |
| `trace-adapter` | `sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f` | `rust-data-plane-oci-rc15-service.tar` | `5c3d0c1e36b3b811bc71d1be50c820640762f180bc4e0569db258416746b2f54` | RC15 service OCI A/B 确定性构建；stable 源码 `3181db37799f18f4af6f0fef4df7dd87364721af` | partial，交付 OCI 存在 |
| `wrapper` | `sha256:373ac52a774f8ffd9f92bf26d4aff2132e54287b2d21bb2d6e30d924365b13b6` | `rust-data-plane-oci-rc11.tar` | `223923a6a915855ce23368c71025d9ce7662258629c2b0f42ac1557914983e92` | RC11 OCI digest record | partial，交付 OCI 存在 |
| `authority-proxy` | `sha256:ba61776ddb2eb0948b7c3cf4b1ffb04cac66b3a2e9da773a09c58e9449d0954c` | `rust-data-plane-rc15-reconnect-strict.oci.tar` | `2702a59f9b99dc88e9299f18aad82e5e950594c9c01e54b47b7e0fd7a69dbc78` | reconnect OCI（内含 authority-proxy） | partial，交付 OCI 存在 |

## 现场有效 hotfix binary（不做正式交付）

R1 回滚后现场容器仍以 bind-mount 方式叠加以下 hotfix binary，与冻结 OCI 内嵌 binary 不同：

| Service | Field effective binary SHA-256 | 说明 |
|---|---|---|
| `agent` | `e172d8ad7dd90b7407f605d7da52b2b7030fe29a645e148ce6948cea69d2a90a` | `rc12-source-fix/ri-agent`（2026-08-07 22:05）；`.comment` 显示 rustc 1.97.0 + Zig 0.13 musl；无法从任何已提交 source commit 字节级复现 |
| `trace-adapter` | `d1fc059a5017642009e3c12c6728186f3452ba267d52817a33e2a799a1918b60` | 同上 |
| `wrapper` | `3393abf4d78aa951928be2f58b8fc05f4df6ac04a9df8b6e4f619df75f1ddf78` | 同上；无 source-commit 绑定 |

结论：这些 hotfix binary 对应 2026-08-07 未提交工作树（源码文件哈希与 `f69ad5a` 一致，但 Cargo.lock 在 08-09 才改写），任何已提交历史（`d07255e`/`b61be65`/`c022d17`/`f69ad5a`）在本地 Zig 0.13 + rustc 1.97.0 下重建均不能字节级一致。因此按发布规则不把这些 binary 冒充正式 release；正式交付使用上表 OCI 内嵌 binary，行为等价性由 R1 门禁的完整功能回归证明。

## OCI archive 记录（dist/images）

- `knot-trace.oci.tar`：SHA-256 `dd4348db986a629c8f9bf6874e38a75baad96e1e6c0c6545d1082118a0434fa9`
- `rust-data-plane-rc15-reconnect-strict.oci.tar`：SHA-256 `07d5898e8879e49f9d065bfd979676e13f845c26ee8d7f4c6f117c27b96fe6bd`，config `sha256:5a0974869334035021023ff8cf4fadba5cb1754f9cf61f73f10e4e0d5d1a592b`
- `rust-data-plane-oci-rc14.tar`：SHA-256 `95dc54ec9bcda0bb9f206fb24ddd23007cdba9ea490e7dda080a51584ee19f5f`，config `sha256:992362e791904eb63e3dbc2b811367f65a907f405282bab1fbb7741620bc7ec5`
- `rust-data-plane-oci-rc15-service.tar`：SHA-256 `634eaf6078d449ea23de803313a9cbfc4871c289e426d0deb24a94a98bd09713`，config `sha256:82fdaaffee47a55ab3b31e6f05367a7777184e9a1a6d6e93eb1289815993d754`
- `rust-data-plane-oci-rc11.tar`：SHA-256 `0e501267f1f752599263df809c2222b700e36f1f33bbee3ce3e67b751c7fb574`，config `sha256:72eaeae03ee42a6b7375989f29ae285d64fb510415dfe0b6f2a77b0c57725ca5`

## Build facts

- Rust 1.97.0（rustc `2d8144b78 2026-07-07`）；`--locked --offline --release`。
- RC15 service 源码锁：`Cargo.toml=139c7b7a7f938acbf0e64bbc0f0e2ee0849917a64e5e70ff94f577f9679ee992`、`Cargo.lock=4278854dcafc58259a55ca7e05cf30a93016a4bb8a6d9276bb9f8d70a107f940`。
- stable 源码提交：`3181db37799f18f4af6f0fef4df7dd87364721af`（父提交 `f69ad5a1a84ea6f8b693190194aaa8ee9d745029`）。

## Release flags

```text
service_image_matrix_frozen=true
producer_reconnect_present=true
wrapper_binary_provenance_known=false
complete_effective_oci_binding=false
```

`wrapper_binary_provenance_known=false` 表示现场 hotfix Wrapper binary 无法绑定到任何已提交源码；冻结的正式 Wrapper 交付物为 RC11 OCI 内嵌 binary，仍满足“不以运行容器复制品冒充正式 release”的规则。行为等价性通过 R1 门禁功能回归验证后才可标记 `r1_migration_passed=true`。
