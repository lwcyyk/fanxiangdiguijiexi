# 稳定部署基线

## 冻结结论

```text
stable_commit=3181db37799f18f4af6f0fef4df7dd87364721af
stable_source_parent=f69ad5a1a84ea6f8b693190194aaa8ee9d745029
stable_version=0.3.0-norn-knot-rc15
rust_oci_digest=sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
rust_oci_archive_sha256=634eaf6078d449ea23de803313a9cbfc4871c289e426d0deb24a94a98bd09713
knot_oci_digest=sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8
knot_oci_archive_sha256=dd4348db986a629c8f9bf6874e38a75baad96e1e6c0c6545d1082118a0434fa9
management_version=0.3.0-norn-knot-rc1
management_oci_digest=sha256:8a6d7aeb1500996769c8bbf3396e381c7a938ca1d8b154108edf87f2d004d0a0
norn_version=0.3.0-norn-knot-rc1
norn_oci_digest=sha256:ad8b495d892c35b18da82d4c55899eaa8ff15d501fd63551e684a85479432323
registry_max_staleness_seconds=45
verification_mode=controlled-strict
trace_binding_passed=false
trace_binding_known_p0=true
production_deployed=false
```

## 为什么选择该基线

稳定源码由两个已验证部分组成：

1. `f69ad5a1a84ea6f8b693190194aaa8ee9d745029`：RC15 Cache Provenance 与跨 Registry 世代当前身份重新验证的源码基线。该提交中的 workspace 版本为 `0.3.0-norn-knot-rc15`，并包含正式 RC15 Rust OCI 的可复现构建记录。
2. `3181db39d4f7423cf0356b3238d24f20d8fbb0fe`：只在上述基线上加入已经在 RC15 Cache Recovery 现场运行并证明的 Trace Producer Adapter 自动重连修复。该修复不引入 RC16 Context、RIK2、Evidence V3 或 Hop Context。

RC15 正式 Evidence 证明：

- 自然 MISS 创建唯一 canonical G0；
- 连续 CacheHit 和全部观察到的派生 Graph 均直接引用 G0；
- Agent restart 后缓存查询立即成功；
- Registry Sync reconciliation 后缓存查询成功；
- Trace Adapter restart 时当前请求 fail-close，后续请求由 Producer 自动重连恢复；
- Agent down/up 20 轮全部为 down→SERVFAIL、up→NOERROR；
- 未清 cache、未等待 TTL、未重启 Resolver；
- 最终 R1 spool pending 为 0、dead-letter 为 0、服务 restart count 为 0。

事实来源：

- `evidence/cache-recovery-20260809T040124Z/FINAL-RESULT.json`
- `evidence/cache-recovery-20260809T040124Z/README.md`
- `evidence/cache-recovery-20260809T040124Z/99-container-state.txt`
- `evidence/tencent-cloud/oci/rc15/oci-verification.json`
- `evidence/tencent-cloud/oci/oci-verification.json`

## Rust 数据平面制品

正式 RC15 Rust OCI：

```text
archive=rust-data-plane-oci-rc15.tar
archive_sha256=634eaf6078d449ea23de803313a9cbfc4871c289e426d0deb24a94a98bd09713
manifest_digest=sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
config_digest=sha256:82fdaaffee47a55ab3b31e6f05367a7777184e9a1a6d6e93eb1289815993d754
```

该 OCI 已完成两次独立 Rust 1.97 Bookworm、`--locked --offline`、Docker network disabled 构建和两次 byte-identical OCI 组装。

Trace Producer 自动重连 binary 是 RC15 正式 OCI 之后的单 binary 修复。稳定部署分支已将其源码固定到 `3181db3`。最终部署包必须从该提交重新执行完整 RC15 Rust A/B 离线构建和 OCI 组装，不能把 Evidence 中的临时 layered image 当作最终公共制品。

## Knot、Management 与 Norn 制品

Knot Resolver：

```text
version=6.3.0
upstream_commit=124d9357dc1c7c1b87f9eb40b4d1b225c3d1132e
archive_sha256=dd4348db986a629c8f9bf6874e38a75baad96e1e6c0c6545d1082118a0434fa9
manifest_digest=sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8
```

Management 与 Norn 复用已经冻结并验证的离线 OCI：

```text
management_manifest=sha256:8a6d7aeb1500996769c8bbf3396e381c7a938ca1d8b154108edf87f2d004d0a0
norn_manifest=sha256:ad8b495d892c35b18da82d4c55899eaa8ff15d501fd63551e684a85479432323
```

这些制品不需要因 RC15 Cache Provenance 修复而重建。

## RC16 保存状态

未完成 Strict Trace Binding 工作已独立保存在：

```text
branch=future/strict-trace-binding-rc16
commit=8cd62a4299186d4f1792a035136ed1ade2df115a
```

该分支作为 future-security-enhancement 保留，不进入本稳定部署包。当前稳定交付继续明确记录：

```text
trace_binding_passed=false
trace_binding_known_p0=true
```

这不改变已证明的双链路、ControlledStrict、Cache Provenance 和 Cache Recovery 结果。
