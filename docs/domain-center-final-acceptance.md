# Domain Center Offline Package Final Acceptance

## Scope

This document freezes the RC15 domain-center deployment package work. RC16 Strict Trace Binding remains out of scope and is not passed.

## Frozen status

```text
stable_baseline_frozen=true
clean_compose_generated=true
legacy_overlay_dependency_removed=true
offline_package_integrity_passed=true
offline_images_verified=true
private_bundle_validation_passed=true
secret_scan_passed=true
trace_binding_passed=false
trace_binding_known_p0=true
production_capacity_validated=false
production_deployed=false
detached_signature_supported=false
```

## Clean Compose correction

The successful historical RC15 runtime is a mixed service set: RC14 Registry Sync, RC15 Agent and Trace Adapter, RC15 reconnect Trace Producer, RC13 Wrapper, and frozen Knot. The clean Compose package previously used one unified reconnect Rust image for all Rust services, which could not be declared equivalent to that historical mixed runtime solely from timeout values. The unified clean image was therefore replaced by the **Service-Level Stable Image Matrix**（`docs/rc15-service-image-matrix.md`）：每个 service 固定自己的已验证 OCI（knot 61e01bea、trace-producer/authority-proxy ba61776d、registry-sync d6c4f9da、agent/trace-adapter/wrapper 1e4409aa），离线包按 v2 image-lock 提供多 OCI archive。

R1 门已按此矩阵迁移并通过（2026-08-10T12:29:25Z，`evidence/domain-center-r1-gate-20260810T1233Z/`）：A/AAAA/TXT × UDP/TCP 全部 NOERROR+AD+RRSIG，wrapper response_digest == final event response_digest（6/6 字节级匹配），controlled_strict_release_passed=true。

## Package artifact

```text
artifact=dist/resolver-identity-domain-center-0.3.0-norn-knot-rc15.tar
sha256=de08a6551a0465429faf3cd277a02878b411d0ec66ccce27927514d95ec2e37c
```

Verified:

- seven role directories;
- no public secrets, databases, cache, evidence, or runtime state;
- OCI archives present and validated;
- exact file-set SHA256 verification passed;
- deterministic outer archive produced;
- clean Compose validator passed;
- no historical overlay markers or RC16 markers.

## Existing cloud state

AuthDNS、R3、R2 已按冻结服务级矩阵迁移完成（2026-08-10T12:46Z，`evidence/cloud-migration-to-frozen-matrix-20260810T1246Z/`）：AuthDNS 受控 recreate（registry-sync d6c4f9da、agent 1e4409aa、authority-proxy ba61776d）；R3/R2 adopt-existing 通过（全部五服务）。迁移后验证：全部节点 running + RestartCount=0、registry-sync 每 2s reconcile count=4、AuthDNS→R3→R2→R1 DNS 链 NOERROR+ad、运行 binary SHA-256 与矩阵一致（resolver 122767e4、trace-producer d1eba1c7、registry-sync 7be62dc1、agent 1c7a3348、trace-adapter 5c3d0c1e、wrapper 6c5537f4、authority-proxy 2702a59f）。

## Acceptance fields

```text
existing_cloud_migration_passed=true
r1_migration_passed=true
dns_resolution_chain_passed=true
out_of_band_identity_chain_passed=false
dual_chain_end_to_end_passed=true
cache_hit_path_passed=true
cache_recovery_passed=false
clean_host_install_passed=false
one_command_install_verified=false
fresh_environment_dns_chain_passed=false
fresh_environment_identity_chain_passed=false
fresh_environment_dual_chain_passed=false
domain_center_package_ready=false
```

`trace_binding_passed=false`、`trace_binding_known_p0=true`、`production_capacity_validated=false`、`production_deployed=false` 保持不动（RC16 Strict Trace Binding 与容量/部署验证不属于 RC15 完成范围）。

`clean_host_install_passed`、`one_command_install_verified`、`fresh_environment_*`、`domain_center_package_ready` 需在干净 VM 七角色安装与幂等复跑完成后置 true（见 `tools/` 安装与 `check-all` 流程）。

The pre-existing RC15 acceptance artifacts remain valid historical evidence and are not relabeled as evidence for the failed clean Compose migration.
