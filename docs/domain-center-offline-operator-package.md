# 域名中心 RC15 七角色离线操作包

## 范围

本交付冻结稳定 RC15 双链路，不包含 RC16 Strict Trace Binding。当前结果继续明确为：

```text
dual_chain_end_to_end_passed=true
trace_binding_passed=false
trace_binding_known_p0=true
release_ready=false
production_capacity_validated=false
production_deployed=false
```

公共包构建器：`tools/build_domain_center_operator_package.py`。

私有包构建器：`tools/build_domain_center_private_bundle.py`。

私有包 schema：`specs/domain-center-private-bundle-v1.schema.json`。

现有云受控归并工具：`tools/adopt_domain_center_existing.py`。

## 公共包

公共包包含七个编号角色目录：

1. Management
2. Norn A
3. Norn B
4. Auth DNS
5. R3
6. R2
7. R1

每个角色只暴露：

```bash
sudo ./install.sh
sudo ./check.sh
sudo ./diagnose.sh
```

构建时必须显式提供五个冻结 OCI。构建器会执行：

- 归档 SHA-256 校验；
- OCI 单平台、manifest、config、layer、diff-id 完整验证；
- OCI 配置和 layer 的受限 secret scan；
- 公共文件 secret/runtime 文件名扫描；
- 精确 `SHA256SUMS`；
- 确定性 outer tar 生成。

示例：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_domain_center_operator_package.py \
  --image-source management=/release/management.oci.tar \
  --image-source norn=/release/go-norn.oci.tar \
  --image-source nginx=/release/mtls-read-proxy.oci.tar \
  --image-source knot=/release/knot-trace.oci.tar \
  --image-source rust=/release/rust-data-plane-oci-rc15.tar
```

输出目录默认是 `dist/resolver-identity-domain-center/`，同时生成确定性 tar 和 `.sha256`。`dist/` 不提交 Git。

内部 SHA-256 用于完整性，不替代发布者身份认证。正式向外分发时必须对 outer tar 的 SHA-256 或 tar 本身制作 detached signature，并通过独立可信渠道固定发布公钥指纹；管理员应在 `sudo` 执行前完成签名验证。

## 每主机私有包

公共包不含 Compose、环境配置或 secret。私有包必须通过安全带外渠道独立交付到：

```text
/etc/resolver-identity/domain-center/<role>/
```

构建示例：

```bash
sudo python3 tools/build_domain_center_private_bundle.py \
  --output /etc/resolver-identity/domain-center/r1 \
  --role r1 \
  --expected-host ri-r1 \
  --compose-project ri-r1 \
  --compose /handoff/r1/compose.yml \
  --environment /handoff/r1/node.env \
  --secrets /handoff/r1/secrets
```

`compose_project`必须与目标运行项目一致。现有腾讯云节点使用 `ri-r1`、`ri-r2`、`ri-r3`、`ri-authdns`、`ri-norn-a`、`ri-norn-b`，这样归并时不会创建竞争端口的第二个 Compose project。

私有根目录和 secret 子目录为 root:root 0700，文件为 root:root 0600，禁止符号链接。`node.env` 中的 image 必须精确使用对应公共角色 `image-lock.json` 的 `import_reference`，操作层会执行 `docker compose config --images` 比对并以 `--pull never` 启动。

## adopt-existing

现有云迁移只允许按下游到上游顺序：

```text
Auth DNS → R3 → R2 → R1
```

每个角色迁移前先生成与当前 project、mount、port、network 完全一致的私有包，再运行：

```bash
sudo python3 tools/adopt_domain_center_existing.py \
  --role r3 \
  --project ri-r3 \
  --compose /etc/resolver-identity/domain-center/r3/compose.yml \
  --environment /etc/resolver-identity/domain-center/r3/node.env \
  --data-dir /var/lib/resolver-identity \
  --output /var/log/resolver-identity-domain-center/adopt-r3.json
```

工具会：

- 捕获现有 container image、mount、port、network、RestartCount；
- 对存在的 `evidence-v2.db` 和 `trace-spool.db` 执行只读 `PRAGMA quick_check`；
- 要求 clean Compose 服务集合与现有 project 完全一致；
- 逐服务执行 `up -d --pull never --no-deps`；
- 再次核对 mount、port、network 和运行状态；
- 记录 `state_deleted=false`、`cache_cleared=false`、`volumes_removed=false`。

工具不执行 `down`、`down -v`、volume 删除、DB 初始化或 Resolver cache 清理。首次真实云执行仍属于外部变更，必须在变更窗口按节点分别批准。

## 尚未完成的门

源码和本机构建验证不等于完成部署验收。以下仍必须真实执行并保存 Evidence：

- 腾讯云逐节点 adopt-existing；
- 安装幂等复跑；
- 双链路全链路重验；
- RC15 Cache Recovery 重验；
- 七台 clean VM 无手工修复安装；
- 发布 detached signature；
- 容量与长时间 soak。
