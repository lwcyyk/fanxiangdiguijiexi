# 会话交接：腾讯云 RC2 部署（0.3.0-norn-knot-rc2）

> 本文件只记录非敏感信息。不得写入私钥、密码、Token、种子或完整敏感 .env；
> 敏感路径一律以 `...` 或路径名引用，不展开内容。

## 1. Git 分支、HEAD 与未提交修改

- 当前分支：`fix/rustls-crypto-provider-rc2`
- HEAD：`1c68f758e840f20d387790499db7ee16412977f3`
- 工作树：干净（`git status --short` 无输出）
- 相关 refs：
  - `origin/master`、`deploy/tencent-cloud-928ed0e`、`domain-center-easy-installer` → 冻结 RC1 `928ed0e`
- 分支自 `fc6cc19` 以来的提交（自旧到新）：
  - `fc6cc19` fix(rustls): install deterministic crypto provider
  - `9ce4183` test(runtime): detect agent and wrapper restart panic
  - `1a510a2` test(acceptance): require live readiness and zero restarts
  - `2340166` release: prepare norn-knot rc2 artifacts
  - `7bb7c54` deploy(tencent-cloud): route ri-test.invalid via STUB+PASSTHRU in kresd
  - `9a9c325` fix(deploy): raise Norn registry scan window to cover genesis/anchor
  - `1c68f75` feat(scripts): add resolver signing-key alignment helper

## 2. RC1 / RC2 提交、版本与 OCI digest

### RC1（冻结，不改动）

- 版本：`0.3.0-norn-knot-rc1`
- 源码提交：`928ed0e69fcf71149f4e224124b6a21e7c34aca0`
- rust OCI：`rust-data-plane.oci.tar`
  - 归档 sha256：`34471fee2b260fa3d496a454298ef2881d27c4460b1991ee29ab19b5c4ca5b28`
  - manifest digest：`sha256:68ec104256119bd3cee736bc2ebb1f327370d31df3598606d7668ce84eda7244`
  - config digest：`sha256:3e4a31ccd54b799c67449342f9dd4225599cdc02bb18d81cf365f739456a366f`
- 缺陷记录：`docs/tencent-cloud/FROZEN-ARTIFACT-ANOMALY.md` 与
  `evidence/tencent-cloud/runtime/rustls-provider-rc1-reproduction/`

### RC2（新增交付，不覆盖 RC1）

- 版本：`0.3.0-norn-knot-rc2`
- 交付提交：`fc6cc19ee569225f0dbc420199980dba742a7137`；发布清单
  `8d438471433e9e242b5df645d71a98b7cfc979ae0db1f5d78f7a290cb27e6fc0`
- rust OCI：`deploy/tencent-cloud/oci/rc2/rust-data-plane-oci-rc2.tar`
  - 归档 sha256：`3fdcfd7330ad87dd2c2e6d8dc04f667831abd72fdd6643c4cf90cc5bb575f8ff`
  - manifest digest：`sha256:02034f740200fb522ae99d939b026f5a7ba6e67dfefede1dc6f1edd9fa2de022`
  - config digest：`sha256:bfb145487d051ba4508a99037eb3ed179bbacc73f1b13cc1a83ca4bda4367be0`
  - 导入引用：`offline/resolver-identity/rust:ri-02034f740200fb52`
- 派生方式：从冻结 RC1 `rust.oci.tar` 派生，仅追加一层替换五个数据面二进制；
  RC1 归档逐字节未改。二进制 sha256（`oci-digest-record.json`）：
  `ri-agent` 86c8139f…、`ri-wrapper` 1867061b…、`ri-trace-adapter` a10ea457…、
  `ri-registry-sync` 1f75d260…、`ri-knot-trace-producer` e394ae9a…
- 其它镜像（沿用 RC1，未重建）：management `ri-8a6d7aeb15009967`、
  knot `ri-61e01beae33fd414`、norn `ri-ad8b495d892c35b1`、nginx `ri-8d9da9cfb339e414`

## 3. 各主机实际状态（2026-08-06 只读快照）

| 主机 | 公网 IP | 内网 IP | 状态 |
|---|---|---|---|
| Management | 118.195.220.95 | 10.206.16.15 | 安装 complete；work 目录持有已签名身份材料（3 身份 / 2 键） |
| Norn A | 119.45.242.175 | 10.206.16.3 | complete；norn-node + norn-read-proxy Up，read-proxy 服务 10.206.16.3:8443 |
| Norn B | 118.195.187.68 | 10.206.16.5 | complete；norn-node + norn-read-proxy Up，read-proxy 服务 10.206.16.5:8443 |
| Auth DNS | 119.45.203.204 | 10.206.16.13 | 非正式角色包；手工配置 BIND 权威，10.206.16.13:53 UDP+TCP，zone ri-test.invalid，非递归 |
| **R3** | 118.195.189.105 | 10.206.16.7 | **COMPLETE**（canary）。install-state rc2/complete/r3；5 容器 Up：agent(5h)、registry-sync(2h)、resolver(6h)、trace-adapter(8h)、trace-producer(8h)，RestartCount=0，无 rustls panic |
| **R2** | 118.195.130.7 | 10.206.16.17 | **COMPLETE**。install-state rc2/complete/r2；5 容器 Up：agent(2h)、registry-sync(3h)、resolver(2h)、trace-adapter(3h)、trace-producer(2h)，RestartCount=0 |
| **R1** | 1.13.159.107 | 10.206.16.14 | **IN PROGRESS**。install-state rc2/**staged**/r1；install_id `1cc6137e-753b-4172-91f7-292820411d0d` 保留；staged_release=`releases/0.3.0-norn-knot-rc2`；**当前无容器运行** |

Auth DNS zone 摘要：`www.ri-test.invalid A 192.0.2.10`、`www AAAA 2001:db8::10`、
`txt.ri-test.invalid TXT "resolver-identity-lab-test"`、`ns1 A 10.206.16.13`；
已从 Norn A 内网直查验证 A/AAAA/TXT 均 rcode 0。

R1 关键中间态：`config/r1/identities-v2.json` 与 `issuer-keys.json` 目前是
占位符（`{"identities":[]}` / `{"keys":[]}`）。管理侧已签发的正式材料
（3 身份、2 键）已暂存：
- 管理主机 `/tmp/ri-identities-mgmt.json`、`/tmp/ri-issuer-keys-mgmt.json`（root 0644）
- 本地 `/tmp/ri-identities-mgmt.json`、`/tmp/ri-issuer-keys-mgmt.json`
- R1 已可达：`ubuntu@1.13.159.107`
- R1 身份公钥（agent.public_key）：`DWAWoWXdWYrVisTBf4li7+oGQDyAQovhNNxiUr5Gh1E=`

## 4. 已完成的 cloud-bound 包、PKI、Registry、preflight、安装

- **Cloud-bound 包**：`deploy/tencent-cloud/packages/resolver-identity-domain-center-easy-install-0.3.0-norn-knot-rc2/`。
  仅重新生成 R1/R2/R3 主机包（携带 RC2 rust 镜像）。Management / Norn A / Norn B
  主机包逐字节沿用 RC1（`e3f33455…` / `a5e1c183…` / `72a623c0…`），未重建。
- **交付校验**：`evidence/tencent-cloud/packages/delivery-release-manifest-rc2.json`
  （release_authentic、signature_valid、trust=trusted_pinned_fingerprint）、
  `delivery-SHA256SUMS-rc2`、`host-packages-rc2.sha256`。
- **PKI**：测试专用，位于管理主机 `/opt/domain-center-install/cloud-928ed0e/lab-pki`；
  各 resolver 使用 `secret/agent-tls` + `secret/secrets`。**私钥内容/hash 永不输出、永不提交、永不进支持包。**
- **Registry**：管理侧 `registry-tool.sh` 完成计划与签名；Norn snapshot 已发布到链上
  （transaction `4d3059bd…`）；plan_hash `0x2312fc49…`；checkpoint 1118；
  state_root `0x5e956d5c0b35cbd8fa952551925c82ef7a6affac5b6a1471a51524907c71bbbf`；
  双节点 head 1296/1296。
- **OCI**：RC2 rust 归档已校验（`evidence/tencent-cloud/oci/rc2/` +
  `oci-digest-record.json`），并在 R3/R2/R1 主机 `docker load`；R3 容器烟测通过。
- **Preflight**：6 个正式角色全部通过。
- **安装**：R3 全流程（install --no-start + activate + 修复）；R2 安装 + 激活；
  R1 安装 --no-start 已 staged（rc2）。

## 5. 当前中断点

R1 激活流水线。刚被用户中止的动作：把已签发身份材料写入 R1 `config/r1`
（root:root 0644）并重算 `config_sha256`。材料已暂存完毕、R1 可达，下一步就是
执行该写入并继续 R1 的剩余步骤（见第 6 节）。

## 6. 下一步准确命令（R1 收尾）

材料已就绪，勿再重取。顺序执行：

**a) 写入身份材料到 `config/r1`（root:root 0644）并重算 config_sha256**

```bash
ssh -o ConnectTimeout=10 ubuntu@1.13.159.107 "sudo python3 -" <<'PYEOF'
import json, os, hashlib
ROOT = "/opt/domain-center-install/cloud-928ed0e"
config = f"{ROOT}/config/r1"
ids = json.load(open("/tmp/ri-identities-mgmt.json"))
keys = json.load(open("/tmp/ri-issuer-keys-mgmt.json"))
assert len(ids["identities"]) == 3 and len(keys["keys"]) == 2
for name, tmp in (("identities-v2.json", "/tmp/ri-identities-mgmt.json"),
                  ("issuer-keys.json", "/tmp/ri-issuer-keys-mgmt.json")):
    dest = f"{config}/{name}"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, open(tmp, "rb").read()); os.close(fd)
    os.chown(dest, 0, 0); os.chmod(dest, 0o644)
def file_hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1024*1024), b""): h.update(b)
    return h.hexdigest()
def tree_hash(root):
    d = hashlib.sha256()
    for p in sorted(os.path.join(dp, fn) for dp, _, fns in os.walk(root) for fn in fns):
        d.update(os.path.relpath(p, root).encode()); d.update(b"\0")
        d.update(file_hash(p).encode()); d.update(b"\n")
    return d.hexdigest()
print("CONFIG_SHA256", tree_hash(config))
PYEOF
```

**b) 同步 state 与 release 配置（不重跑 install，避免 STATE003）**

- 把上一步得到的 config_sha256 写入
  `install/ri-r1/state/install-state.json`（保留 install_id `1cc6137e…`、version rc2、
  status staged、staged_release 不变），并同步更新
  `install/ri-r1/releases/0.3.0-norn-knot-rc2/config/` 下的两份身份 JSON
  与 `releases/0.3.0-norn-knot-rc2/.installed.json` 的 `config_sha256`。

**c) trace-adapter networks 修复（与 R3 同款）**

- 仅改 RELEASE compose：`install/ri-r1/releases/0.3.0-norn-knot-rc2/docker-compose.yml`
  第 150 行 `    networks: [link-control]` → `    networks: [link-control, agent-egress]`。
- **不改** product-kit 包内 compose（保持 role_sha256 稳定）。

**d) 对齐签名种子**

```bash
sudo python3 .../align-resolver-signing-key.py \
  --host ri-r1 --identity-public-key DWAWoWXdWYrVisTBf4li7+oGQDyAQovhNNxiUr5Gh1E=
```

**e) 激活并验证**

```bash
sudo env DC_MIN_MEMORY_MB=1900 python3 ... activate   # 官方向导动作
sudo env DC_MIN_MEMORY_MB=1900 python3 ... status
```
验证：5 容器 Up、RestartCount=0、日志无 rustls panic、/healthz + /readyz OK、
证据库 3 身份 ACTIVE、registry-sync 新鲜、state_root 与 Norn 快照一致
（`0x5e956d5c…`）。

## 7. 已发现但不得重复处理的问题

- **RC1 rustls CryptoProvider 启动 panic**：确定性、已归档（exit 101）。
  RC2 已修复并加回归测试；勿再复现/诊断。
- **R3 已应用的修复（勿在 R2/R1 上重复"诊断"）**：agent 签名种子对齐、
  trace-adapter networks/端口修复、registry-sync 重锚定
  （`RI_NORN_MAX_SCAN_BLOCKS=100000` 覆盖 genesis 1118 与 R3 重锚）。
- **R1 身份写入后勿重跑 install**：`releases/0.3.0-norn-knot-rc2` 已存在且
  `.installed.json` 记录旧 config_sha256，重跑会触发 STATE003 → 采用第 6 节手工编辑路径。
- **Management / Norn A / Norn B 包勿重建**（逐字节沿用 RC1）。
- **冻结 RC1 交付勿改动**（包、FROZEN-ARTIFACT-ANOMALY.md、RC1 异常证据）。
- **master 勿强制覆盖**；合并与否在验证后决定。
- **site-inventory.json 中 R1 `wrapper_upstreams` 仍为自指 `tcp://10.206.16.14:53`**
  （提交态），R1 服务器实际 .env 已修正为 `tcp://10.206.16.17:53`（SEC108）。
  记录偏差，勿机械改清单。
- **命令分类器间歇不可用**（deepseek-v4-flash[1M]）：ssh 类命令失败时耐心重试；
  只读操作不受影响。
- **向导一律** `sudo env DC_MIN_MEMORY_MB=1900 python3 ...`。
- 全部部署命令用 `ubuntu` 用户登录（尝试 ubuntu，其次 root）；脚本/日志/git 中
  不得出现 sshpass/口令；禁止 `StrictHostKeyChecking=no`。

## 8. 腾讯云 SSH 别名

`~/.ssh/config` 中无这些别名（仅 github.com）。按"user@公网IP"直连，SSH 用户先用
`ubuntu`，失败再试 `root`：

| 别名（会话约定） | 连接 |
|---|---|
| ri-management-cloud | `ubuntu@118.195.220.95` |
| ri-norn-a-cloud | `ubuntu@119.45.242.175` |
| ri-norn-b-cloud | `ubuntu@118.195.187.68` |
| ri-authdns-cloud | `ubuntu@119.45.203.204` |
| ri-r1-cloud | `ubuntu@1.13.159.107` |
| ri-r2-cloud | `ubuntu@118.195.130.7` |
| ri-r3-cloud | `ubuntu@118.195.189.105` |

## 9. 不能删除或重置的数据

- **各 resolver 的 `/var/lib/resolver-identity/ri-r*/`**（含 `evidence-v2.db` 与
  install_id 标记）：删除数据目录而 state 的 install_id 仍指向它 → DATA003 直接报死。
- **R1 `state/install-state.json`**：保留 install_id `1cc6137e…`；
  已有 `state/install-state.rc1-staged-backup-…` 与 `state/MIGRATION-RC1-STAGED-TO-RC2.txt`。
- **管理主机**：work 目录已签名身份材料与 issuer-keys；`lab-pki` 测试 PKI；
  各 resolver `secret/{agent-tls,secrets,norn-tls}`。
- **Norn A/B 链数据**（`/var/lib/resolver-identity/ri-norn-{a,b}`）：注册表链 + 快照。
- **Registry 数据 / 证据库 / 身份材料 / Auth DNS 配置 / 清单 / UFW / NTP / swap** 全主机保留。
- **冻结 RC1 交付物**与 RC1 异常证据。
- **RC2 OCI 归档**与 digest 记录（`deploy/tencent-cloud/oci/rc2/`、
  `evidence/tencent-cloud/oci/rc2/`）。

## 10. 未完成的端到端验证

（对应任务 #16，全部为"待做"，此前均未通过/未执行）

1. **Auth DNS 直查**：从 R3 直查 `10.206.16.13:53`，`www.ri-test.invalid` A/AAAA/TXT。
2. **链路查询**：R1（first-hop，wrapper upstream `tcp://10.206.16.17:53`）→ R2 → R3 →
   Auth DNS。
3. **带外身份验证**：逐级比对 agent TLS 证书绑定公钥与 identities-v2.json 中该
   server_id 的公钥。
4. **最小负向 fail-close**：agent /readyz 在快照陈旧/缺失时返回 503；上游拒绝。
5. **Trace 验证**：knot-trace-producer → trace-adapter socket，日志中的 provenance。
6. 通过后：更新陈旧证据（`deployment-state.json`、CHANGELOG 部署状态段落、
   R3 SHA256SUMS、max_scan_blocks / trace-adapter / 签名键 / wrapper_upstream 偏差记录），
   出 32 项最终报告。
