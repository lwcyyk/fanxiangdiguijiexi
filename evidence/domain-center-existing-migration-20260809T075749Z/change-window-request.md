# 腾讯云 adopt-existing 最小变更清单

## 需要批准的主机与顺序

1. `ri-authdns` (`119.45.203.204`)
2. `ri-r3` (`118.195.189.105`)
3. `ri-r2` (`118.195.130.7`)
4. `ri-r1` (`1.13.159.107`)

Management、Norn A、Norn B 本窗口不重启。

## 当前状态

- 四台数据平面主机的全部容器均为 running；
- 全部 `RestartCount=0`；
- R1/R2/R3 的 `evidence-v2.db` 与 `trace-spool.db` 均 `PRAGMA quick_check=ok`；
- AuthDNS `evidence-v2.db` 为 `ok`；
- 当前状态已记录到 `pre-state.json`；
- 尚未执行任何迁移变更。

## 变更内容

每台主机：

1. 安全复制最终 clean Compose、对应 `node.env` 和不含新身份材料的主机私有 bundle；
2. 保持现有 Compose project：`ri-authdns`、`ri-r3`、`ri-r2`、`ri-r1`；
3. 使用 `tools/adopt_domain_center_existing.py`；
4. 逐服务执行 `docker compose up -d --pull never --no-deps <service>`；
5. Resolver cache 精确复用现有 `knot-cache-rc12-fresh-20260808T045100Z`；
6. R1/R2/R3 Producer 继续使用已现场验证的 reconnect image `sha256:e14e118d...`，其余服务保持当前已验证 image，直到统一正式 OCI 完成；
7. 迁移后执行角色 `install.sh` 两次和 `check.sh`，再复跑双链路、Cache Provenance 与 Cache Recovery。

## 影响范围

- 每个被归并服务会被 Compose 受控重建，单机存在短时服务中断；
- 下游到上游顺序限制影响面；R1 最后处理；
- 不修改 DNS wire、身份、Registry 内容或 PKI；
- 不重启 Norn；
- 不清 Resolver cache。

## 绝不执行

- `docker compose down`
- `docker compose down -v`
- volume 删除
- DB/Evidence/dead-letter 删除
- Resolver cache 清理
- PKI 或身份重新生成
- Norn state 重置
- ControlledStrict/freshness 放宽

## 回滚方式

若任一服务未稳定运行、mount/port/network 漂移或 readiness 失败：

1. 停止继续上游节点；
2. 使用 `pre-state.json` 中记录的原 Compose config-files、environment file、project 和现有 image ID，执行该服务原配置的 `docker compose up -d --no-deps <service>`；
3. 不删除当前数据、cache、PKI 或 volume；
4. 重新执行 SQLite quick_check 和角色健康检查；
5. 将失败记录写入本 Evidence 目录，不把迁移标记为通过。

## 当前授权边界

该操作会重建腾讯云运行容器，属于真实外部环境变更。当前会话没有单独、明确的变更窗口批准，因此停在此边界，等待上述四台主机和变更内容被批准。

## AuthDNS 执行结果（2026-08-09）

AuthDNS 已按授权开始迁移，但第一项 clean Compose 服务 `registry-sync` 使用统一 Rust OCI 后立即因运行时兼容性失败：

```text
/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found
```

已立即停止后续迁移，并按 pre-state 使用原 AuthDNS registry-sync Compose 配置回滚。回滚后：

- `registry-sync` 恢复原 RC14 image，running，RestartCount=0；
- Agent readiness HTTP 200；
- Registry readiness HTTP 204；
- Authority readiness HTTP 204；
- Evidence DB `quick_check=ok`；
- DNS UDP/TCP 查询均返回预期 `192.0.2.10`；
- 未删除 DB、Evidence、cache、volume、PKI 或身份。

证据：

- `authdns-result.json`
- `authdns-post-rollback-inspect.json`

R3、R2、R1 未执行迁移。需要先解决统一 Rust OCI 的 glibc 兼容性并重新验证，不能继续扩大变更。
