# 现有云迁移到冻结服务级矩阵（existing cloud migration to frozen matrix）

记录时间：2026-08-10T12:46Z（R1 门 12:29:25Z PASS 后完成）

迁移顺序（下游→上游）：AuthDNS → R3 → R2（R1 已于先前 adopt 到冻结矩阵并通过 R1 门）。

## 各角色结果

| 角色 | 方法 | 结果 | 容器（冻结镜像） |
|---|---|---|---|
| AuthDNS | 受控 recreate（mounts 由 file→dir 对齐最终交付拓扑 + 冻结镜像） | passed | registry-sync:ri-d6c4f9da、agent:ri-1e4409aa、authority-proxy:ri-ba61776d |
| R3 | adopt-existing | passed | resolver:ri-61e01bea、trace-producer:ri-ba61776d、registry-sync:ri-d6c4f9da、agent:ri-1e4409aa、trace-adapter:ri-1e4409aa |
| R2 | adopt-existing | passed | 同上 R3 服务集 |

adopt evidence：`adopt-r2.json`、`adopt-r3.json`；authdns 冻结 node.env：`authdns-node.env.frozen`。

## 关键操作记录

1. 每个角色先加载冻结 OCI（`load_images.py` 严格校验 archive SHA-256 + manifest/config digest + 确定性本地标签，`--pull never`）。
2. node.env：去掉统一 `RI_IMAGE`，改为服务级 `RI_*_IMAGE` 冻结引用。
3. clean Compose（`deploy/domain-center/{r2,r3,authdns}/compose.yml`）与运行拓扑一致：
   - r2/r3：与旧 compose 仅 image 变量不同（mounts/ports/networks 完全一致）→ adopt-existing 通过。
   - authdns：旧运行拓扑为 file 级 secret/tls mount，clean Compose 为 dir 级 mount（与其他角色一致）→ 采用受控 recreate
     （`up -d --pull never --no-deps`，registry-sync → agent → authority-proxy），保留 `/var/lib/resolver-identity/ri-authdns` 数据。
4. r2/r3 adopt 后，resolver 与重建的 trace-producer 之间的 knot hook socket 断开（fail-closed 使解析 SERVFAIL），
   按既定操作受控 restart resolver（缓存 bind-mount 保留）恢复。已在 R1 会话中验证该模式。
5. 迁移后验证：
   - AuthDNS authority-proxy 监听 10.206.16.13:53，registry-sync 每 2s reconcile count=4。
   - R3→AuthDNS、R2→R3 均 NOERROR+ad。
   - R1 wrapper 仍释放 NOERROR+ad（verified cache）。
   - R2/R3 trace pipeline 事件持续入库。

## 状态标志

```text
existing_cloud_migration_passed=true（六节点管理/Norn/AuthDNS/R3/R2/R1 全部运行冻结服务级矩阵；R1 门已 PASS）
```
