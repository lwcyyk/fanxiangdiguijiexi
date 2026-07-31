# Go-Norn 单链现场交付手册

## 1. 交付边界

本交付包含中心管理服务器、两个独立 Go-Norn 节点和递归解析器链路服务器的软件包。
它只完成预发布安装和模拟验收，不连接真实生产服务器，不切换 DNS 流量。

当前仓库没有 BIND、Unbound、Knot Resolver 或 PowerDNS Recursor 的生产级内部
Trace 插件。`ri-trace-adapter` 是事件接收和可靠传输组件，不是 Resolver 插件。
因此 Release Manifest 固定为：

```json
{"production_trace_ready": false}
```

在真实插件通过并发、缓存、重试和关联 ID 验收前，这是 P0 切流阻断项。

## 2. 生成交付包

现场 Inventory 使用
[`deploy/field/inventory.example.yaml`](../../deploy/field/inventory.example.yaml)
的结构。文件采用 JSON 语法，是 YAML 1.2 的严格子集，不允许重复字段。

```bash
python3 tools/manage_norn_field_delivery.py validate \
  --inventory /secure/field/inventory.yaml

python3 tools/manage_norn_field_delivery.py render \
  --inventory /secure/field/inventory.yaml \
  --output-root artifacts/field-deployment

python3 tools/manage_norn_field_delivery.py verify \
  --release artifacts/field-deployment/<version>
```

Inventory 只记录镜像 digest、主机、网络、Registry 固定值和秘密配置档案名。
渲染器不会创建、读取或复制任何秘密。

## 3. 安装顺序

1. 在管理服务器解压 management 包并执行 `preflight.sh`、`install.sh`。
2. 在不同物理服务器解压 Norn 包，分别使用 Node A、B 配置。
3. 从安全系统生成不同的节点配置、节点密钥和 mTLS 材料。
4. 先启动 Node A，等待其创世块持久化并登记 peer ID，再配置并启动 Node B；
   不得让两个空数据节点同时各自创建创世块。
5. 核验两个 mTLS 端点只允许三种读方法，所有写方法返回拒绝。
6. 管理服务器离线生成身份、Plan 和签名快照，经 SSH 隧道发布到 Node A。
7. 按 R1、R2、R3 顺序安装 resolver-link 包；每台主机先验证 Registry Sync。
8. R1 使用 `first-hop` profile，R2/R3 不启用该 profile。

受控预发布 Go-Norn 使用 Node A 单一发布/产块、Node B 独立只读同步副本。
Node B 保持独立 P2P 密钥、证书和数据目录，但不使用 `-g` 产块参数，避免两个
独立生产者在当前 Go-Norn 实现上形成分叉。管理发布通道只能写入 Node A。

## 4. 现场目录

```text
/opt/resolver-identity/releases/<version>/
/opt/resolver-identity/current
/var/lib/resolver-identity/<host>/
/etc/resolver-identity/<host>/
```

安装示例：

```bash
./preflight.sh
sudo ./install.sh \
  --version <version> \
  --config-dir /secure/rendered-config/<host>/config
./health-check.sh
```

镜像必须使用完整 `name@sha256:<digest>`，目标服务器不执行源码编译。

## 5. 升级和回滚

```bash
sudo ./upgrade.sh --config-dir /secure/rendered-config/<host>/config
sudo /opt/resolver-identity/current/rollback.sh
```

升级健康检查失败会自动恢复程序符号链接。Norn 数据、SQLite、Registry 快照和链上
状态不会自动回滚。

普通卸载：

```bash
sudo /opt/resolver-identity/current/uninstall.sh
```

普通卸载保留 release 和数据。只有经过审批时使用：

```bash
sudo /opt/resolver-identity/current/uninstall.sh --purge-data
```

`--purge-data` 只删除带安装器所有权标记的数据目录。

## 6. 网络与权限

- Node A/B 之间只开放 P2P 31258。
- Native gRPC 45555 仅绑定节点 loopback。
- 解析器只访问 Node A/B mTLS Read 8443。
- 管理服务器通过 SSH 22 建立发布隧道。
- Agent 和 Wrapper 不允许访问 Norn。
- upstream 不启动 Wrapper。

以生成的 `network-matrix.json` 和 `secret-requirements.json` 为现场防火墙及秘密下发
依据。跨服务器地址不得使用 `localhost`。

## 7. 离线镜像

在联网制品机先按 Release Manifest 的完整 digest 拉取镜像，再分别执行
`docker save`。将归档命名为 `management.tar`、`rust.tar`、`norn.tar` 和
`nginx.tar`，通过：

```bash
python3 tools/manage_norn_field_delivery.py render \
  --inventory /secure/field/inventory.yaml \
  --offline-image-dir /secure/offline-images
```

目标机使用包内 `common/load-offline-images.sh`，该脚本在 `docker load` 前核验每个
归档的 SHA-256。

## 8. 不得上线的情况

- `production_trace_ready=false`；
- Node A/B 共用节点密钥、证书、目录或 Volume；
- 任一镜像不是完整 digest；
- mTLS Read 代理接受写方法；
- Registry Sync 无法同时核对 A、B；
- R2/R3 出现 Wrapper；
- 失败同步覆盖 SQLite 或刷新成功心跳。
