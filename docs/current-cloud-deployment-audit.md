# 当前腾讯云部署审计

审计时间：2026-08-09 UTC

本审计直接读取七台实验服务器的 `docker ps`、`docker inspect`、Compose labels、mount、network、port、RestartCount 和部署目录，不以历史会话记录代替运行态。

## 总体结论

当前 DNS 与身份双链路运行态由多个历史 Compose overlay 叠加形成。所有运行容器 `RestartCount=0`，但 Resolver 节点与 Auth DNS 节点并不存在一份可直接交付的单一 Compose。

最终交付必须保留当前运行语义，但删除以下运行时依赖：

- `docker-compose.rc11.yml`
- `compose.rc12*.yml`
- `compose.rc13*.yml`
- `compose.rc14.yml`
- `compose.rc15.yml`
- `compose.rc15-reconnect.yml`
- `compose.registry-rc13-experiment.yml`

这些文件是实验演进记录，不是管理员需要理解或叠加的正式配置。

## 七角色现状

### Management

```text
host=ri-management
private_ip=10.206.16.15
running_containers=0
current_release=0.3.0-norn-knot-rc1
```

Management 主机保留安装、配置、secret 和 work 目录，但当前没有常驻容器。最终包仍需提供 Management 角色，用于生成/发布 Registry snapshot、保存站点清单并执行 `check-all.sh`；不能假设 Management 必须有常驻容器。

需要保留：

- Management tools / Norn publisher 离线镜像和配置；
- 站点 inventory；
- Norn mTLS client材料；
- 只读全站验收脚本。

可以删除：

- 对 RC1 release symlink历史结构的管理员暴露；
- 要求管理员理解 release/overlay 生命周期的界面。

### Norn A

```text
host=ri-norn-a
private_ip=10.206.16.3
compose_project=ri-norn-a
compose_file=.../releases/0.3.0-norn-knot-rc1/docker-compose.yml
norn_image=sha256:ad8b495d892c35b18da82d4c55899eaa8ff15d501fd63551e684a85479432323
read_proxy_image=sha256:8d9da9cfb339e4147190984ce6a61e148e036125aaf33d09c023c3c87b0166ae
restart_counts=0
```

端口：

- `10.206.16.3:31258` Norn P2P；
- `127.0.0.1:45555` native read backend；
- `10.206.16.3:8443` mTLS read proxy。

Norn A 已经使用单一 Compose，正式 Compose 可从现有配置整理，保留 node config、data dir、TLS read proxy和 `ri-norn-field` 网络。

### Norn B

```text
host=ri-norn-b
private_ip=10.206.16.5
compose_project=ri-norn-b
compose_file=.../releases/0.3.0-norn-knot-rc1/docker-compose.yml
norn_image=sha256:ad8b495d892c35b18da82d4c55899eaa8ff15d501fd63551e684a85479432323
read_proxy_image=sha256:8d9da9cfb339e4147190984ce6a61e148e036125aaf33d09c023c3c87b0166ae
restart_counts=0
```

端口和正式需求与 Norn A 对称。Norn B 同样已使用单一 Compose。

### Auth DNS

```text
host=ri-authdns
private_ip=10.206.16.13
compose_project=ri-authdns
bind9=active
agent=RC15, sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
registry_sync=RC14, sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80
authority_proxy=RC13, sha256:e268b76c159f002c4198e3bf3743e2cea41a3a22297190488b249dfdf1ae5fed
restart_counts=0
```

运行中的 Compose labels来自四份文件：

- base `docker-compose.yml`；
- RC13 authority/Agent配置；
- RC13 trace wait；
- RC14 registry-sync；
- RC15 Agent。

正式所需：

- host-network Agent、Registry Sync、Authority Proxy；
- host BIND9 backend；
- Authority Proxy监听 `10.206.16.13:53`，BIND backend保持loopback；
- Agent mTLS和定向 peer credentials；
- Norn双读节点、45秒 freshness；
- Authority trace ingestion fail-close。

实验历史：

- `compose.rc12-source-fix.yml`；
- `compose.rc13*.yml`；
- `compose.rc14.yml`；
- `compose.rc15.yml`；
- registry experiment overlay。

这些必须合并为 `deploy/domain-center/authdns/compose.yml`。Auth DNS目前没有正式 easy-install角色包，这是最终七角色交付的明确缺口。

### R3

```text
host=ri-r3
private_ip=10.206.16.7
compose_project=ri-r3
resolver=Knot sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8
agent=RC15 sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
trace_adapter=RC15 sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
trace_producer=RC15 reconnect sha256:e14e118da311d8bdaf87b3516a0befce20d2a80fd3f4733e391d5e4a6ee01396
registry_sync=RC14 sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80
restart_counts=0
```

Resolver监听 `10.206.16.7:53`。运行容器分别继承 RC11、RC12、RC13、RC14、RC15和 reconnect overlays，共十余份历史文件。

正式必须保留：

- Knot trace hook和独立 trace socket；
- Producer `network_mode: none`；
- Adapter/Agent `link-control`和Agent egress；
- Registry Sync独立 Norn网络；
- Resolver egress；
- 当前现存 cache/data/trace挂载路径在 adopt-existing 时原样保留；
- ControlledStrict、45秒 freshness、定向 peer credentials。

### R2

```text
host=ri-r2
private_ip=10.206.16.17
compose_project=ri-r2
component_images=与R3相同
restart_counts=0
```

R2与R3服务拓扑相同，Resolver监听 `10.206.16.17:53`。同样依赖大量历史 overlay，必须归并为一份 Compose。

### R1

```text
host=ri-r1
private_ip=10.206.16.14
compose_project=ri-r1
resolver=Knot sha256:61e01beae33fd4140acdad907617e59da366a211c1ff6c116433fd2031bbdcc8
agent=RC15 sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
trace_adapter=RC15 sha256:1e4409aaffcbb38c2d13d91b3e8fb6b004f677d7ddb566ae8007aa5ae8ebe23f
trace_producer=RC15 reconnect sha256:e14e118da311d8bdaf87b3516a0befce20d2a80fd3f4733e391d5e4a6ee01396
registry_sync=RC14 sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80
wrapper=RC13 sha256:e268b76c159f002c4198e3bf3743e2cea41a3a22297190488b249dfdf1ae5fed
restart_counts=0
```

端口：

- Knot Resolver：`10.206.16.14:53` UDP/TCP；
- Wrapper：`10.206.16.14:1053` UDP/TCP；
- Agent：`10.206.16.14:8443`；
- Wrapper/Registry/Trace metrics。

R1 Compose labels显示最多的历史 overlay：RC11、RC12、RC13 chain/timeout/provenance、RC14、RC15和reconnect。最终 Compose必须明确表达 Wrapper只部署在R1、Resolver仍监听53、Wrapper对外监听1053、Wrapper上游指向本机Resolver TCP、ControlledStrict和完整身份验证链。

## 镜像统一要求

当前实验环境是有意混合运行版本。最终公共部署包不应继续暴露这种混合标签：

- 从稳定源码提交重新构建一个包含全部六个 Rust binary和Producer reconnect修复的统一 RC15 Rust OCI；
- 所有 Rust服务引用该单一不可变 manifest；
- Knot、Management、Norn、read proxy复用已经冻结的不可变 manifest；
- 不把临时 `rc15-reconnect` layered image作为最终公共制品。

## adopt-existing 安全迁移要求

现有云迁移到clean Compose时必须：

1. 先记录所有容器image ID、mount、network、port和RestartCount；
2. 对Evidence DB、trace spool DB执行只读 `quick_check`；
3. 使用相同Compose project name；
4. clean Compose引用完全相同的数据、cache、trace、secret和TLS host路径；
5. 只执行 `docker compose up -d --no-deps <service>` 或受控整项目 reconcile；
6. 不执行 `down -v`；
7. 不删除、复制覆盖或初始化已有数据目录；
8. 不清 Resolver cache；
9. 每个角色迁移后检查image digest、mount、port、network、ready和RestartCount；
10. 按 Auth DNS→R3→R2→R1顺序迁移数据平面，R1最后。

## 审计限制

直接通过无客户端证书的 `curl -k https://<agent>:8443/readyz` 返回连接失败/HTTP 000是预期的mTLS行为，不代表Agent不健康。正式 `check.sh` 必须使用对应节点的受信client cert，或在容器内执行受控readiness probe。

当前运行容器均无 Docker healthcheck，由外部ready/metrics进行检查。最终 Compose可保留应用ready检查方式，但 `check.sh`必须明确验证，而不能仅依赖容器状态为running。
