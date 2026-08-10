# 域名中心离线安装说明

## 安装顺序

必须按以下顺序安装：

1. Management
2. Norn A
3. Norn B
4. Auth DNS
5. R3
6. R2
7. R1

## 解压公共包

```bash
sha256sum -c resolver-identity-domain-center-0.3.0-norn-knot-rc15.tar.sha256
tar -xf resolver-identity-domain-center-0.3.0-norn-knot-rc15.tar
cd resolver-identity-domain-center
```

每台主机还需要由安全渠道取得与本机角色匹配的私有配置包，并按交接要求安装到：

```text
/etc/resolver-identity/domain-center/<role>/
```

## 安装和检查

进入本机对应的编号目录后执行：

```bash
sudo ./install.sh
sudo ./check.sh
```

安装命令可以重复执行。

如果检查失败，执行：

```bash
sudo ./diagnose.sh
```

脱敏诊断日志写入：

```text
/var/log/resolver-identity-domain-center/
```

## 全站检查

全部角色安装完成后，在 Management 主机执行：

```bash
sudo ./check-all.sh --inventory /etc/resolver-identity/domain-center/site-inventory.json
```

不要手工运行或修改 Docker 容器、环境文件、数据库、证书和密钥。安装或检查失败时，应保留诊断日志并交由维护人员修复安装包。
