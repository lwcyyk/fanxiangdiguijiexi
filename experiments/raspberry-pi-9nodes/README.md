# 九台树莓派实验结果与 RQ1–RQ5 实验报告

This directory publishes a byte-preserving **public subset of existing results**
from the nine-Raspberry-Pi resolver-identity testbed. Publication date: 2026-10-14.
It is not a new experiment, an independent reproduction, a complete raw-platform
archive, or a new security proof.

## 阅读入口

- [RQ1–RQ5 精简报告 PDF](reports/rq1-rq5-summary-20261010/RQ1-RQ5-实验报告.pdf) / [Markdown](reports/rq1-rq5-summary-20261010/RQ1-RQ5-实验报告.md)：2026-10-10 的分项解释与全条件结果表。
- [详细实验测试与验证报告 PDF](reports/validation-report-20261012/递归DNS解析器带外身份认证系统实验测试与验证报告.pdf) / [Markdown](reports/validation-report-20261012/递归DNS解析器带外身份认证系统实验测试与验证报告.md) / [可编辑 Word](reports/validation-report-20261012/递归DNS解析器带外身份认证系统实验测试与验证报告.docx)：2026-10-12 的详细交付稿。
- [实验结果总览 CSV](reports/validation-report-20261012/实验结果总览.csv) / [RQ5 全条件性能 CSV](reports/validation-report-20261012/RQ5全条件性能汇总.csv)。
- [既有实验数据审计说明](reports/validation-report-20261012/实验数据审计说明.md) / [原始证据路径及哈希索引](reports/validation-report-20261012/实验数据与证据索引.md)。索引中的原本地路径不是公开下载地址，也不表示该路径下所有文件均已上传。

## 已有实验及计数单位

| 实验 | 已有结果 | 计数与结论范围 |
|---|---|---|
| RQ1：功能与候选关联 | 11 条件，2,200 measured Roots；600 缓存准备查询另计 | 指定深度、缓存终止、重试、NXDOMAIN、回退与配置切换的功能关联检查 |
| RQ2：身份检查与状态变化 | 1,700 negatives = 200 live DNS + 1,500 isolated；30 发布事件另计 | 不同验证入口分别报告，合法 controls 与恢复不加入负向分母 |
| RQ3：响应绑定与授权非复用 | 700 local negatives、70 controls、24,000 fixtures/groups；四个历史组件接受案例保留 | emit、Store、Graph 入口不同；组件接受不等于已展示客户端绕过，也不称为已修复 |
| RQ4：故障依赖与恢复 | 302 活动事件 = 151 explicit rejections + 102 expected continuations + 49 inconclusive timeouts；700 恢复查询另计 | 恢复不补出超时活动期的缺失结论 |
| RQ5：部署成本与调度 | 26 conditions、130 pairs、260 blocks；30,600 measured requests、15,300 warmup requests | 22 native/pipelined 与 4 serial/pipelined 是不同配对比较族 |

平台角色和路径参见报告。Norn B 与 R2 共用主机；完整 D3 未命中路径为
client → Wrapper → R1 → R2 → R3 → AuthDNS。配置深度不等于缓存命中后
每次实际访问的解析器数量。

**文档回归提示：**2026-10-10 精简报告中“每种传输五批、每批 20”的
统一描述不适用于 Profile A/B switch 的混合传输批次。2026-10-12 审计说明
已保留该例外：每个 profile 五批，每批 10 UDP + 10 TCP；总计仍为
100 UDP + 100 TCP = 200 measured Roots。本次没有改写任何旧报告或数字。

## 目录与机器可读结果

- `results/frozen/`：已有 RQ1–RQ5 汇总、RQ5 条件汇总、130 对配对效应、全局计数和采集后的探索性分析计划。
- `results/tables/`：既有数值表的 LaTeX 片段，不是独立可编译论文工程。
- `results/rq5/`：260 block 指标、失败记录、归档哈希索引、历史未入组尝试清单、方法说明和既有图表。
- `evidence/rq1-rq4/`：原证据索引指向的 summary/verification 类文件。历史 pilot、unit、formal 目录保留各自名称；它们不能直接累加为新的正式样本量。
- `evidence/rq5/`：仅使用已冻结的 13 个 canonical batch、pair000–pair129，每对两个 block。包含原 pair plan、schedule、pair receipt、block receipt、workload summary 和客户端 `workload-raw.jsonl`，不混入同编号的失败准备尝试。
- `provenance/`：来源、文件大小及 SHA-256；本次复制和公开内容检查范围。
- `SHA256SUMS`：本目录发布文件的 SHA-256 清单（不包含清单自身）。

所有复制文件保持原字节。目录内 `.gitattributes` 禁止 Git 对这些封存文本
进行自动换行转换。来源和发布文件的哈希一致，只说明字节完整性，不证明
远端执行归属、构建真实性或完整安全保证。

## 失败、分母和指标不变

RQ5 保留全部提供的测量请求：30,467 valid / 30,600 offered，133 measured
failures，以及 330 warmup failures。near 的 pipelined 条件仍为 480/600；
pair044 的对应 block 仍为 0/120。其客户端记录没有删除或重判。

成功回答时延与全部提供请求的有效回答比例使用不同分母。零成功 block 的
成功时延未定义，不记作零；near 只有四对可定义时延，但保留五个可靠性
观察。每对 block P50 的比值几何平均不能用表列中位数相除替代。不同配对
批次、速率扫描 r1 与默认 D3 行不能相互替换。五对重复、确定性顺序、事后
分析、欠压观察及单平台范围仍按原报告解释。

## 未上传的材料及检查边界

完整多 GB 批次 ZIP、六角色完整 pcap、未经公开检查的节点日志、运行数据库、
私钥、令牌、证书备份和机器访问凭据不在此发布目录。其存在与哈希范围可查
既有索引；本次不承诺公开下载或数据申请渠道，也不删除本地原件。

本次仅复制结果文件、对照既有封存哈希，并按客户端记录已有 `phase`/`ok`
标志核对完整性；未重新解析 wire 判据、重判样本、重算分位数或区间，未执行
实验、测试、部署或节点命令。源码仓库的当前提交不是所有历史 campaign
构建与远端 executable 对应的新增证明。

一般远端发送到目标端到达的归属、完整历史公钥/部署映射、摘要规则与所有
历史构建的对应，继续保留原报告中的材料范围。公开文件不改变这些状态。
