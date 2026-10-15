# D5 接口前提与现有子链验收

日期：2026-10-15。修复后结论仍为 **PARTIAL_FAIL（21 PASS / 1 FAIL，完整联调仍有依赖缺口）**，不满足 D5 退出条件。当前源码已在 Linux 原生目录完成工程验收，662 测试全通过。风险传递和确认重放已修复；执行前审计失败能够阻止 I/O，但完成审计故障下的真实 WRITE 已验证会改变文件。没有进入 D6，没有调用模型、下载依赖或提交 Git。

本轮实际调用 A 的 PolicyEngine、C 的 SecureExecutionPipeline / ConfirmationAuthority / ExecutionBroker、SQLiteTicketStore、AuditStore / ProvenanceService，以及 D2 合同编译与计划校验、D3 固定检测器、D4 Memory Gate。子链入口只执行虚构只读文件，后续 Linux 机制探针另执行虚构文件 WRITE。B 的 normalization / gateway 源码和可运行入口仍缺失；所有规范效果均由夹具或测试宿主直接提供，不能视为真实工具归约。

## 结果与复验

修复后正式运行目录是 `artifacts/d/D5_20261015_fix_04/`，另一随机种子复验在 `_05/`；初次验收为 `D5_20261015_subchain_02/`、`_03/` 的 17 PASS / 3 FAIL。每例保存实际 SQLite 审计和 `trace.json`，汇总为 `report.json`。入口拒绝覆盖已有目录；初次结果保留，未改写为修复后成绩。

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
& '.\.venv\Scripts\python.exe' scripts/d5_eval.py --output artifacts/d/D5_repeat_01
```

当前预期退出码 **1**：22 个工程探针中 21 PASS、1 FAIL、0 ERROR；原 20 例继续执行，另加执行意图审计故障和完成故障可追溯性两例。这不是 48 个攻击场景的成功率或模型安全评价；本轮没有改变 D1 的原始样本、标签或划分。即使后续探针全通过，B 仍缺失时入口也只记录 PARTIAL_BLOCKED、退出 2，不能自动升级为完整 D5 PASS。

| 范围 | 实测 |
|---|---|
| D2 → 夹具效果 → A/C 真实文件读取 | 整个只读计划校验 READY，返回预期字节，1 次实际读取，重建 decision → intent → execution 共 2 条边 |
| 敏感文件写入 | A 硬 DENY，C 未执行，独立读取确认目标字节未变 |
| secret → 不可信目的地 | 使用虚构标签与目的地，A 的 IFC 硬 DENY，未调用 C I/O；未测试联网接收端 |
| 确认：待定、拒绝、首次批准 | 批准前 0 次读取，拒绝后 0 次，首次批准读取准确内容；使用需确认的只读效果，不是实际 push |
| 票据重启重放、改目标、改主体、到期 | 首次有效票据读取一次；关闭并重开 SQLite 使用计数后，旧票据被拒绝；其余反例也在文件操作前被拒绝 |
| 规范化失败、未支持 EXEC | 人工提供 failed 高影响效果得到硬 DENY；直接向 C 提交 EXEC 被拒绝；没有真实 Shell 归约或命令执行 |
| 决策审计故障、策略不可用 | 注入异常向上传递，0 次 C 文件操作 |
| 执行意图审计故障 | 有效票据消费后、I/O 前提交意图；意图写入失败时 0 次文件操作，票据不自动返还 |
| 完成审计故障可追溯性 | 抛 ExecutionAuditError，不返回读取正文，不自动重试；数据库重开仍能查询到未决执行意图 |
| D3 显式调用方门禁 | 检测命中时 A 给 CONFIRM，D 的 executable=false；测试宿主据此没有调用 C |
| D4 重新读取、过期快照 | 读前重新查询 Memory Gate；有效记录允许读取，过期记录拒绝且不调用 C。有效链重建 8 条内部/跨组件边；过期链 3 条内部边 |

最后两项接线位于**测试宿主**，尚未成为 C 的生产入口。D4 写入绑定、主体身份、来源标签由测试宿主提供；不证明真实宿主身份认证或模型数据流取证。

## 三个原始问题的修复结果

1. **C-01：已修复风险透传接口。** `SecureExecutionPipeline.run()` 新增 risk_signals、side_effects_used，原样交给 A；预算计数严格拒绝布尔值、负数、字符串和小数。`risk_pipeline_gap` 将实际 D3a 输出送入新接口，C 结果由 ALLOW 变为 CONFIRM、I/O 由 1 变为 0，风险同时进入审计。硬 DENY 与默认 DENY 回归通过。调用宿主仍须提供真实风险/计数；缺失的 B 入口和旧解释器没有自动接入 D 检测器。
2. **C-06：已修复确认请求重复消费。** 请求及 HMAC 绑定记录保存在 AuditStore 的新增 confirmations 表；绑定原始效果/决策/期限、主体、trace、session 和审计上下文。BEGIN IMMEDIATE 下 pending→approved/denied/expired 与事件写入同事务提交，只有获胜方能返回票据；并发两个连接批准仅成功一次。篡改、跨主体/会话、未知请求、不同签名密钥、已消费和已拒绝请求均拒绝。独立进程及不同随机种子复验通过。合同到期上限约束确认和批准票据，策略版本变化时 pipeline 拒绝旧请求。原重放例由 2 次读取变为 1 次，第二次抛 ConfirmationStateError。
3. **C-07：已增加预写保护，严格失败仍保留。** C 在 I/O 前持久化 execution_intent（prepared），之后以 execution 记录成功或失败，并链接该意图。意图写入故障阻止 I/O；执行结果写入失败抛 ExecutionAuditError，携带 intent_event_id，读取正文不向上返回。`AuditStore.pending_executions()` 可在重开数据库后查询未决操作，入口不自动重试。原 `execution_audit_fault` 仍只故障最终 execution 事件，仍观察到 1 次读取，因此 **“任何结果审计故障都不得已发生 I/O”断言继续 FAIL**；不同之处是现在留下持久化意图，原来只有 decision。新增可追溯性探针 PASS 不替代这个失败。

原三例均操作虚构只读文件，目标敏感文件全部保持原字节，没有实际外发或命令执行。本轮已修改 C 的生产实现；A 的公共模型、策略内核和冻结数据未改。有效审计哈希链只说明已保存事件未被篡改，**不说明缺失的完成事件已补全**。未决意图也不等于操作已发生：它还可能对应意图提交后、I/O 前的进程崩溃；不得据此直接重放。

**C-08 确认溯源已补齐：** decision → requested → approved → execution_intent → execution，5 个事件、4 条边；直接 ALLOW 为 3 个事件、2 条边。保留原上下文，即使 resolve 未再次传入也不会丢失。初次轨迹的 0 条边作为历史缺口保留。

## 状态和故障语义

确认表与审计事件属于同一个 SQLite 事务；审计写入失败会回滚状态转移，不会返回新票据。现有数据库采用新增表的兼容初始化；旧版本只有审计事件、没有绑定记录的确认请求不能恢复批准，按未知请求拒绝。记录 HMAC 使用调用方注入的签名密钥，测试中的公开虚构密钥不能用于生产。数据库和签名密钥都被攻破、数据库整体回滚、OS 旁路不在此保护范围内。

SQLite 票据计数与审计库/文件系统不属于同一个事务。意图写入失败可能已经消费票据；批准提交后进程崩溃也可能没有把票据交给执行器。这些情况选择少执行，不自动补发或重试。结果审计故障不能承诺文件回滚；后续 Linux WRITE 实测在完成审计失败时文件已改变，重开数据库后保留 1 条未决意图。确认记录绑定 CanonicalEffect，不新增任意工具参数/正文的独立取证或生产规范化能力。

## 尚未执行的 D5 项目

| 计划项目 | 当前状态与具体原因 |
|---|---|
| B 输入入口、Shell/路径/编码归约、Gateway 完整中介 | BLOCKED：没有生产模块或可运行接口，不能用 host_test_effect 代替 |
| 真实 EGRESS 与受控接收端 canary | BLOCKED：C v0 不支持 EGRESS，也无 B 网络适配器；没有创建网络接收端 |
| 实际 review → push / 下载执行 | BLOCKED：C v0 拒绝 REPO_MUTATE / EXEC；确认只读测试不能替代这些效果 |
| 真实子 Agent、MCP 工具变化、旧授权作废、重连与重复事件 | BLOCKED：缺少 B 注册表、manifest 生命周期、真实调度入口 |
| 原解释器/直接工具调用绕过中介、OS 隔离与禁网 | NOT_VALIDATED：Python 检查和测试宿主自愿门禁不能证明无旁路；本轮 socket 审计 hook 仅约束此 Python 进程 |
| 多语言、零宽/同形、片段累积、编码和稀释变体 | NOT_RUN：不在缺失生产规范化/中介链时生成“完整稳健性通过”结果；D3 原固定规则 FP/FN 保留 |
| 故障矩阵全覆盖、跨 MCP 真因果链、正文 token 因果归因 | NOT_RUN：仅实测表内故障及 Memory/C 边；不将人工来源边升级为真实模型因果证据 |
| 当前 D2–D5 源码的 Linux 全套验收与 POSIX 写入 | 工程 PASS：662 项全通过，3 个 WRITE 机制探针通过；完成审计故障的文件改变仍证明严格原子性不成立 |

下一步仍需补齐 B 的真实接口、C 的隔离环境与未决操作核查流程。严格的跨数据库/文件系统原子性断言未满足，不能直接进入完整系统评价或宣称无旁路。Linux 当前源码的执行方法和正式证据见 [Linux 验收](D5_linux_acceptance.md)。

## 工程检查与证据界限

修复阶段新增 31 项 C 安全回归测试通过，D5 子链 pytest 为 22 项通过，聚焦 426 项通过；Linux 入口又新增 20 项归档/路径回归通过。当前完整 Windows pytest 为 **656 通过、6 个历史平台失败**，Linux 为 **662 全通过、0 ERROR、0 SKIP**；原六项平台失败均在 Linux 通过。两个原集成测试和一个 broker 测试更新为明确要求新增的意图事件与父边，没有删减历史平台失败断言。唯一开放的严格故障验收由独立 `d5_eval.py` 无排除执行，入口仍退出 1。

Ruff check / format 与 Pyright 通过。随机种子 17、991 的 22 例断言、状态、I/O 次数和边数一致；UUID、绝对临时路径及时间会不同，不宣称原始轨迹逐字节一致。D1 三个冻结文件哈希未变。进程内 socket hook 未记录网络连接/DNS/数据报尝试，模型调用 0；该 hook 不提供操作系统隔离。

紧凑证据：[D5_subchain_acceptance.json](evidence/D5_subchain_acceptance.json)。本轮只保存本地源码、测试、报告和脱敏轨迹，不提交或推送 Git。
