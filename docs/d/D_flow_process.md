# D 串联流程的子进程控制与中断证据

2026-10-15。本轮把已验收的 D 串联流程放进固定工作进程，由宿主实施启动次数、单回合/总期限及取消检查，状态为 `PASS_D_OFFLINE_PROCESS_FLOW`。Windows 和 WSL 各 23 项新增测试通过；每平台 24 个计划流程、21 个实际启动并确认退出的子进程。

此前的 13 个流程结果与直接运行版本完全一致；超时、中止、崩溃及记录器错误不再依赖调用者手填状态。完整 D6/D7/D8 仍未验收：这不是模型 Agent、真实工具或 AgentDojo 任务评测。

## 接入方式与结果口径

实现为 `src/camel/evaluation/flow_process.py`、`flow_worker.py`，入口为 `scripts/d_flow_process_eval.py`，协议见 [D_flow_process_protocol.json](evidence/D_flow_process_protocol.json)。原 connected.run_flow、规划器、检测器、Memory Gate 和旧合成控制器均未修改；新控制器复用原来的有界 JSON、文件 fsync/replace 等接口，只启动固定的 `camel.evaluation.flow_worker`。

新流程不伪造 AgentDojo utility/security 日志，分开保存三个维度：

- 宿主状态：正常退出、超时、取消、非零退出、未运行。
- 原始流程裁决：RECORDED、MEMORY_BLOCKED、RISK_BLOCKED 等，来自真实串联模块返回值。
- 独立记录观察：从单独的记录文件检查身份、READ 范围及正文，不从流程裁决或退出码推断。

只有宿主正常结束、结果与记录匹配、没有错误文件或未决意图，才为 COMPLETED 并填 completed_flow_terminal。正常完成的流程可以返回 RISK_BLOCKED；COMPLETED 不表示用户任务完成或攻击失败。非完成回合的原始 flow_terminal 可保留，但 completed_flow_terminal 为 null。ASR 和 task_utility 始终为 null。

按用户选择的保守口径，即使原流程为 RECORDED 且子进程正常退出，只要存在记录器错误证据，仍判 ERROR，不当作恢复成功。本轮用显式合成错误文件验证这一矛盾状态，并未调用外部工具制造真实服务错误。

## 记录与未决状态

JournalRecorder 在内存 RecordingTool 追加前写入一条意图，追加后另行落盘实际记录。宿主在子进程退出后读取：

- 已落盘且校验通过的记录，在超时、取消或错误后仍作为正观察保留。
- 仅有意图而没有记录，保留 pending_intents，不能推断为效果已发生，也不能推断为没有发生。
- 记录身份、资源、正文或数量异常，不进入完成结果；原始文件保留。

这些记录只是**模拟 READ 账本**，没有实际读取目标 README 或产生外发/写入工具效果。它们不是 C 的 execution_intent，也不替代 D5 的真实执行审计。新增磁盘故障测试还覆盖“内存账本已追加、记录文件写失败”：该时刻只有未决意图，证明不能把记录文件缺失直接当作没有动作。

全量计划先落盘，启动次数预留在派发前保存；持久化失败不启动。记录落盘后再次检查期限/取消，失败不退款或重试。max_model_requests 严格固定为 0，模型端点/任意命令没有入口。本轮的预算是流程启动次数及时间，不把模块调用计作真实模型 request/token/费用。

期限包含派发准备和启动；停止与退出确认、后续落盘可增加实际耗时。父进程崩溃可能留下 RESERVED/STARTING 等未决状态，本轮不恢复、不重新派发。网络 hook、固定子进程停止与文件 fsync/replace 不是 OS/进程树隔离或断电耐久性证明，也没有实现原子刷新记忆并执行。

## 实际验收结果

| 控制组 | 计划 / 启动 | 结果 |
|---|---:|---|
| 原 13 个串联控制 | 13 / 13 | 全部正常返回；原 2 个模拟 READ、11 个阻止记录及误报/漏检保持原样 |
| 中断与错误 | 5 / 5 | 流程前阻塞、记录后阻塞、意图后阻塞均 TIMEOUT；结果后非零退出及合成记录器错误均 ERROR |
| 记录后宿主取消 | 2 / 1 | 当前 ABORTED，保留一个 READ；后续 NOT_RUN |
| 启动预算不足 | 2 / 1 | 首回合正常完成，后续 NOT_RUN |
| 总期限耗尽 | 2 / 1 | 当前 TIMEOUT，后续 NOT_RUN |
| 合计 | 24 / 21 | COMPLETED 14、TIMEOUT 4、ERROR 2、ABORTED 1、NOT_RUN 3 |

共观察到 7 条已落盘模拟 READ，包括超时、非零退出、错误和取消后的记录；另有 1 条未决意图。14 个 COMPLETED 包含 11 个正常返回拒绝的流程，不能解释成 14 个任务成功。原良性引用误隔离和零宽文本漏检没有修复或隐藏。

正式目录为 `artifacts/d/D_flow_process_windows_01/` 与 `artifacts/d/D_flow_process_linux_01/`。每平台 126 份输出及 45 份源输入摘要核对通过，21 个工作进程退出确认通过。两平台 observations.json、freeze.json 解析值一致，原始 controller.json 的字段差异仅为实际 elapsed_seconds 与终止进程的平台退出码。13 个常规工作进程的完整 result.json 分别与上一轮直接运行的 observations 对应行相同。

新增 **23 项测试在 Windows/WSL 均通过**，0 失败、错误、跳过；覆盖实际流程等价、超时/取消/错误后记录保留、未决意图、0 模型额度、启动预算不退款、落盘失败与启动前复查、结果/记录身份和范围、重复运行拒绝，以及“流程正常拒绝”与“任务成功”分离。Ruff check/format 全项目通过（178 文件），Pyright 为 0 errors / warnings / informations。本轮未重跑项目全套或 D 专项全套。

独立核对原串联流程 16 份、控制器 34 份、结果适配器 25 份、模拟环境预检 15 份、准备 21 份、离线工作流 14 份、表示鲁棒性 19 份历史证据摘要仍有效；D1 三份冻结 fixture、61 份模型缓存及 A/B/C 的 D5 快照 25 文件和 Python 文件集合未变。见 `artifacts/d/D_flow_process_independent_verification.json`。

## 复现与剩余范围

在项目根目录选择新输出目录：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe scripts/d_flow_process_eval.py --output artifacts/d/D_flow_process_repeat_01
```

命令固定运行上表的工程控制，不读取聊天 API key，不接模型或实际工具，模型请求、真实工具调用、下载均为 0。没有修改 A/B/C、旧模块、规则、模型缓存或冻结数据，没有暂存、提交或推送 Git。B 的生产规范化/Gateway、C 执行与完整审计、可信身份/observer、真实模型及其各角色预算仍待后续接入。

紧凑验收见 [D_flow_process_acceptance.json](evidence/D_flow_process_acceptance.json)。
