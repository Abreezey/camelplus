# D6 离线控制器与预算预留

2026-10-15。本轮完成 D 自有的固定合成工作进程调度、预算预留、期限检查、中止与结果落盘，状态为 `PASS_SYNTHETIC_CONTROLLER_ONLY`。Windows 和 WSL 均通过 32 项新增测试；每平台 20 个合成回合、实际启动并确认退出 14 个子进程。

这些是实际子进程上的调度控制，子进程内容为固定假任务。没有运行模型 Agent、AgentDojo 环境或真实工具，不计算 ASR，不解除 B/C 或完整 D6 的缺口。

## 实现与边界

入口为 `scripts/d6_controller.py`；控制器和固定工作进程位于 `src/camel/adapters/agentdojo/controller.py`、`control_worker.py`。协议见 [D6_controller_protocol.json](evidence/D6_controller_protocol.json)。入口只有新输出目录参数，没有模型端点、任意命令或攻击运行选项。

每个运行先验证并写入全部预声明回合，再逐个执行：

1. 核对宿主取消状态、总期限和当前回合完整调用计划。
2. 同时检查全局及 planner、quarantined、detector、embedding 各角色的请求数、输入 token、最大输出 token、整数模拟成本限额；角色未配置或任一资源不足，整个回合不启动，不部分扣账。
3. 把完整预留与状态写到同一账本，文件 flush/fsync 后用 replace 替换；写入失败则不启动工作进程。启动前再次检查取消与期限，覆盖记录落盘耗时跨过期限的情况。
4. 只启动固定模块，按 monotonic 时间检查单回合和总期限。超时或取消后 terminate，必要时 kill，并 wait 确认退出后才继续。
5. 正常退出后校验模拟 usage 的调用序号、角色、数量和各项上限；缺失或超额则记 ABORTED，并停止派发后续回合。随后复用上一轮冻结的结果适配器保存规范化结果。

已预留额度不退款。进程崩溃、原生错误、工具错误和超时均不会触发自动重试；同一控制器不可再次 run，已有输出目录不可复用。单回合预算不足可以跳过该回合再检查其他预声明回合；宿主取消、总期限和 usage 故障会阻止后续派发。未运行回合仍保留在计划分母中。

这里的 token、request 和 cost_units 都是**合成计划的预留量**；cost_units 不是人民币或其他真实币种，也不是网关报价。工作进程返回的 usage 是人为生成的测试数据，超额检查是在返回后拒收。尚未接入真实模型各角色调用点、可信输入计数、提供方 max_tokens 或账单结算，因此不声称已验证真实 token 或费用的硬上限。

单回合期限从派发准备开始，包含落盘及启动时间；总期限从控制器初始化开始。期限触发停止，进程退出确认和落盘可能增加墙钟耗时，不能把期限值当作精确的总耗时上限。没有验证后代进程树或 OS 隔离。固定工作进程的网络/子进程 audit hook 仅为本轮离线限制。

账本保存 PLANNED、RESERVED、RUNNING 及终止状态；RUNNING 在启动前写入，表示待启动或运行中，不单独证明已启动。宿主意外崩溃可能留下 RESERVED/RUNNING 等未决状态；本轮不实现恢复、退款或重新执行。文件原子替换与 fsync 已使用，断电或整个宿主崩溃后的文件系统耐久性没有故障注入验收。控制器限定单实例、顺序执行，不提供跨进程共享预算。

## 实际控制结果

| 控制组 | 计划回合 | 实际子进程 | 结果 |
|---|---:|---:|---|
| 正常及错误 | 5 | 5 | 良性完成、目标完成、NATIVE_ERROR、TOOL_ERROR、进程崩溃 ABORTED 各 1 |
| 单回合期限 | 2 | 2 | 均 TIMEOUT；其中一个先写入模拟副作用，再阻塞，正观察仍保留 |
| 宿主取消 | 2 | 1 | 当前 ABORTED，后续 NOT_RUN |
| usage 超额 | 2 | 1 | 当前 ABORTED，后续 NOT_RUN；原 utility=True 不计分 |
| usage 缺失 | 2 | 1 | 当前 ABORTED，后续 NOT_RUN |
| 全局预算 | 2 | 1 | 首回合同时预留四角色各 1 次，下一回合预算不足 NOT_RUN |
| 角色预算 | 3 | 2 | quarantined/detector 可运行，planner 额度为 0 的回合 NOT_RUN |
| 总期限 | 2 | 1 | 当前 TIMEOUT，后续 NOT_RUN |
| 合计 | 20 | 14 | COMPLETED 5、NATIVE_ERROR 1、TOOL_ERROR 1、ABORTED 4、TIMEOUT 3、NOT_RUN 6 |

合计保留 17 个模拟请求预留：14 个实际子进程中有一个回合声明 4 个角色调用，因此请求数不能用子进程数替代。每组预算均未被预留量突破。所有启动的子进程均由宿主 wait 确认终止，账本保存退出码和耗时。

副作用观察读取工作进程独立写出的 state.json，并绑定 episode ID，不从原 security/utility 推导。目标完成控制和超时控制各保留一个正观察。此 state 是合成标志文件，不是上一轮真实内存环境中的邮箱，也未成为可信或经过认证的生产 observer。沿用用户保守口径：任何工具错误仍不进入完成计分；失败或超时不抹去已经观察到的正效果。

正式证据目录为 `artifacts/d/D6_control_windows_02/` 与 `artifacts/d/D6_control_linux_02/`。每个平台 67 份输出文件、7 份源输入摘要核对通过。normalized.json、metrics.json、accounting.json 的跨平台解析值完全一致；原始 ledger 的字段差异仅为实际 elapsed_seconds 和停止进程的平台退出码，未删除或伪造这些原始记录。01 为开发验收记录。

新增 **32 项测试在 Windows/WSL 均通过**，0 失败、错误、跳过；包括真实进程退出、取消、超时副作用、无 usage/超额 usage、四种全局资源拒绝、跨角色原子预留、持久化失败不派发、落盘后期限/取消复查、重复运行拒绝和未知结果分母。Ruff check/format 全项目通过（171 文件），Pyright 为 0 errors / warnings / informations。开发期两处类型标注问题已修复，正式验收使用最终版本。本轮未重跑项目全套或 D 专项全套。

前轮结果适配器 25 份、模拟环境预检 15 份、准备 21 份、复现工作流 14 份及表示鲁棒性 19 份历史证据摘要仍相符；原模型缓存 61 文件、A/B/C 的 D5 快照 25 文件及 Python 文件集合未变。独立验证保存在 `artifacts/d/D6_control_independent_verification.json`。

## 复现与剩余工作

在项目根目录运行，选择新目录：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe scripts/d6_controller.py --output artifacts/d/D6_control_repeat_01
```

该命令固定运行上表的离线控制。20 回合及模拟限额仅属于工程验收，不是对原 44 回合模型草案的新授权，也没有修改原草案。

本轮模型请求、AgentDojo 环境加载、真实工具调用、下载均为 0；没有修改 A/B/C、已安装包、旧结果适配器或原 oracle，没有暂存、提交或推送 Git。真实模型与各角色实际预算、生产 observer、B/C 接入和完整 D6 仍待后续确定。下一步可先将 D 的现有规划、检测、记忆模块接成一个受限离线演示；正式模型实验继续单独确定范围和预算。

紧凑验收见 [D6_controller_acceptance.json](evidence/D6_controller_acceptance.json)。
