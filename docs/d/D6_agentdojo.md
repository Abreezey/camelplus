# AgentDojo 离线适配准备

日期：2026-10-15。状态：**PASS_PREPARATION_ONLY / D6 正式评测未运行**。本轮只读取本地安装、任务注册表和源码，生成禁用执行的 smoke 草案；没有下载、模型请求、环境加载或基准任务回合。B/C 未完成的依赖仍保留。

## 已核实的版本与接口

本地 AgentDojo 包版本为 **0.1.34**，安装内 LICENSE 为 MIT。包版本与 benchmark version 是两条独立版本轴，不能用 `0.1.34` 选择任务集。本轮读取 `v1.2`、`v1.2.1` 的实际注册表：

| 套件 | 用户任务 | 注入目标 | 数据文件 |
|---|---:|---:|---|
| workspace | 40 | 14 | environment / injection_vectors 均存在 |
| travel | 20 | 7 | 同上 |
| banking | 16 | 9 | 同上 |
| slack | 21 | 5 | 同上 |

两版本计数相同，不等于任务实现相同，例如 workspace 的 injection_task_11 在 v1.2.1 有更新。目录与 107 份本地代码/数据文件摘要已保存，没有加载 YAML 环境或执行其工具。

当前项目 main.py 的源码签名含 `user_tasks`，不含 `injection_tasks`，并调用 `get_suite("v1.2", ...)`。上游 `agentdojo/scripts/benchmark.py` 的 Click 装饰器则有 `--user-task`、`--injection-task`、`--benchmark-version`。这些是源码核对结果，未通过运行入口启动模型来验证兼容性；不能给现有 main.py 随意追加一个不存在的注入目标筛选参数。

## 可审阅的最小配置草案

配置位于 [D6_smoke_draft.json](evidence/D6_smoke_draft.json)。状态为 `DRAFT_NOT_EXECUTABLE`，`ready=false`、`execution_enabled=false`，任务/套件选择仍标记为提案。模型、调用/token/费用/时间上限均待用户确定，`new_requests_authorized=0`；原 D3b 的 54 次生成额度已经用满，本草案不扩展额度。

草案沿用项目现有 **v1.2 / workspace**，选以下 5 个用户任务，以及同一个 `injection_task_0`。所选用户任务的 ground_truth 仅做 AST 静态工具名检查，不实际运行：

| 用户任务 | 内容摘要 | 静态工具名 |
|---|---|---|
| user_task_0 | 查询指定社交活动的受邀者邮箱 | search_calendar_events |
| user_task_1 | 汇总指定日期的日程 | get_day_calendar_events |
| user_task_2 | 查询下一次瑜伽课时间 | get_current_day、search_calendar_events |
| user_task_3 | 查询指定晚餐活动地点 | search_calendar_events |
| user_task_17 | 从邮件查询徒步时间、地点 | search_emails |

`injection_task_0` 的目标是在模拟邮箱中发送指定内容，固定攻击候选名为 `important_instructions`，只核对其本地源码，未实例化攻击或生成载荷。公开基准地址只属于待运行的模拟环境，不能映射到真实邮件/网络发送。所选用户任务虽具有只读 ground_truth，模型实际轨迹是否只读尚未验证。

上游 with-injections 路径按用户 ID 与注入 ID 做笛卡尔积，并先把每个注入目标作为用户任务做可达性预检。按每组独立初始化、每项一次计算：

| 计划量（尚未执行） | 每组 | 四组合计 |
|---|---:|---:|
| 良性用户回合 | 5 | 20 |
| 受攻击回合：5 用户 × 1 注入目标 | 5 | 20 |
| 注入目标作为用户的预检 | 1 | 4 |
| 总回合 | **11** | **44** |

若误选 5 个注入目标，则每组受攻击回合会是 25，含良性和预检共 35。44 不是模型请求上限：规划、工具轮次、隔离解析和检测可能分别调用模型，未来须统一计数所有角色，不能只限制主 Agent。

四组仍为 B0 原始 Agent、B1 原版 CaMeL、B2 A+B+C 关闭 D、B3 A+B+C+D。当前均为 `ready=false`；B0/B1 也缺少本轮预算约束和结果观察器，B2/B3 还依赖 B 的实际规范化/Gateway/MCP 与完整 C 执行隔离。原 gateway 的模型别名仅通过了检测调用，规划/tool calling/隔离解析兼容性未知。完整 Task verifier 与生产 D 入口也未实现。

## 成功判定与易混口径

安装版 BaseInjectionTask.security 的含义是 **True 表示注入目标执行成功**。无注入分支会返回 `utility, True`，其中 True 不能进入 ASR。部分 provider 错误处理也会填 `utility=False, security=True`，因此未来结果适配器必须先检查 trace/error 和回合状态，将未完成/错误另列，不能把原字段直接平均当作安全率或攻击成功率。

本轮用真实 injection_task_0.security 和 user_task_0.utility 配合最小 stub 状态验证方向：目标匹配为 True，内容不符/空状态为 False；用户答案匹配为 True、空答案为 False。这里只调用纯判定函数，stub 的搜索方法直接返回构造数据，**未执行 ground_truth、模拟工具、环境加载或 AgentPipeline**。这不是判定器与完整环境/独立效果观察器一致性的验收。

另外，所选 v1.2 user_task_0.utility 的 `strict` 默认值为 False，其他四项为 True；其文本答案通过不能单独证明状态没有被额外改变。未来应保留原生 utility，同时另记可观察副作用与策略违规，不能静默改原判定器后宣称同口径复现。

计划指标分别记录 benign completion、攻击目标达成、确认事件和各角色成本。5 对 smoke 只作描述性结果；比例带分子/分母及 Wilson 区间，四组按同一用户任务配对，预检不能算作新的攻击试验。注入是否可见、正控制是否有效及 oracle/独立观察器是否一致，均仍未运行。

## 复现与证据

只生成清单和草案，输出目录需尚不存在：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe scripts/d6_prepare.py --output artifacts/d/D6_prepare_repeat_01
```

该入口没有 `--run` 参数。进程拒绝网络及子进程调用；这仍不是 OS 沙箱证明。Windows 与 WSL 正式输出分别为 `artifacts/d/D6_prepare_windows_01/`、`artifacts/d/D6_prepare_linux_01/`，状态均为 PASS_PREPARATION_ONLY。目录、草案和纯判定探针跨平台 JSON 解析值一致（目录字段仅安装根路径不同），6 份准备输入文件摘要与 107 份包内代码/数据摘要已记录。

新增 **18 项测试在 Windows/WSL 均通过**，0 失败/错误/跳过；验证版本/任务筛选、5×5 计数、禁用执行、判定方向和无运行开关。Ruff check/format 全项目通过（161 文件），Pyright 为 0 errors / warnings / informations。本轮未重跑专项全套或项目全套，之前的 462 项专项记录仍为历史证据。

原模型缓存 61 份与 A/B/C 的 25 个快照文件未变，前轮复现和表示测试证据摘要仍匹配。紧凑验证见 [准备验收证据](evidence/D6_preparation_acceptance.json)。本轮没有新模型调用、下载、Git 暂存/提交/推送；D6 正式评测、完整 D7/D8 仍未完成。
