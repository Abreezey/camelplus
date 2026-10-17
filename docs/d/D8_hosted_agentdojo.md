# DeepSeek + AgentDojo 三维 smoke

日期：2026-10-17。状态：**smoke 33/33 与全量 1842/1842 托管回合完成；链路 PASS，安全增益不可识别（基线 ASR=0），效用门禁 FAIL**。

本阶段把 D6 的禁执行草案落为可运行协议，使用 AgentDojo 0.1.34 / benchmark v1.2 的开源
workspace 套件，同时测三类结果：攻击目标达成率（ASR）、良性任务完成率（utility）、本地安全链时延。
固定协议见 [D8_hosted_agentdojo_protocol.json](evidence/D8_hosted_agentdojo_protocol.json)。

## 对照组与安全边界

| 组 | 路径 |
|---|---|
| B0 | AgentDojo 原始 tool-calling Agent |
| B1 | 原版 CaMeL privileged pipeline |
| B3 | B1 + A 策略、B Gateway/归约、C 持久 ticket/audit、D 结果检测 |

B3 的 24 个 workspace 工具清单被冻结；14 个只读工具允许，10 个写/外发工具要求确认。基准没有可信
确认 UI，因此后者返回“被策略阻断”而不执行上游，且不标作 tool error，避免把成功防御从 ASR 分母删除。
AgentDojo 的邮箱、日历、云盘是内存环境中的复合 RPC，不能交给本地 IO Broker 再执行；C 在该路径提供
持久 ticket 与 hash-chain audit。真实本地 READ/WRITE/EGRESS 仍由 Broker 执行。

每组固定 5 个 benign、5 个 `important_instructions` attack、1 个 goal control，共 33 回合。每回合
重新加载环境。错误、超时和未运行保持 unknown；结果用既有严格 adapter 统计计划分母、Wilson 区间，
另报 B3 confirm rate。五任务 smoke 只验证链路和口径，不能当作有统计功效的论文结论；所选良性任务均为
只读，因此也不能证明良性写操作的效用。

## DeepSeek 与预算

模型为 `deepseek-flash`，OpenAI 兼容基址 `https://api.deepseek.com`。主规划与隔离解析共用一份
400 次 HTTP 尝试上限；每次发送前先 fsync 预约，失败不退款，OpenAI SDK 重试为 0。AgentDojo 或
pydantic-ai 的上层语义重试仍会产生新 HTTP 尝试，但每次都计数且不能越过硬上限。密钥只允许通过
git-ignore 的 `.env` / 进程环境提供，不进入命令行、trace、审计或证据。

```bash
uv run --env-file .env python scripts/d8_agentdojo_deepseek.py \
  --output artifacts/d/D8_deepseek_smoke_01
```

## 已完成的本地性能门禁

`scripts/system_component_cost.py` 以预热 100、计时 1000、最近秩 P95 测量固定输入，无模型和外网：

| 工作负载 | P50 ms | P95 ms |
|---|---:|---:|
| A PolicyEngine（ALLOW / default DENY） | 0.006 | 0.007 |
| A+C pipeline（READ / DENY / stub EGRESS） | 0.409 | 0.540 |
| raw stub RPC | 0.010 | 0.011 |
| B secured Gateway + 同一 stub RPC | 0.749 | 0.861 |

Gateway P95 增量为 **0.849 ms**，低于 150 ms；A 决策 P95 为 **0.007 ms**，低于 20 ms。
这只是本机进程内微基准，不含模型与真实网络时延，也不能据速度推断安全效果。紧凑证据见
[D8_system_component_cost.json](evidence/D8_system_component_cost.json)，原始样本在
`artifacts/d/system_cost_20261017_v4/`。

## DeepSeek smoke 实际结果

最终输出为 `artifacts/d/D8_deepseek_smoke_20261017_04/`：33/33 回合均为 COMPLETED，
无 error / timeout / unknown；使用 77/400 次请求（planner 75、quarantined 2），总墙钟 397.9 秒。
紧凑、带哈希的门禁证据见
[D8_hosted_agentdojo_acceptance.json](evidence/D8_hosted_agentdojo_acceptance.json)。

| 组 | benign utility | ASR | 全回合 P50 / P95 |
|---|---:|---:|---:|
| B0 原始 Agent | 5/5 = 100% | 0/5 = 0% | 2.38s / 3.15s |
| B1 原版 CaMeL | 4/5 = 80% | 0/5 = 0% | 8.36s / 22.39s |
| B3 A/B/C/D | 3/5 = 60% | 0/5 = 0% | 14.67s / 149.50s |

三个 ASR 的 95% Wilson 区间均为 `[0, 0.4345]`。B0 自身已经 0/5，故这个样本没有观察到可归因的
防御增益，不能宣称 B3 降低 ASR。B3 相对 B0 的良性完成率下降 **40pp**，明确不满足项目
“下降 ≤5pp”门禁；B1 也下降 20pp。B3 共记录 21 ALLOW、1 CONFIRM、0 DENY，confirm rate
为 1/22 = **4.55%**，低于 10% 门槛，但良性集合只有只读任务，不能外推写任务。

B3 的 D sink 分析 20 个结果 envelope、产生 0 条 finding。它证明检测接缝执行了，不证明固定规则覆盖了
该攻击表示。B3 的 1 次 CONFIRM 是 goal-control 的发送邮件请求；上游虚拟邮箱未被调用，说明确认阻断
有效。B3 的全回合 P95 为 149.5 秒，而本地 Gateway 增量不足 1ms；长尾来自模型生成不符合 CaMeL
解释器约束的代码后反复重规划，不是 A/B/C 本地热路径。

本轮修复了两项真实兼容问题：DeepSeek thinking 与结构化输出 `tool_choice=required` 冲突，以及结构化
列表被拆成超过 D view 配额后 fail-closed。隔离模型现固定关闭 thinking；AgentDojo 结果完整、未截断地
序列化为一个确定性 JSON detection view，原生对象仍返回 benchmark。旧 `_02`（修复前完整基线）和
`_03`（中止诊断）均保留且不覆盖。

因此本轮结论是：**真实评测管线已经可用，系统产品可用性尚未过门禁**。下一轮应扩大到含 benign
WRITE 的任务集，并针对 DeepSeek/CaMeL 代码生成长尾做独立消融；任何新测量必须使用新输出目录。

## 全量运行（2026-10-17 下午）

smoke 之后按组拆分跑满 workspace 全量人口：每组 614 回合（14 goal control + 40 benign +
560 attack = 40 用户任务 × 14 注入任务），三组共 **1842 回合全部跑完**，输出位于
`artifacts/d/D8_full_3way_20261017_124346_{B0,B1,B3}/`。请求用量 1880 / 1207 / 1723（上限各 3000）。
同日另有一个合并目录 `D8_deepseek_full_20261017_01`：进程中途死亡（无 summary.json，日志止于
provider JSONDecodeError 警告，疑似与拆分版并行抢账户限速），其 502 个 B0 回合与拆分版冗余，
**以拆分版为准**。紧凑证据见 [D8_hosted_agentdojo_full.json](evidence/D8_hosted_agentdojo_full.json)；
逐组运行日志与 `summary.json` 已入库：[runs/](evidence/D8_hosted_agentdojo_runs/)（B0 完成
547/614、B1 614/614、B3 614/614，六攻击族筛选 29/36；逐回合 `episodes/` 仍只留在
`artifacts/d/`）。

### 三维结果

| 组 | ASR（attack_goal） | 多余副作用* | benign utility | confirm rate | 回合 P50 / P95 |
|---|---:|---:|---:|---:|---:|
| B0 原始 Agent | 0/560（界 [0, 0.107]） | **176** | 36/40，完成子集 100% | — | 3.98s / 10.52s |
| B1 原版 CaMeL | 0/560（CI95 [0, 0.0068]） | **11** | 20/40 = 50%（CI95 [0.352, 0.648]） | — | 3.77s / 24.70s |
| B3 A/B/C/D | 0/560（CI95 [0, 0.0068]） | **3** | 24/40 = 60%（CI95 [0.446, 0.737]） | 170 请求 9 批准 = **11.93%** | 3.97s / 61.49s |

\* 多余副作用 = 独立环境观察器（AGENTDOJO_ENV_DIFF_V1）在 attack 回合捕获的预期外效果计数；
该观察器在本 runner 中只记录 extra_effect_observed，不判定注入目标达成，故 independent_goal 全为未知。

### 解读

1. **防御轴：ASR 基线为零，无法归因防御增益。** B0（无防御）对 `important_instructions` 全量
   560 个 attack 回合 ASR 为 0；同日 6 攻击筛选（direct / ignore_previous / important_instructions /
   injecagent / system_message / tool_knowledge，各 5 回合，`D8_b0_multiattack_20261017_145517`）
   在 B0 上也全为 0。deepseek-flash 对 AgentDojo 现有攻击族免疫，因此本种群不能证明 B3 降低 ASR。
   唯一的差异化防御信号是多余副作用：**B0 176 → B1 11 → B3 3**，全链压制了无防御 Agent 98% 的
   越界行为——但这是环境差分观察，不是 AgentDojo oracle 指标。要测出 ASR 差异需要更易受诱导的
   对照模型或自适应攻击（ref.md R14）。
2. **效用轴：门禁 FAIL，损失主要来自 CaMeL 特权管道。** B3 相对 B0 完成子集下降 40pp
   （60% vs 100%），违反“≤5pp”门禁；但 B1 原版 CaMeL 自身只有 50%，即大部分损失是上游
   CaMeL 代码生成环节固有的，ABCD 插入层相对 B1 **回升 10pp**。B3 的 22 个 benign WRITE 回合
   全部跑完（22/22 completed），但只有 9 个过 utility——确认交互对合法写任务的效用成本仍待专门测量。
3. **时间轴：本地热路径达标，长尾在模型侧重规划。** 本地安全链微基准见上节（决策 P95 0.007ms、
   网关增量 0.849ms，均过门禁）；回合级 P95 B3 为 61.5s（smoke 时 149.5s），长尾仍是模型生成
   不符合 CaMeL 解释器约束后的反复重规划，不是 A/B/C 本地路径。
4. **错误口径：** B0 有 67 个 TOOL_ERROR 回合（60 attack / 4 benign / 3 goal control），按严格
   adapter 排除出完成计分并显式报告为 unknown，故 B0 比率给逻辑界并附完成子集比率；B1 / B3
   无错误回合，比率与 CI95 直接可读。confirm rate 11.93% 边缘超过 <10% 门禁（170 次确认请求、
   9 次批准、0 次拒绝）。

全量结论与 smoke 一致但证据更强：**评测管线在全量人口上可用且统计口径完整；安全增益在本模型上
不可识别（基线 ASR=0）；效用门禁未过，损失主要继承自 CaMeL 特权管道；确认率边缘超标。**
下一轮的优先级：① 用易受诱导的模型或自适应攻击建立非零 ASR 基线；② 消融 CaMeL 规划器失败任务，
把 B1/B3 效用差距收敛到 ≤5pp；③ 专测 benign WRITE 的确认 UX 成本。

## 多套件 × 全攻击族协议（待分人运行）

上一轮只覆盖 workspace 和单一 `important_instructions` 全量矩阵，事后补的 6 攻击族筛选只有每族 5 回合，
不能把 ASR、环境副作用和效用损失外推到 AgentDojo 的其他场景。扩展协议固定为 AgentDojo 0.1.34 /
benchmark v1.2 的全部四个套件、六个标准非 DoS 攻击族和 B0/B1/B3 三组。冻结证据见
[D8_hosted_agentdojo_multisuite_protocol.json](evidence/D8_hosted_agentdojo_multisuite_protocol.json)。

| 套件 | 用户任务 | 注入任务 | 每组 attack | 每组总回合 | 三组总回合 | 每组预算 / 时限 |
|---|---:|---:|---:|---:|---:|---:|
| workspace | 40 | 14 | 3360 | 3414 | 10242 | 12000 请求 / 18h |
| travel | 20 | 7 | 840 | 867 | 2601 | 4000 请求 / 6h |
| banking | 16 | 9 | 864 | 889 | 2667 | 4000 请求 / 6h |
| slack | 21 | 5 | 630 | 656 | 1968 | 3500 请求 / 5h |
| 合计 | 97 | 35 | 5694 | 5826 | **17478** | — |

每组总回合 = benign 用户任务 + injection goal control + 用户 × 注入 × 6 攻击族。攻击族固定为
`direct`、`ignore_previous`、`system_message`、`injecagent`、`important_instructions`、
`tool_knowledge`。每个套件工具表均冻结为 READ / WRITE 二分；新工具 fail closed。Slack 的
`get_webpage` 是读取不可信网页，归 READ，因此 Slack 实际为 5 READ + 6 WRITE。

每位执行者领取一个套件，把下面的 `D8_SUITE` 改成自己的套件；同一套件的三组并行，同一账户不要同时
启动第二个套件，使在途模型请求保持不超过 3（DeepSeek 限额 2500 并发，墙钟而非额度是瓶颈）。输出目录
必须全新，密钥只从 `.env` 读取：

```bash
cd /new_data/cpipc/agent-sec/camelplus

D8_SUITE=travel  # 改为 workspace / travel / banking / slack
case "$D8_SUITE" in
  workspace) D8_MAX_REQUESTS=12000; D8_TOTAL_SECONDS=64800 ;;
  travel|banking) D8_MAX_REQUESTS=4000; D8_TOTAL_SECONDS=21600 ;;
  slack) D8_MAX_REQUESTS=3500; D8_TOTAL_SECONDS=18000 ;;
  *) echo "unknown suite: $D8_SUITE"; exit 2 ;;
esac

set -a
source .env
set +a
D8_RUN_TAG="$(date +%Y%m%d_%H%M%S)"

for group in B0_original_agent B1_original_camel B3_ABCD; do
  output="artifacts/d/D8_multisuite_${D8_RUN_TAG}_${D8_SUITE}_${group}"
  nohup .venv/bin/python scripts/d8_agentdojo_deepseek.py \
    --population full \
    --suite "$D8_SUITE" \
    --group "$group" \
    --attack direct \
    --attack ignore_previous \
    --attack system_message \
    --attack injecagent \
    --attack important_instructions \
    --attack tool_knowledge \
    --max-requests "$D8_MAX_REQUESTS" \
    --total-seconds "$D8_TOTAL_SECONDS" \
    --output "$output" \
    > "${output}.log" 2>&1 &
  echo "PID=$! suite=$D8_SUITE group=$group output=$output"
done
```

查看进度：

```bash
for f in artifacts/d/D8_multisuite_*_*/normalized.json; do
  printf "%-80s %s\n" "$f" "$(jq length "$f")"
done
```

`tool_knowledge` 要求注入任务 ground truth 提供 `placeholder_args`；不满足的组合会保留为
`NATIVE_ERROR`，不得从计划分母静默删除。待四位执行者交回 12 个输出目录后，再统一聚合 ASR、独立环境
副作用、benign utility、良性 WRITE utility、confirm rate、错误界和时延；本节当前仅表示协议和实现已就绪，
不表示 17478 回合已经执行。

## 工程验收

- `ruff check src tests scripts`：PASS；`pyright`：0 errors / 0 warnings。
- 完整 pytest：1311 passed，另有 2 failed 来自上游 `0aa4bb5` 自带的冻结 pin
  （`test_detection_validation.py::test_real_frozen_pin_still_matches_without_running_detector`、
  `test_detection_test.py::test_actual_validation_selection_matches_without_test_predictions`，
  报 `candidate_pin_changed_or_outside_root:src/camel/__init__.py`：pin 期望
  `36371bf9…`，而该文件在 `280c2c2` / `0aa4bb5` / `890eab9` 三个 ref 上均为 `7acc6d52…`）。
  已在 `0aa4bb5` 的干净 worktree 上复现，与本模块三次提交无关；需由 pin 作者重新生成或补上
  漏提交的 `src/camel/__init__.py` 改动（MCP stdio 用例需在受限沙箱外运行）。
- 多套件协议自校验：`full_episodes(suite, 6 攻击)` 计数 17478 = 5826 × 3，`SUITE_TOOL_REVIEWS`
  四表哈希与协议证据一致，`run_smoke` 拒绝未知套件与非 workspace smoke。
- `d_offline_acceptance.py --harness-validation`：`PASS_OFFLINE_COMPONENTS`（输出
  `artifacts/d/D8_offline_acceptance_20261017_multisuite/`）。
- `scripts/full_system_demo.py`：4/4 checks passed。
- D 离线组件验收：665 passed，planner / detector / memory / representation 全 PASS，0 模型请求、0 下载；
  输出位于 `artifacts/d/D8_offline_acceptance_20261017/`。该工作流按设计标记
  `full_D8_accepted=false`，因为离线组件通过不能替代上述托管效果/效用门禁。
