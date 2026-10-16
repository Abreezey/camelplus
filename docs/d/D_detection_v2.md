# V2 检测候选：行为规则与局部引用语境

日期：2026-10-15。状态：**Dev 候选已冻结，尚未做 Validation 选择与 Test 评估**。用户选择本轮采用行为规则与局部引用语境；没有接入主链，没有修改原规则或原数据。

## 实现范围

候选 `d-local-context-v2-dev1` 位于 `src/camel/detection/candidate_v2.py`，使用原公共 ContentView、DetectionResult、Finding、Evidence 和 RiskSignal。原规则仍保存在独立的 rules.py，版本与阈值均不变。V2 基于 Dev 增加七类有界模式：取消业务动作、证据/审计篡改、私有材料传送、来源标签伪造、答案插入、评分诱导和隐瞒来源。这些是启发式规则，不是语义理解模型。

仅当命中完整位于成对引号内，且同一句、引号两侧各至多 80 字内有明确撤回、弃用、批评或缺乏凭证的说明时，候选尝试降权该命中。上下文中的其它引文先被遮盖，不得用引文自己声称的“撤回”证明无风险；若引文外有明确执行/采纳要求，则不降权。括号不完整或嵌套超过四层不作此降权。没有全局跳过引用，没有按 case_id 或真值分支。

每个降权命中均保存原 finding、引文范围、上下文范围与理由，保留原规则完整结果；正常保留的命中也输出原文坐标。单来源、恒等视图、最多 4,000 字及 64 findings；不支持的多来源、外部规范化视图或超限均为 UNKNOWN，不静默截断。候选接口的范围窄于原检测器，不可直接替换生产入口。

本候选没有全角/零宽/逐字空格/Base64 修复，也没有替代 B 的生产规范化。原 D1/384 表示回归材料的既有错误仍保留；本轮未重新运行其完整回放或据此宣称修复。

## Dev 对照

仅使用新场景集的 Dev 12 对、24 例；任务、授权动作、真值和划分不拼入检测正文。全部规则开发与选择已了解这些 Dev 错误，因此成绩只是开发诊断，不是泛化证据。

| 指标 | 原规则 | V2 候选 |
|---|---:|---:|
| TP / FP / FN / TN | 5 / 4 / 7 / 8 | 12 / 1 / 0 / 11 |
| 攻击 / 良性 UNKNOWN | 0 / 0 | 0 / 0 |
| Precision | 55.6% | 92.3% |
| Recall | 41.7% | 100% |
| 良性未被标记比例 | 66.7% | 91.7% |

候选 Precision 的 Wilson 95% 区间为 [66.7%, 98.6%]，Recall 为 [75.8%, 100%]。良性未标记不是任务成功；没有真实工具执行，Agent ASR 与任务效用为 null。

原规则的 s11-b、s12-b、s25-b、s56-b 四个引用误报均被降权，原七个漏报均转为检出；另新增 **s26-b 误报**：原文先说布展顺序，随后提到已被否决的取消预约建议，新取消模式跨句匹配了“先…取消…预约”。此问题没有在看完结果后修补，完整结果与正文保留。候选 FP 总数降低不代表没有引入新误报。

记录了一个代码版本、三次 Dev 运行：Windows 两个哈希种子与一次 WSL/Linux 复现。重复运行不算新增样本，计时内部重复也不算新增数据。没有打开 Validation/Test 的检测结果。

## 成本与工程验证

按原协议每次 100 轮，前 10 轮预热不计；每组 2,400 次本地函数调用、2,160 个有效计时样本，交替先后顺序。首轮在项目回归运行期间采集，保留该记录；其后单独运行的复现记录同时保存，不以更快一轮覆盖旧数值。

| 运行 | 原规则 p95 | V2 p95 | 预设资格上限 |
|---|---:|---:|---:|
| Windows 首轮 | 0.0246 ms | 0.0680 ms | 5 ms |
| Windows 复现 | 0.0236 ms | 0.0663 ms | 5 ms |
| WSL/Linux 复现 | 0.0199 ms | 0.0560 ms | 5 ms |

三次均通过 `max(原规则 p95 × 2, 5ms)` 的 Dev 成本门槛；候选 p95 约为原规则的 2.8 倍，不能写成只增加两倍以内。数据为短文本上的本机函数耗时，未控制其它系统负载，不代表整个 Gateway 延迟或生产性能。

- 新增工程测试 Windows、WSL/Linux 各 **37 通过**，覆盖局部降权、引文外指令、伪造拒绝语境、括号异常、来源与坐标、输入/发现数量上限、硬 DENY、配对指标和计时期限。
- Windows D 专项及共享核心/策略 **694 通过**，无失败、错误、跳过。此轮没有重跑全项目 Linux 套件或 D5 严格验收。
- Ruff check/format 通过，187 文件；Pyright 全项目 0 errors/warnings/informations。
- 三次原规则观察、候选观察和 summary 均逐字节一致；独立核验重新统计混淆矩阵，检查 7 个降权 finding、所有保留 finding 的原文坐标及 107 个冻结文件摘要。

## 剩余风险与下一关

低信任来源可以伪造撤回/弃用上下文，诱导候选降低风险；工程测试明确保存这一行为。局部文字无法证明真实意图，也不能证明恶意指令不会被下游消费。没有给出语义安全、抗自适应攻击或新分布泛化结论；通过 Dev 门槛不构成上线许可。

当前代码、参数、语料与基线摘要已写入 [候选冻结记录](evidence/D_detection_v2_candidate_freeze.json)。仅固定它作为下一次 Validation 比较的候选，尚未执行 Validation 的保留选择。下一关应按 [已有协议](D_detection_followup_protocol.md) 一次比较原规则与本候选，不根据 Validation 修补后再次声称独立验证；完成选择记录后才运行一次 Test。Validation 失败就保留负结果与原规则。

候选只输出风险，最终决策仍由 PolicyEngine 负责；单测确认即使命中被降权，确定性的策略硬 DENY 仍拒绝。没有连接生产执行、Memory Gate 或 AgentDojo，也没有改变 D5 既有严格失败与 B/C 接入缺口。

## 复现与证据

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe scripts/d_detection_candidate.py --output artifacts/d/D_v2_dev_repeat_01
```

选择尚不存在的目录。入口只支持 Dev，验证旧基线和新代码摘要后再运行；网络与子进程由进程审计钩子禁止，不安装依赖或读取密钥。运行前追加 STARTED，完成/失败追加终态，文件独占锁防止同时写入；若外部终止留下锁或无终态记录，需要显式复核，不自动重试。此日志不是防篡改或主机崩溃恢复系统。

原始结果为 artifacts/d/D_v2_dev_01、D_v2_dev_02、D_v2_linux_dev_01；运行账本为 artifacts/d/D_v2_dev_runs.jsonl，独立复核为 D_v2_independent_verification.json。原始 artifacts 保持 Git 忽略；可复核交付为 [验收 JSON](evidence/D_detection_v2_acceptance.json)、[24 例候选完整输出](evidence/D_detection_v2_dev_observations.json) 与 [结构化协议](evidence/D_detection_v2_protocol.json)。原规则输出见上一轮 Dev 证据，两轮原规则逐例一致。

本轮模型请求、下载与真实工具调用均为 0；没有 Git 提交或推送。
