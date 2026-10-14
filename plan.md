# CaMeL 二次开发：4 人分工计划

> 依据：[arch.md](./arch.md)（架构与实施计划）、[ref.md](./ref.md)（论文依据）、CLAUDE.md（开发行为规范）。
> 本文件只定义分工、交付物与验收标准，不设定时间限制。排期按 arch.md §10 阶段门禁推进。

## 1. 分工总览

按**纵向工作流负责制**分工：每个人对自己的模块从设计、实现到验收负责到底，避免阶段交接丢失安全语义。arch.md 的组件依赖链为 `core → normalization/gateway → broker → detection/memory`，分工与之对齐。

| 成员 | 工作流 | 负责模块（arch.md §9） | 论文依据 |
|---|---|---|---|
| **A · 安全内核** | 核心模型 + 策略裁决 | `core/`（TrustLabel、IntentContract、CanonicalEffect、Decision、CanonicalEvent）、`policy/`（Typed DSL、IFC、能力票据、Decision Composer） | R02 / R03 / R15 / R17 / R22 |
| **B · 通道与规范化** | 输入入口 + 效果归约 + 网关 | Ingress 规范化、`normalization/`（fs / shell / net / git / mcp）、`gateway/`（MCP stdio/HTTP 代理、manifest digest） | R07 / R08 / R09 / R13 |
| **C · 执行与审计** | 沙箱执行 + 用户确认 + 溯源 | `broker/`（沙箱、egress 代理、凭据注入）、确认 UI/API、`audit/`（事件存储、provenance DAG、报告） | R16 / R17 / R18 |
| **D · 智能与评测** | 规划器 + 检测 + 记忆 + 基准 | `planner/`（IR、TDG、Contract Compiler）、隔离 LLM 加固、`detection/`（分层检测）、`memory/`（Memory Gate）、`adapters/agentdojo/`、全部基准评测与消融 | R01 / R04 / R05 / R06 / R10 / R11 / R12 / R14 |

## 2. 各角色职责与验收标准

### A · 安全内核

**职责**

1. 定义并冻结 5 个版本化 Pydantic 核心模型（arch.md §5），生成 JSON Schema；跨进程只传版本化 JSON，禁止自由格式字典。
2. 把现有 `Allowed | Denied` 二态升级为三态 Decision Composer（ALLOW / CONFIRM / DENY，任一硬 DENY 即 DENY，风险只能升级不能降级）。
3. 实现小型强类型、默认拒绝的 YAML 策略 DSL（Pydantic 编译为纯谓词，语义参考 Progent [R03]）。
4. 实现机密性/完整性双维标签传播（IFC，参考 Fides/DIFC [R02][R15]），LLM 不可修改标签。
5. 实现一次性能力票据：绑定 `subject + exact effect hash + resource + destination + expiry + max_uses`，不可转移。
6. 提供旧 `capabilities/*` 与旧安全策略的兼容转换层（迁移完成前不删旧代码）。

**验收**

- 不变量 I1–I7（arch.md §3）全部有单测或性质测试（authority 不扩张、秘密不流向低 clearance、硬拒绝不可被覆盖）。
- 旧四套 AgentDojo 策略可无损转换为 DSL fixture，作为黄金测试通过。
- 决策重放一致率 100%（固定策略与输入时）。

### B · 通道与规范化

**职责**

1. Ingress：Unicode NFKC、零宽/控制字符标记、可逆解码预算；原文与规范化文本并存，策略匹配规范化文本，取证引用原文。
2. Effect Normalizer：把 fs / shell / net / git / mcp 调用归约为 `CanonicalEffect[]`（arch.md §6.4）：
   - 路径：绝对化、`realpath`、符号链接边界、工作区根校验；
   - Shell：AST 解析管道、重定向、子命令、`curl | sh`、base64 解码执行；不用正则解析 Shell；无法可靠归约的高影响命令 fail closed；
   - 网络：规范化 scheme/host/port，拦截私网、metadata endpoint、DNS rebinding、非授权 egress；
   - Git：区分只读、工作区修改、commit、remote 修改、push。
3. MCP Security Gateway：stdio 与 Streamable HTTP 代理，成为 MCP 注册、发现、调用和返回的唯一通道；保存 server identity 与工具 schema/description digest，变更即暂停工具并产生 `tool_manifest_changed` 事件。
4. 返回值交给 Agent 前封装来源与标签，进入检测器与审计。

**验收**

- 对抗语料（危险路径、管道、重定向、编码执行、rug pull）全部被正确归约，危险用例零放行。
- 所有测试工具调用必须经 Gateway，无旁路。
- 本模块是 arch.md 指定的**首个独立高覆盖测试模块**，单测覆盖率全项目最高。
- 差分测试：原始调用与规范效果在允许环境中的实际效果一致。

### C · 执行与审计

**职责**

1. Execution Broker：在 OS 层执行已批准效果；Agent 进程不持有长期密钥，Broker 按票据注入短期凭据或 opaque handle。
2. 沙箱 profile：只读根、显式可写挂载、独立临时目录、系统调用约束；网络默认拒绝，egress 经代理复核实际 DNS/IP、重定向与请求体标签；高风险命令使用容器/轻量 VM（namespace / seccomp / Landlock）。
3. 确认 UI/API：CONFIRM 时向用户展示具体资源、接收方与后果；确认后签发一次性票据（票据格式由 A 定义，C 负责签发与校验的执行侧）。
4. Audit：追加式事件存储（首版 SQLite，payload 与 metadata 分离，秘密只存哈希/受控引用）；哈希链或批次 Merkle root 防静默修改。
5. Provenance：用 `trace_id + parent_ids + derived_from` 重建跨 MCP、Agent、会话、记忆链路，输出攻击 DAG 与时序报告。

**验收**

- 绕过解释器/Gateway 的直接调用仍被阻断（旁路测试）。
- 票据不可跨主体、跨效果复用，过期与超次数使用被拒绝。
- 审计事件包含策略版本、模型版本、工具 manifest digest 和代码提交；另一名评审者可仅凭事件 + 策略版本重放决定。
- 决策日志默认脱敏，不含 API key、完整 secret、思维链。

### D · 智能与评测

**职责**

1. Planner：沿用 CaMeL Privileged LLM 生成结构化程序，编译为受限 IR + 工具依赖图（TDG）与 Intent Contract；不可信工具结果可补充参数，不能新增高权限分支，扩权必须重新确认（参考 IPIGuard/Task Shield [R05][R04]）。
2. 隔离 LLM 加固：无网络、无工具运行配置，仅做数据解析，输出经严格 schema 验证并记录结构化审计。
3. 分层检测（只产生 RiskSignal，只能把风险向 CONFIRM/DENY 提升，不得覆盖硬规则 DENY）：确定性规则 → 本地分类/embedding → 独立 LLM verifier（固定输出 schema、最小必要上下文）。
4. Memory Gate：记忆条目保存原始来源、写入主体、敏感性、完整性、TTL 与策略版本；摘要/合并继承所有父来源；检索结果仍按不可信数据处理；高风险记忆进入 quarantine 分区（威胁依据 AgentPoison [R10]）。
5. 评测：AgentDojo 基线复现与回归 [R11]，补充 ASB [R12]、MSB [R13]；自适应红队作为发布门禁 [R14]；负责全部消融实验。

**验收**

- 故障注入证明：检测器失效（超时/无效 JSON/被绕过）时硬不变量仍成立。
- 跨会话记忆污染场景：检索命中不被重标为用户指令，provenance 因果链可回放。
- 达成 arch.md §10.2 质量指标：AgentDojo/MSB ASR 相对无防御显著下降（报告置信区间）；benign task completion 相对当前 CaMeL 基线下降 ≤ 5 个百分点；benign confirm rate < 10%；参数级 provenance precision/recall ≥ 95%（合成真值集）。
- 必做消融：分别关闭输入检测、Task verifier、IFC、Intent Contract、Gateway、Memory Gate、Sandbox，比较 ASR、效用、确认率、时延。
- 性能：规则/IFC 决策 P95 < 20 ms；Gateway 总 P95 增量 < 150 ms（均不含外部 LLM 调用）。

## 3. 共同任务与协作接口

**全员共同参与（每个阶段起点）**

- 阶段 0 基线冻结：锁定依赖、AgentDojo 版本、模型与随机种子，保存 utility / security / 时延基线报告；现有 pytest / ruff / pyright 全绿后才进入开发。
- 阶段 5 发布门禁：四条命令全绿 + 固定种子 AgentDojo 回归 + 对抗语料 + 策略快照重放 + 依赖/SBOM 扫描。

**跨角色接口（先冻结、后并行）**

| 接口 | 提供方 → 使用方 | 冻结物 |
|---|---|---|
| 核心模型 schema | A → B / C / D | 5 个模型的 JSON Schema v0，之后只增量演进 |
| CanonicalEffect 映射表 | B → A | 各适配器归约出的效果类型清单，供策略 DSL 引用 |
| 票据格式 | A → C | 票据字段与签名方式；C 负责签发/校验执行 |
| 决策流程 | A + B → 全员 | arch.md §7 固定判定优先级，任何模块不得改变硬拒绝语义 |
| RiskSignal schema | D → A | 检测器输出格式（含检测器版本、置信度、证据范围），供 Decision Composer 合并 |

**执行顺序约束**

1. A 先冻结核心模型 schema，B / C / D 才能并行开发；
2. B 的 Normalizer + Gateway 先于 C 的 Broker 集成（Broker 只对规范化效果负责）；
3. D 的检测器、TDG、Memory Gate 最后接入，且**不得改变硬拒绝语义**（arch.md §13）。

## 4. 协作规则（CLAUDE.md + arch.md §12，全员遵守）

1. **开工前**：每个 PR 首部写四项——问题（现有行为与风险）、假设（信任边界、输入范围、不处理的情况）、最小方案（改与不改的模块）、验收（可自动验证的成功/失败样例）。存在两种合理安全语义解释时必须先澄清，不静默选择。
2. **简单优先**：最少代码解决当前问题；纯函数、显式数据模型、表驱动策略优先；首版用 SQLite/JSON，不预建插件框架，不因"将来可能"引入 Kafka/图数据库；不用 LLM 解决确定性问题。
3. **外科式修改**：每个 PR 只解决一个可描述问题；不顺手重构无关代码；保持现有 API 兼容层，迁移完成且有调用证据后再删除；变更新增的未使用代码同 PR 清理，既有死代码另开 issue。
4. **安全编码**：默认拒绝；异常、超时、未知枚举不得隐式放行；任何外部效果先规范化、再裁决、后执行；日志默认脱敏；LLM 输出永远按不可信输入处理并严格 schema 验证；安全边界代码禁止可变默认参数、动态 `eval/exec`、宽泛异常吞噬、不受限反序列化。
5. **Definition of Done**（arch.md §12.5）：正常/拒绝/边界/故障用例齐全；威胁模型或不变量有对应测试；lint、类型检查、单测与集成测试通过；有可观测指标与结构化审计（不含秘密）；有性能基线且无未解释回退；文档说明输入、输出、失败策略与非目标；另一名评审者可仅凭事件和策略版本重放决定。
6. **安全修复流程**：先加入最小复现测试，再修复，再保留为回归测试。
7. **评审**：阶段出口由非牵头人复核；每个阶段只有验收门槛（arch.md §10 出口条件）全部通过才进入下一阶段。

## 5. 交付物清单

| 交付物 | 负责人 |
|---|---|
| 基线报告（依赖锁定、AgentDojo utility/security/时延） | 全员（D 汇总） |
| 5 个核心模型 + JSON Schema + 兼容转换层 | A |
| 三态 Decision Composer + 策略 DSL v0 + IFC + 能力票据 | A |
| fs/shell/net/git Effect Normalizer + 对抗语料 | B |
| MCP Security Gateway（stdio/HTTP 代理 + manifest digest） | B |
| Execution Broker + 沙箱 profile + egress 代理 + 确认 UI/API | C |
| 追加式审计存储 + provenance DAG + 报告 | C |
| 受限 IR + TDG + Contract Compiler + 隔离 LLM 加固 | D |
| 分层检测器 + Memory Gate | D |
| AgentDojo/ASB/MSB 评测 + 自适应攻击 + 消融报告 | D |
| MVP 演示（arch.md §10.1 七项） | 全员（各自模块部分） |
| 最终报告（可由固定命令再生成） | 全员（D 汇总） |

## 6. 首轮不做

- 不做大规模模型训练、不切微服务、不引入图数据库/Kafka；
- 不把任何 LLM 判定当作最终安全边界；
- 不在首版引入 OPA/Cedar 等外部策略服务；
- 先证明"完整中介 + 规范效果 + 确定性裁决"闭环可运行，再用测量结果决定扩展。
