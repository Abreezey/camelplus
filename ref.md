# CAMEL 二次开发：技术选择与论文依据

> 核验日期：2026-10-14。  
> 本文件说明论文如何支撑 `arch.md` 的选择，不表示本项目复现了论文全部结果。引用优先使用 arXiv、ACL Anthology、ACM、USENIX 等原始页面。

## 1. 证据使用规则

| 标记 | 含义 |
|---|---|
| 直接采用 | 架构中保留或实现论文的核心机制 |
| 组合采用 | 借用论文思想，但接口、信任边界或实现不同 |
| 威胁/评测 | 用于构造攻击与评价，不作为防御保证 |
| 基础理论 | 提供安全模型或数据模型基础 |
| 工程选择 | 没有对应论文保证；必须由实现测试验证 |

重要边界：论文中的实验结果只对其模型、数据集和威胁模型成立。尤其是检测准确率，不能外推为本系统的安全保证。

## 2. 组件—方法—论文映射

| 架构组件 | 采用的方法 | 主要依据 | 采用方式与边界 |
|---|---|---|---|
| 总体安全内核 | 可信规划器、隔离 LLM、控制/数据流分离、capability | [R01] CaMeL | 直接采用思想并复用现有代码；增加外部 Gateway/Broker，弥补解释器旁路 |
| 动态信息流 | 机密性/完整性标签、污点传播、确定性策略 | [R02] Fides；[R15] DIFC | 组合采用；标签判断是硬边界，LLM 不可修改标签 |
| 权限策略 | 细粒度工具参数 DSL、最小权限、运行时 enforcement | [R03] Progent | 直接采用 DSL 思路；首版策略由人审，不自动信任 LLM 生成策略 |
| Intent Contract | 每步动作必须服务可信用户目标 | [R04] Task Shield | 组合采用；语义判断只能升级风险，不能授权硬规则禁止的动作 |
| 工具依赖图 | 先规划 TDG，再接触不可信工具输出 | [R05] IPIGuard | 组合采用；保留受控重规划，但不可信结果不能扩权 |
| 提交前验证 | speculative reasoning + verify-before-commit | [R06] VIGIL | 组合采用；只在副作用提交前验证，最终执行仍由确定性 Broker 控制 |
| MCP Gateway | 注册/调用/返回拦截、结构和语义检查 | [R07] ShieldMCP | 直接采用拦截形态；增加 manifest digest、IFC 和能力票据 |
| 输入通道分离 | prompt/data 分离、结构化查询 | [R08] StruQ | 组合采用；不要求必须训练专用模型，因此只作软防线 |
| 来源显式化 | 对不可信内容持续标记/变换 | [R09] Spotlighting | 可选软防线；来源 metadata 才是权威记录，文本标记不是安全边界 |
| Memory Gate | 记忆/知识库投毒威胁模型 | [R10] AgentPoison | 威胁与评测依据；本项目采用来源保留、隔离写入和检索后再校验 |
| Agent 基准 | 工具返回间接注入、utility/security 联合评测 | [R11] AgentDojo | 直接作为现有回归基线；不作为唯一测试集 |
| 广覆盖基准 | 多场景、工具、攻击和防御指标 | [R12] ASB | 补充系统提示、工具与记忆阶段覆盖 |
| MCP 基准 | 工具描述、调用、返回阶段的 12 类 MCP 攻击 | [R13] MSB | 直接作为 MCP 验收集；关注 NRP 及分阶段结果 |
| 自适应红队 | 针对已知防御优化攻击 | [R14] Adaptive Attacks | 发布门禁；用于反对“静态攻击上低 ASR 即安全” |
| 标签格与解密级 | 去中心化信息流和细粒度共享 | [R15] Myers–Liskov | 基础理论；本项目只实现所需子集，不宣称完整语言级 IFC |
| Provenance DAG | why/where provenance、派生关系 | [R16] Buneman et al. | 基础数据模型；LLM 改写后只保证派生边，不保证精确 token 因果 |
| 能力与沙箱 | 对象能力、细粒度权利与 capability mode | [R17] Capsicum | 原则采用；Linux 实现可用 namespace/seccomp/Landlock，不等于复现 Capsicum |
| 风险测试 | 用模拟工具环境发现高风险 Agent 失败 | [R18] ToolEmu | 仅用于测试设计；LM 模拟器不能替代真实 Broker/沙箱 |
| 多 Agent 传播 | 语义 taint、动态协作图、提交前工作流验证 | [R19] SafeFlow | 可选 P1/P2；当前为预印本，先用规则化来源传播实现 |
| 注入检测器 | 从模型行为状态识别外部内容中的指令 | [R20] InstructDetector | 可选模型能力；需要白盒模型，不适合闭源 API 默认路径，也不是硬边界 |
| 来源完整性基线 | 权限提升前保持 prompt/data 来源完整性 | [R21] Prompt Flow Integrity | 组合采用其来源完整性目标；用结构化标签和 Gateway 执行 |
| 三态交互 | IFC 条件满足自动执行，否则请求确认 | [R22] RTBAS | 组合采用；本项目显式增加不可恢复硬拒绝与 scoped ticket |

## 3. 论文条目

### R01. CaMeL：架构基线

Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis, Florian Tramèr. **Defeating Prompt Injections by Design**. arXiv:2503.18813, 2025.  
原文：<https://arxiv.org/abs/2503.18813>

- 提出在 LLM 周围构建保护层，从可信 query 显式抽取控制流和数据流；
- 使用隔离模型处理不可信数据，并用 capability 防止未经授权的数据外泄；
- 是本仓库解释器、`CaMeLValue` metadata 和 privileged/quarantined LLM 分工的直接来源。

### R02. Fides：面向 Agent 的 IFC

Manuel Costa, Boris Köpf, Aashish Kolluri, Andrew Paverd, Mark Russinovich, Ahmed Salem, Shruti Tople, Lukas Wutschitz, Santiago Zanella-Béguelin. **Securing AI Agents with Information-Flow Control**. arXiv:2505.23643, 2025.  
原文：<https://arxiv.org/abs/2505.23643>

- 给出 Agent planner 可执行安全性质的形式模型；
- Fides 跟踪 confidentiality 与 integrity 标签并确定性执行策略；
- 支撑本项目的双维标签、动态污点与“模型不是最终裁决者”。

### R03. Progent：策略 DSL 与最小权限

Tianneng Shi, Jingxuan He, Zhun Wang, Linyu Wu, Hongwei Li, Wenbo Guo, Dawn Song. **Progent: Programmable Privilege Control for LLM Agents**. arXiv:2504.11703, 2025.  
原文：<https://arxiv.org/abs/2504.11703>

- 以 DSL 表达工具调用级细粒度权限和拒绝 fallback；
- 在 Agent 运行期确定性执行，且可模块化接入；
- 本项目采用其策略形态，但不让未经人工审核的 LLM 自动策略直接进入生产。

### R04. Task Shield：任务对齐检查

Feiran Jia, Tong Wu, Xin Qin, Anna Squicciarini. **The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents**. ACL 2025, pp. 29680–29697. DOI: 10.18653/v1/2025.acl-long.1435.  
原文：<https://aclanthology.org/2025.acl-long.1435/>

- 将防御问题改写为“每条指令和工具调用是否服务用户目标”；
- 支撑 Intent Contract 与逐动作 alignment verifier；
- 其判定依赖模型，本项目只把它作为风险信号。

### R05. IPIGuard：先规划的工具依赖图

Hengyu An, Jinghuai Zhang, Tianyu Du, Chunyi Zhou, Qingming Li, Tao Lin, Shouling Ji. **IPIGuard: A Novel Tool Dependency Graph-Based Defense Against Indirect Prompt Injection in LLM Agents**. EMNLP 2025, pp. 1023–1039. DOI: 10.18653/v1/2025.emnlp-main.53.  
原文：<https://aclanthology.org/2025.emnlp-main.53/>

- 将任务执行表示为预先规划的 Tool Dependency Graph；
- 把规划与接触不可信外部数据解耦，降低被工具结果诱导出新调用的概率；
- 支撑本项目 TDG 和“重规划不得静默扩权”。

### R06. VIGIL：Verify Before Commit

Junda Lin, Zhaomeng Zhou, Zhi Zheng, Shuochen Liu, Tong Xu, Yong Chen, Enhong Chen. **VIGIL: Defending LLM Agents Against Tool-Stream Injection via Verify-Before-Commit**. ACL 2026, pp. 9764–9785. DOI: 10.18653/v1/2026.acl-long.443.  
原文：<https://aclanthology.org/2026.acl-long.443/>

- 允许推理阶段保留灵活性，在副作用提交前做 intent-grounded verification；
- 适合本项目的 Gateway → verifier → Broker 边界；
- 本项目额外要求硬策略优先，避免 verifier 自身受注入。

### R07. ShieldMCP：MCP 运行时拦截

Saurabh Yergattikar. **Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments**. ACL Industry 2026, pp. 865–871. DOI: 10.18653/v1/2026.acl-industry.58.  
原文：<https://aclanthology.org/2026.acl-industry.58/>

- ShieldMCP 在 MCP 工具调用和返回路径组合结构检查与语义意图验证；
- 覆盖 tool poisoning、工具返回间接注入和供应链操纵；
- 支撑独立 MCP Security Gateway，而不是只修改 Agent prompt。

### R08. StruQ：结构化 prompt/data 通道

Sizhe Chen, Julien Piet, Chawin Sitawarin, David Wagner. **StruQ: Defending Against Prompt Injection with Structured Queries**. arXiv:2402.06363, 2024.  
原文：<https://arxiv.org/abs/2402.06363>

- 用安全前端和专门训练的模型区分 prompt 与 data；
- 说明只靠分隔符不足，模型训练与结构化通道需配合；
- 本项目将其用作输入软防线，而非唯一保证。

### R09. Spotlighting：持续来源信号

Keegan Hines, Gary Lopez, Matthew Hall, Federico Zarfati, Yonatan Zunger, Emre Kiciman. **Defending Against Indirect Prompt Injection Attacks With Spotlighting**. arXiv:2403.14720, 2024.  
原文：<https://arxiv.org/abs/2403.14720>

- 通过对不可信输入变换，持续向模型提示其来源；
- 可用于文档/网页内容的 prompt 层隔离；
- 文本变换可能被绕过，权威来源仍由系统 metadata 保存。

### R10. AgentPoison：长期记忆投毒威胁

Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, Bo Li. **AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases**. NeurIPS 2024; arXiv:2407.12784.  
原文：<https://arxiv.org/abs/2407.12784>

- 展示通过污染长期记忆/RAG 知识库植入可迁移、隐蔽触发器；
- 支撑 Memory Gate、来源保留、quarantine 和跨会话回归测试。

### R11. AgentDojo：当前回归基准

Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr. **AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents**. NeurIPS 2024 Datasets and Benchmarks; arXiv:2406.13352.  
原文：<https://arxiv.org/abs/2406.13352>

- 提供具不可信工具数据的动态环境、正常任务和安全测试；
- 同时衡量 task utility 与攻击成功，是现有仓库可直接复现的基线。

### R12. ASB：广覆盖 Agent 安全基准

Hanrong Zhang, Jingyuan Huang, Kai Mei, Yifei Yao, Zhenting Wang, Chenlu Zhan, Hongwei Wang, Yongfeng Zhang. **Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents**. ICLR 2025; arXiv:2410.02644.  
原文：<https://arxiv.org/abs/2410.02644>

- 覆盖多场景、数百工具、prompt injection、memory poisoning 和混合攻击；
- 用于补充 AgentDojo 对系统不同阶段和攻击族的覆盖。

### R13. MSB：MCP 专项基准

Dongsen Zhang, Zekun Li, Xu Luo, Xuannan Liu, Peipei Li, Wenjun Xu. **MCP Security Bench (MSB): Benchmarking Attacks Against Model Context Protocol in LLM Agents**. ICLR 2026; arXiv:2510.15994.  
原文：<https://arxiv.org/abs/2510.15994>

- 覆盖规划、调用和响应三个阶段及 12 类 MCP 攻击；
- 包含工具描述注入、同名冲突、越界参数、伪造用户返回、tool transfer 等；
- 支撑 Gateway 的验收用例与安全—性能联合指标。

### R14. 自适应攻击评测

Qiusi Zhan, Richard Fang, Henil Shalin Panchal, Daniel Kang. **Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents**. Findings of NAACL 2025, pp. 7116–7132. DOI: 10.18653/v1/2025.findings-naacl.395.  
原文：<https://aclanthology.org/2025.findings-naacl.395/>

- 针对八类防御进行自适应攻击并展示静态评测的不足；
- 支撑把 adaptive red-team 设为发布门禁，并禁止只用已知模板宣布鲁棒。

### R15. DIFC：信息流基础模型

Andrew C. Myers, Barbara Liskov. **A Decentralized Model for Information Flow Control**. SOSP 1997, pp. 129–142. DOI: 10.1145/268998.266669.  
原文：<https://doi.org/10.1145/268998.266669>

- 给出互不信任主体、去中心化 authority、细粒度共享与 declassification 模型；
- 是 TrustLabel、readers 和显式背书/解密级操作的理论基础。

### R16. 数据来源（Provenance）

Peter Buneman, Sanjeev Khanna, Wang-Chiew Tan. **Why and Where: A Characterization of Data Provenance**. ICDT 2001, pp. 316–330. DOI: 10.1007/3-540-44503-X_20.  
原文：<https://doi.org/10.1007/3-540-44503-X_20>

- 区分数据为何出现及来自何处等 provenance 问题；
- 支撑事件 DAG 中来源、派生和影响解释的分层表达。

### R17. Capsicum：能力式系统隔离

Robert N. M. Watson, Jonathan Anderson, Ben Laurie, Kris Kennaway. **Capsicum: Practical Capabilities for UNIX**. USENIX Security 2010.  
原文：<https://www.usenix.org/conference/usenixsecurity10/legacy-presentation/capsicum-practical-capabilities-unix>

- 展示用 capability mode 和细粒度权利限制 UNIX 应用；
- 支撑“Broker 持权、Agent 无权”和最小、不可转移、可过期能力票据的工程方向。

### R18. ToolEmu：高风险工具测试

Yangjun Ruan, Honghua Dong, Andrew Wang, Silviu Pitis, Yongchao Zhou, Jimmy Ba, Yann Dubois, Chris J. Maddison, Tatsunori Hashimoto. **Identifying the Risks of LM Agents with an LM-Emulated Sandbox**. arXiv:2309.15817, 2023.  
原文：<https://arxiv.org/abs/2309.15817>

- 通过 LM 模拟工具和环境探索高风险、长尾失败；
- 可辅助生成测试，但论文也依赖模拟准确性，因此不能替代真实执行隔离。

### R19. SafeFlow：跨 Agent 语义信息流

Haowen Dai, Zonghao Ying, Wenfeng Li, Xiangfan Wu, et al. **SafeFlow: Semantic Information-Flow Control for Blocking Malicious Propagation in Multi-Agent Systems**. arXiv:2607.25255, 2026（预印本）.  
原文：<https://arxiv.org/abs/2607.25255>

- 将多 Agent 间的恶意目标碎片传播建模为语义信息流；
- 使用结构化语义 taint、动态协作图和工作流级验证；
- 与跨 Agent provenance/authority 传播高度相关，但因是预印本，当前只作为 P1/P2 设计输入。

### R20. InstructDetector：白盒指令检测

Tongyu Wen, Chenglong Wang, Xiyuan Yang, Haoyu Tang, Yueqi Xie, Lingjuan Lyu, Zhicheng Dou, Fangzhao Wu. **Defending against Indirect Prompt Injection by Instruction Detection**. Findings of EMNLP 2025, pp. 19472–19487. DOI: 10.18653/v1/2025.findings-emnlp.1060.  
原文：<https://aclanthology.org/2025.findings-emnlp.1060/>

- 利用模型中间层隐藏状态与梯度检测外部内容中的指令；
- 适合可访问权重/梯度的本地模型，不适合纯闭源 API；
- 其高准确率是论文数据集结果，本项目必须重新做跨语言、自适应和 OOD 校准。

### R21. Prompt Flow Integrity

Juhee Kim, Woohyuk Choi, Byoungyoung Lee. **Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents**. arXiv:2503.15547, 2025.  
原文：<https://arxiv.org/abs/2503.15547>

- 从来源完整性角度限制低信任 prompt 对高权限动作的影响；
- 支撑 `integrity + authority` 分离，以及敏感参数需可信来源的策略。

### R22. RTBAS：IFC 与用户确认

Peter Yong Zhong, Siyuan Chen, Ruiqi Wang, McKenna McCall, Ben L. Titzer, Heather Miller, Phillip B. Gibbons. **RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage**. arXiv:2502.08966, 2025.  
原文：<https://arxiv.org/abs/2502.08966>

- 将信息流约束用于工具型 Agent，并在条件不满足时引入用户确认；
- 支撑三态交互，但本项目额外区分不可确认绕过的硬 `DENY`，并把确认限制为精确、短期、单次票据。

## 4. 无直接论文背书的工程选择

以下选择是为本仓库和交付约束作出的工程判断，不应包装成论文结论：

| 选择 | 理由 | 如何验证 |
|---|---|---|
| Python 3.10+ / Pydantic v2 | 与现有代码一致，减少重写 | 类型检查、schema 兼容、序列化黄金测试 |
| 首版小型 Typed YAML DSL | 规则域有限，避免引入独立策略服务 | parser/编译器单测、默认拒绝、策略快照回放 |
| SQLite → PostgreSQL 的渐进存储 | 先满足单机演示和可重放，再按规模迁移 | 吞吐/保留期压测、迁移测试 |
| Shell AST、路径安全句柄、egress proxy | 字符串黑名单不能描述真实效果 | 差分测试、TOCTOU/重定向/DNS rebinding 用例 |
| Linux namespace/seccomp/Landlock 或容器 | 当前部署环境适用，且可与 Broker 集成 | 逃逸测试、系统调用/网络/挂载负面测试 |
| 哈希链/Merkle 批次审计 | 便于检测日志被静默修改 | 篡改检测与恢复演练 |
| 不在首版使用图数据库/Kafka | 当前规模未证明需要，降低运维面 | 以实际 P95、吞吐、保留期触发升级 |

## 5. 选型取舍摘要

- **选结构性强制，不选纯检测**：自适应攻击已显示多类检测式防御可被绕过 [R14]。
- **选 CaMeL + Fides 的确定性内核**：分别提供可信控制/数据流分离和 Agent IFC 形式化基础 [R01][R02]。
- **选外置 Gateway/Broker**：CaMeL 的解释器内策略无法覆盖绕过解释器的真实工具通道；MCP 运行时拦截已有直接系统依据 [R07]。
- **选 TDG + 提交前验证提高效用**：允许读取不可信数据完成任务，同时把不可逆动作延迟到完整上下文可验证时 [R05][R06]。
- **选 provenance-preserving Memory Gate**：记忆投毒已被实证展示，检索命中不能等同于可信 [R10]。
- **选多基准 + 自适应评测**：单个基准或静态攻击集不足以支撑安全结论 [R11][R12][R13][R14]。
