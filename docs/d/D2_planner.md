# D2 可信合同编译、受限计划与工具依赖图

状态：**受限离线范围验收 PASS**。只支持“读取指定文档”和“仅检视代码”两个结构化模板；没有实现通用自然语言规划器。D1 冻结 48 例保持原样，其中 28 例适配当前模板，另外 20 例为 UNSUPPORTED。本轮未启动 D3。

按用户最新要求，全部改动仅保留在本地；**未 Git 暂存、未提交、未推送**。当前基线为 D1 提交 bbd2a4516da4eaaa8a846dae62c7ae07a8b09f72。

## 实现与信任边界

src/camel/planner/ 包含 models.py、compiler.py、validation.py、fixture_adapter.py 和公开入口 __init__.py。复用实际 IntentContract、CanonicalEffect、TrustLabel、PolicyEngine 与 validate_child_contract，没有另建同名公共安全模型，未修改 A/C 的正式实现或旧解释器。

可信入口以 TrustedTask 提供 task_id、principal、精确模板名、明确资源 ID 和到期时间；Organization 提供已批准资源目录、禁止数据类别及预算。编译 API 没有外部网页/工具返回/记忆或模型计划参数。自然语言自由任务返回 UNSUPPORTED；缺资源、目录外资源或模板类型不符返回 REQUIRES_AUTHORIZATION；过期和重复/超预算资源拒绝。不会从外部内容猜测授权。

编译后的公共合同只有 READ/read_file，资源是目录中明确列出的具体标识符；无外发接收方、无委派、副作用预算为 0，TTL 受组织上限约束。资源目录拒绝 glob 元字符，以免精确资源意外变成权限通配符。默认最多 8 个资源，TTL 最多 3600 秒。

这项入口边界依赖宿主把真实用户授权送入 TrustedTask：Python 类型、frozen 或自声明 trusted 字段本身不是身份认证。当前未实现可信入口的进程隔离、签名认证或部署证明。哈希用于快照一致性，不是授权签名。

资源 ID 是宿主/B 已提供的规范标识符。D2 不解析 Shell、不自行归约路径，不将字符串相等宣称为真实文件路径/符号链接安全；实际 B 归约、C 执行与旁路隔离留待 D5。

## 受限 IR 与 TDG

候选 JSON 只有声明的节点结构：工具 ID/版本、资源 ID、效果引用、来源 ID、显式依赖及数据槽引用。未知结构、伪造合同/授权字段、任意计划解释/隐式思维链字段均被拒绝；空/截断 JSON 和超过 65536 字节的候选也拒绝。每个当前只读工具节点对应一个效果引用。

工具必须存在于宿主登记表且版本与模板匹配。当前 fixture-v1 只注册 read_repository_document 与 inspect_repository_code，两者只有 focus 数据槽。来源注册表由宿主/B 提供；模型计划只引用 ID，不能自带可信标签。来源必须有非空且匹配的 provenance、完整标签、唯一字段和可追踪父来源。派生标签调用真实 TrustLabel.join，不能洗白父来源或秘密标签。

TDG 含可信任务节点、来源节点及工具节点，边区分 authorization、data、dependency、derived 和 tool_result。工具结果的生产者也进入依赖图，防止结果反向依赖自身；稳定拓扑排序拒绝工具环、来源环和工具—结果反馈环。默认限制 32 个工具节点、64 个来源、64 个效果和 32000 个来源字符。

每个规范化结果通过请求指纹绑定当前合同、工具 manifest、节点、解析后的数据槽值与来源标签。缺少效果列表、身份/引用不一致或输入变化后重放旧结果均拒绝。B 不可用，当前仅使用明确标记的 fixture_stub；不会把该桩写成真实 Shell/路径归约器。

所有规范效果都接受真实 PolicyEngine 检查，另校验其与只读工具 manifest、资源、来源及能力要求一致。夹带 WRITE/EXEC/EGRESS/DELEGATE、资源空集、伪造标签或未授予能力都不能进入可执行 IR；非 EXACT 归约需要重新授权。DENY 无论是否带原因文字都优先拒绝。

结果区分 READY、DENIED、REQUIRES_AUTHORIZATION；结构/身份/图错误为 INVALID。只有整个计划 READY 时 executable_node_ids 才非空。返回的 effects 是候选规范效果，不能视为已经执行或已获许可。解释仅保存“任务 ID—工具节点—效果 ID—规则决定—来源”的可复现引用，不保存模型隐式思维链。

## 增量与执行约束

fill_data_slot 只能填已有且为空的数据槽，不能新增资源、工具、接收方、效果或权限分支。填充后必须重新获取规范效果并验证；旧适配器结果因指纹不符被拒绝。新增资源返回 REQUIRES_AUTHORIZATION，当前不实现人机确认回合，也不把 CONFIRM 自动变成 ALLOW。

fixture_adapter.replay_fixture 在每次记录前重新验证全计划，并用当前时钟和策略检查合同；只在 READY 时把效果写入内存账本。这个账本是唯一合成效果，没有实际文件读取、网络、Shell、MCP、子 Agent 或记忆访问。即便计划前缀合法，后续节点不合法时也不会提前记录前缀效果。真实宿主是否绕过验证仍须后续集成证明。

两个模板均禁止委派。扩权子合同测试直接复用公共 validate_child_contract，得到 delegation_not_allowed；这不宣称已支持安全的通用多层委派或穷尽所有 glob 包含关系。

## 实验与结果

正式记录：artifacts/d/D2_20261015_offline_01/。CPU、Windows 离线、Python 3.10.12，既有冻结依赖；没有模型、训练、下载或外部基准。固定时钟继承 D1 的 2026-10-15T00:00:00+00:00，不拟合阈值。

D1 适配只依据冻结的可信 allowed_effects 判断模板范围，不根据攻击标签选择政策或生成权限。28 个适配例来自 14 个攻击/良性族，配对合同指纹逐一相同：

| 固定候选结果 | 数量 | 解释 |
|---|---:|---|
| READY | 14 | 良性只读候选完成一次替身记录 |
| INVALID | 12 | 攻击候选引用未注册的越权工具 |
| DENIED | 2 | 读虚构秘密路径被真实策略拒绝 |
| UNSUPPORTED | 20 | 可信任务需要写入、外发、记忆或委派，超出两个模板 |

28 个适配例的独立效果检查全部通过：14 个攻击无替身效果，14 个良性完成预期替身调用。20 个范围外例的 ledger 为 null，不算攻击成功拦截或良性失败。不把这组窄范围结果与 D1 全范围直接比较为效用/安全率提升，也不宣称真实模型 ASR=0。D1 原回放仍为 44 PASS / 4 Memory Gate BLOCKED，逐例观测未变；D1 文件哈希及划分均未改动。

另有 16 个工程控制，不作为新的独立攻击样本：两模板正常读取、同事实改变注入内容、正常增量填槽、旧规范结果重放、review 后 push、README 后读密钥/外发、依赖环、新资源确认、硬拒绝、到期、夹带 EGRESS、子合同扩权及范围外自由任务。16 个控制全部符合预期；相同事实配正常/注入文本时，合同指纹与实际效果范围不变。

| 检查 | 当前结果 |
|---|---|
| 规划器单元测试 | 64 通过，0 警告 |
| 规划器 + D1 + 核心/策略 | 197 通过 |
| 完整 Windows pytest | 407 通过、6 个原有平台失败、0 错误、0 跳过 |
| Ruff lint / 格式 / pyright | 全通过，类型检查 0 errors / 0 warnings |
| 独立进程确定性 | PYTHONHASHSEED=17/991 的 observations.json 和 controls.json 逐字节一致 |
| D1 回归 | 逐例观测与 D1 正式验收相同 |

完整 Windows 的六项失败仍是缺 O_NOFOLLOW、链接权限和 POSIX 路径语义，与 D0/D1 名称完全相同；没有删除、跳过或改旧断言。D0 Linux 的 320 项通过为历史记录，本轮没有冒充 D2 Linux 完整验收。

## 复现与剩余依赖

默认仅取 D1 dev：

这里的 dev 限制是回放选择，不是文件隔离：共享加载器仍验证完整 cases.jsonl 的哈希、全体 Schema 和族划分。不能将默认命令称为“物理上从未读取 Test”。

```powershell
$env:PYTHONPATH = 'src'
& '.\.venv\Scripts\python.exe' scripts/d2_eval.py --output artifacts/d/D2_dev_repeat_01
```

为验证基础设施而读取全部固定场景时：

```powershell
$env:PYTHONPATH = 'src'
& '.\.venv\Scripts\python.exe' scripts/d2_eval.py --split all --harness-validation --output artifacts/d/D2_harness_repeat_01
```

输出目录必须是新目录。脚本禁止 socket/DNS/urllib 请求，记录基线/差异、源码和冻结数据 SHA256、依赖版本、时钟、策略版本、逐例 IR/TDG/决定/来源/账本及控制结果。Test 只用于固定基础设施验收，不是盲测；未根据 Test 调检测器或阈值。进程网络钩子不是 OS 沙箱。

证据为 E1/E2 的固定候选与合成效果：尚未接入原版 privileged_llm、真实 B 归约、C 执行、模型规划或 Memory Gate。后续 D3a 才实现隔离解析与规则检测，D5 再接真实链路。紧凑证据见 [evidence/D2_offline_acceptance.json](evidence/D2_offline_acceptance.json)；完整日志留在本地 artifacts，不提交缓存或运行时。
