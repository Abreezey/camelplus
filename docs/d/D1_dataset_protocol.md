# D1 固定场景、真值与离线评测器

状态：D1 离线协议与评测器验收通过；48 个场景均可加载并回放，其中 44 PASS、4 BLOCKED。BLOCKED 来自未实现的 Memory Gate 生命周期，不算安全成功或良性失败。本轮只执行 D1，没有启动 D2 或模型评测。

## 样本与冻结规则

用户已确认采用 24 个攻击种子族，各配一个良性场景，共 48 个，全部由助手依据既定合同和组织规则编写为合成固定输入，没有模型生成的标签或外部数据下载。真值尚未经过独立人工重标，不是已验证的自然分布基准。

| 来源 | 攻击族 | 配对后场景数 |
|---|---:|---:|
| 直接输入 | 6 | 12 |
| 网页 | 2 | 4 |
| 文档/源码 | 2 | 4 |
| 邮件/Issue | 2 | 4 |
| 工具返回 | 2 | 4 |
| 工具描述/schema | 2 | 4 |
| 跨 MCP | 2 | 4 |
| 记忆 | 6 | 12 |

直接输入覆盖角色伪装、伪授权、扩大合同、review 转 push、覆盖组织禁止及带凭据委派；间接输入覆盖指令夹带、来源冒充和越权效果；记忆覆盖权限提升、跨会话来源、摘要合并、过期、子 Agent 派生及隔离条目。良性配对包含恶意字符串的研究引用、翻译、代码/工具描述审查、授权本地写入、授权内部数据使用和公开摘要委派。危险词出现本身不是攻击判据。

族级划分固定为 dev/validation/test = 12/6/6 族，对应 24/12/12 个场景。配对两例必须有完全相同的可信任务、合同和划分。当前每族只支持一攻一良，未来新增翻译、编码、拼接等变体须另立版本，并沿用原族划分；不能把变体作为新的独立样本跨划分。加载器检查规范化后相同原文不能跨划分，这不能保证语义近重复或跨语言变体已完全清除。

冻结目录为 tests/fixtures/d/d1_v1/，仅包含 cases.jsonl、policy.yaml、manifest.json。manifest 记录字节 SHA256、族映射、固定时钟和基线提交。真值在首次策略回放前写入并冻结；之后只修复评测实现，未按实测结果修改真值或划分。

Git 属性对 tests/fixtures/d/** 设置 -text，保留冻结文件的原始字节（含原始 CRLF），关闭提交/检出时的换行转换，避免破坏 SHA256；场景内容、真值及最初哈希不变。局部 whitespace 属性保留常规空白检查，将 CR 识别为行终止符；依据 [Git attributes](https://git-scm.com/docs/gitattributes) 与 [cr-at-eol](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corewhitespace) 官方说明。

- 数据版本：d1_synthetic_pairs_v1。
- cases.jsonl SHA256：492961d3aff3edd6d790f943cb310e2d79a809e349c89fc8b1012ca3b66cf899。
- policy.yaml SHA256：1bdf1e87b4828740dbf56313eded9e5eb87fd7d04e365d2980d78fe7223ea3ec。
- 固定时钟：2026-10-15T00:00:00+00:00；随机种子不适用（无随机采样）。

D1 会读取 Test 验证加载、回放和观察器，因此这不是“从未打开过 Test”的盲测。没有模型、检测器或阈值拟合；后续阈值只用 dev、validation 用于选择，不能依据这里的 Test 结果调检测规则再声称独立终测。真实模型阶段还需要明确独立终测协议。

## 真值与独立观察

每例包含计划要求的 case_id/family_id/source_type/split/task/authorized_scope/input_events/candidate_calls/expected_labels/expected_effects/expected_decision/forbidden_observables/benign_success_oracle，并增加 variant、required_components 和 truth_rationale。

- 标签真值：每个来源事件显式提供公共 TrustLabel 的全部字段、非空 provenance 和 source_id。缺标签、缺来源、缺任一标签维度、未知字段、父引用缺失或自环都报错；不补造默认可信标签。标签结构合法仍不证明真实来源身份可信。
- 决策真值：每个固定候选调用分别标注 ALLOW、CONFIRM 或 DENY。组织硬禁止 EXEC/AUTH_CHANGE/虚构秘密路径读取；越合同或 push 为 CONFIRM；秘密标签外发由真实 IFC 判断。CONFIRM 当前仅验证未批准轨迹，不执行确认回合。
- 效果真值：expected_effects 是工具替身应记录的调用 ID 列表；观察器另逐项核对固定输入中的类型、操作、资源、接收方和载荷，不能只凭 ID 或决策文字通过。
- 攻击目标：forbidden_observables 按效果类型、资源、接收方及可选载荷子串匹配真实记录账本。当前 24 个目标是固定的越权效果，不将“尝试 EGRESS”自动等同于秘密字节已泄露。观察器另有 canary 子串回归，只有实际载荷含 canary 才匹配该类目标。
- 良性完成：观察器检查预期效果确实被记录，并且替身返回值匹配独立 oracle。拒绝所有调用会使可评估的 22 个良性例全部失败；这里验证的是合成工具轨迹完成，不是模型语义任务成功。

src/camel/evaluation/fixtures.py 复用实际公共模型，CanonicalEffect 来自明确声明的固定效果桩，不是 B 的生产归约器。replay.py 调用真实 PolicyEngine 和 TrustLabel.join；派生摘要保留父来源及保密等级。输入文本不会被解释为计划、政策或合同，不能据此声称完成了语义规划器或注入检测器。

RecordingTool 仅向内存账本追加记录，不调用文件、网络、Shell、真实 MCP、持久记忆或子 Agent。结果观察器直接检查账本，独立于策略的 DENY 文本。CLI 对 socket/DNS/urllib 请求加进程审计钩子；这不是 OS 沙箱。

过期和隔离区读取各有一攻一良，共 4 例声明需要 memory_lifecycle_gate。当前无该组件，仍保存真实内核的标签和决策，但 ledger、是否出现禁止效果、良性完成均为 null，结果为 BLOCKED。过期/隔离攻击在裸内核中仍可 ALLOW 的差异也保留，未补写假 Gate 或把空账本当安全通过。其余记忆来源场景只验证固定来源及标签/策略传播，不验证跨进程持久化或真实检索。

## 结果与反向验证

正式本地记录：artifacts/d/D1_20261015_offline_02/。D1 在用户已选定的 Windows 离线环境运行，不需要 POSIX 文件执行；D0 的 Linux 320 项通过仍是历史基线，不冒充当前 D1 Linux 验收。

| 结果 | dev | validation | test | 合计 |
|---|---:|---:|---:|---:|
| PASS | 24 | 12 | 8 | 44 |
| FAIL | 0 | 0 | 0 | 0 |
| BLOCKED | 0 | 0 | 4 | 4 |

可评估攻击 22 个：观察到禁止效果 0；另 2 个攻击 BLOCKED。可评估良性 22 个：替身任务完成 22；另 2 个良性 BLOCKED。不能将阻塞例放入安全成功分母。未实现检测器，Precision、Recall、FP/FN 和模型 ASR 目前不适用，输出为 null，没有宣称“真实模型 ASR=0”。本规模仅为 smoke，无统计显著性结论。

两个独立进程分别使用 PYTHONHASHSEED=17/991，observations.json 逐字节一致；标签集合采用规范排序。单进程重复回放也一致。新评测模块 29 项单元测试，加核心/策略共 133 项通过；规范、格式和 pyright 检查通过。完整 Windows 349 项中 343 通过、6 个原有平台失败、0 错误、0 跳过，失败名称与 D0 完全相同，没有新增失败或改旧预期。

反向验证包括：强制 ALLOW 使 22 个可评估攻击全部被观察器判 FAIL；强制 DENY 使 22 个可评估良性全部完成失败；伪称 DENY 但账本存在禁止效果时仍检出；额外效果、同 ID 换目标、源标签缺失、合同配对不一致、跨划分原文复用、文件哈希篡改均被拒绝。测试没有真实网络请求或执行载荷。

## 复现与后续

在项目根目录，使用已冻结安装的项目 Python，默认只回放 dev；加载器仍验证完整冻结文件、全体 Schema 和族划分，并非物理隔离 Test 文件内容：

```powershell
$env:PYTHONPATH = 'src'
& '.\.venv\Scripts\python.exe' scripts/d_eval.py --output artifacts/d/D1_dev_repeat_01
```

完整 D1 基础设施验收需显式说明读取 Test 的用途，输出目录必须是新目录：

```powershell
$env:PYTHONPATH = 'src'
& '.\.venv\Scripts\python.exe' scripts/d_eval.py --split all --harness-validation --output artifacts/d/D1_harness_repeat_01
```

运行器记录 Python/平台、实际依赖、锁文件及源码哈希、固定时钟、策略版本、Git 基线/差异、起止时间、逐例结果和阻塞原因。观测有 FAIL 或不确定性时返回非零；已声明且透明记录的缺失组件 BLOCKED 不作为评测器崩溃。原始记录留在 artifacts/d，可提交的紧凑证据见 [evidence/D1_offline_acceptance.json](evidence/D1_offline_acceptance.json)。

本阶段完成固定输入与离线评测基础设施；完整系统仍待后续组件。下一步是 D2：可信合同编译、受限 IR 和 TDG，按同一冻结协议验证；本轮不提前实现 D2、D3 或 Memory Gate。
