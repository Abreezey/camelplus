# 公共接口契约（跨模块合作说明）

> 维护规则：本文是 A/B/C/D 四个模块之间的**接口单一事实来源**。任何跨模块签名的变更必须先改本文、在群里同步、再改代码。各模块内部私有函数不在契约范围内。
> 当前状态：A/C 已有接口与部分实现；B 已实现并完成自身缺陷修复，待 C 真实执行联调；D 状态由负责人维护。

## 1. 端到端数据流

```
用户意图 ──D──> IntentContract（信任编译）
外部内容 ──B──> CanonicalEffect（归约 + 打标）
                    │
                    v
          A: PolicyEngine.evaluate ──> Decision（ALLOW/CONFIRM/DENY）
                    │
                    v
          C: SecureExecutionPipeline
              ├─ DENY    → 阻断，零执行
              ├─ ALLOW   → 现签单次票据 → Broker 执行
              └─ CONFIRM → ConfirmationRequest → 用户批准/拒绝 → resolve()
                                │
                                v
          C: AuditStore（哈希链）+ ProvenanceService（DAG / 报告）
```

每一步都产生 `CanonicalEvent`（带 `trace_id` / `parent_ids`），全部进审计链。

## 2. 已冻结数据模型（A 交付，破坏性变更需全员对齐 + bump `schema_version`）

| 模型 | 位置 | 要点 |
|---|---|---|
| `TrustLabel` | `camel.core.labels` | provenance/integrity/confidentiality/authority/readers/data_classes；`join` 只降完整性/权限、只升机密性 |
| `IntentContract` | `camel.core.contract` | contract_id/principal/goal/allowed_effects（glob）/forbidden_data_classes/allowed_destinations/delegation/expires_at |
| `CanonicalEffect` | `camel.core.effect` | effect_id/type（9 种）/operation/resources/data_refs（内联 TrustLabel）/destination/reversibility/derived_from/normalization_confidence |
| `Decision` | `camel.core.decision` | frozen：outcome/hard_reasons/confirm_reasons/risk_signals/policy_version/contract_id/evidence/safe_alternative |
| `CanonicalEvent` | `camel.core.events` | 必填 event_id/trace_id/session_id/principal/source/payload_ref/timestamp；可选 parent_ids/span_map/labels |

2026-10-15 本地修复约束（沿用 v1 字段布局，收紧输入校验；依赖未知字段或宽松类型转换的调用方需要调整）：

- `RiskSignal`、`IntentContract`、`AllowedEffect`、`DelegationSpec` 拒绝未知字段；这不是身份/授权来源验证。
- `RiskSignal.confidence` 接受有限 JSON 数字，范围 [0, 1]；拒绝字符串和布尔转换。
- `side_effect_budget` 与 `max_depth` 必须为非负整数，拒绝字符串、布尔和小数转换。
- 子合同效果类型始终在父合同范围内；非空 child_ceiling 进一步收窄。操作/资源必须同时被同一父条目覆盖；仅证明相同 pattern、全局父 pattern 或具体子值命中父 glob，无法证明的复杂 glob 子集拒绝。

## 3. 策略与裁决接口（A 交付）

```python
# DSL：多文档 YAML → 规则列表；畸形规则加载期抛 ValueError（fail closed）
rules = load_rules(yaml_text)                       # camel.policy.dsl

# 引擎：固定顺序 ①规范化失败 ②IFC ③Contract ④DSL ⑤Composer；无显式 ALLOW 即默认 DENY
engine = PolicyEngine(rules, classifier, confirm_threshold)   # camel.policy.engine
decision = engine.evaluate(effect, now=..., contract=..., risk_signals=...,
                           side_effects_used=..., evidence=..., safe_alternative=...)
engine.policy_version                               # "sha256:..."，必须进审计事件

# 票据：HMAC 签名一次性授权（I5）
ticket = issue_ticket(key, subject=..., effect=..., expires_at=..., max_uses=1)
verify_ticket(key, ticket, effect, subject=..., store=..., now=...)   # 任何失败必 raise TicketVerificationError
# v0.6：hash_effect 绑定效果全字段（含 data_refs 标签）；expires_at 必须 tz-aware；
#       TicketStore 协议为 uses + try_consume（原子检查并消费，不再有 record_use）
```

Composer 的风险合成：硬 DENY 优先；确定性 confirm_reasons 保留确认路径；风险信号只能把已显式允许的效果升级为 CONFIRM，不能将默认 DENY 改为 CONFIRM。策略版本仍表示规则/分类器配置，重放还必须匹配代码版本。

## 4. 执行与审计接口（C 交付）

```python
# ---- 审计 ----
audit = AuditStore("audit.db")            # 或 ":memory:"；两张表：audit_events（哈希链）+ audit_payloads
audit.append(event, payload={...})        # 返回 record_hash；event_id 全局唯一
audit.events(trace_id=...)                # 按链序返回
audit.payload_of(event_id)                # 决策/执行载荷
audit.verify_chain()                      # 篡改/删行 → ChainIntegrityError

redact(secret_value)                      # → "sha256:<16hex>"，入审计前脱敏

# ---- 审计上下文（v0.5：审计四字段的模型版本 / manifest digest / 代码提交）----
audit_context = AuditContext.from_env()   # camel.audit；读 CAMEL_MODEL_VERSION / CAMEL_TOOL_MANIFEST_DIGEST / CAMEL_CODE_COMMIT
                                          # 或显式 AuditContext(model_version=..., ...)；未供数字段为 None，payload "context" 诚实记 null

provenance = ProvenanceService(audit)
provenance.timeline(trace_id)             # 时间线
provenance.dag(trace_id)                  # parent_ids + effect.derived_from 双来源边
provenance.report(trace_id)               # 脱敏 markdown 报告

# ---- 沙箱 ----
profile = SandboxProfile.workspace(root="/ws", scratch="/ws/scratch")
profile.resolve_read(resource)            # realpath 后必须在 read root 内，否则 SandboxViolationError
profile.resolve_write(resource)           # parent realpath 后必须在 write dir 内

# ---- 执行代理 ----
broker = ExecutionBroker(signing_key=key, profile=profile,
                         ticket_store=SQLiteTicketStore("tickets.db"), audit=audit,
                         vault=KeyVault(os.environ["CAMEL_MASTER_KEY"]))  # 可选：短期凭据注入（camel.broker）
result = broker.execute(effect, ticket, subject=..., trace_id=..., session_id=...,
                        content=..., parent_ids=..., audit_context=audit_context)
# 校验顺序（不可重排）：静态沙箱 → verify_ticket → 凭据派生 → IO → 审计
# v0.6 支持 READ/WRITE/EGRESS；EXEC / REPO_MUTATE / 其余 UnsupportedEffectError（fail closed + 审计 rejected）
# WRITE 需要 POSIX O_NOFOLLOW；缺少该能力时在票据消费和 IO 前 UnsupportedEffectError，审计 rejected
# 配置 vault 时：票据校验后 HMAC 派生短期凭据（绑定票据、随票据过期），
#   result.credential_handle 与审计 payload 只记 opaque handle（"cred_" 前缀），secret（SecretBytes）绝不外泄

# ---- EGRESS 执行（v0.6，2026-10-16）----
from camel.normalization import NetworkPolicy  # 复用 B 的网络边界，不扩展 SandboxProfile
broker = ExecutionBroker(..., network=NetworkPolicy(allowed_hosts={"api.example.com"}),
                         resolver=...,        # Callable[[host, port], tuple[str, ...]]，默认真实 DNS，测试可注入
                         transport=...,       # httpx.BaseTransport | None，测试注入点；作为固定 IP 传输的内层（镜像 B 的 PinnedHTTPTransport）
                         timeout=30.0, max_response_bytes=1_048_576)
# EGRESS 效果（destination=URL，operation="http_<method>"）执行语义：
#   烧票前静态校验（拒绝不烧票）：destination 必填、operation 须为 http_<method>、
#     network 未配置 → UnsupportedEffectError、NetworkPolicy.target() 允许表/DNS/私网/元数据检查（拒绝记 rejected）
#   执行时：revalidate 复验 DNS（地址集变化 = 重绑定 → failed）、连接固定到已批准 IP
#     并保留原 Host 头与 TLS SNI、3xx 重定向一律 failed（授权不继承）、响应有界读取（超限 failed）
#   配置 vault 时注入 `Authorization: Bearer <secret>`（固定方案，无配置项）；secret 绝不入审计/日志
#   result.output = 响应体 bytes；data_refs 标签不在 Broker 复查（A 的 IFC 已在裁决层硬拒秘密外发）
# EXEC 仍 fail closed（等内核级沙箱）

# ---- 确认流 ----
confirmations = ConfirmationAuthority(signing_key=key, audit=audit)   # ticket_ttl 默认 5 分钟
req = confirmations.request(decision, effect, trace_id=..., session_id=..., subject=...)
req.render()                             # 给用户看的确认文本
confirmations.approve(req, subject=..., ...)   # → CapabilityTicket（单次）
confirmations.deny(req, subject=..., ...)      # 只审计，不签票

# ---- 集成管道（推荐入口）----
pipeline = SecureExecutionPipeline(engine=engine, broker=broker, confirmations=confirmations,
                                   audit=audit, signing_key=key)
result = pipeline.run(effect, subject=..., trace_id=..., session_id=..., contract=..., content=...,
                      audit_context=AuditContext.from_env())  # 可选：decision/confirmation/execution payload 均携带 context
# DENY → execution=None；ALLOW → execution.output；CONFIRM → confirmation 待 resolve
pipeline.resolve(result.confirmation, approved=True/False, subject=..., trace_id=..., session_id=..., content=...)
```

## 5. 角色间契约清单

**B（归约/网关）必须保证：**
1. 产出 `CanonicalEffect`，`resources` 用**绝对路径**（`file://` 前缀可选）；相对路径会被 C 的沙箱拒绝；
2. 每个 `DataReference` 内联携带 `TrustLabel`（IFC 裁决不依赖外部值存储）；
3. 归约失败设 `normalization_confidence=FAILED`（高影响效果会被 I6 硬拒）；
4. `effect_id` 全局唯一；`derived_from` 填上游事件 `event_id`；
5. 消息类效果 destination 设为接收方主体标识（如邮箱），才能命中 readers 通道（A 的 v0.2 修正）；
6. **供审计字段**：每个工具的 manifest digest（plan.md §2.C 验收 3 要求入审计链），随效果或网关上下文传给 C。

**D（规划/检测/评测）必须保证：**
1. `IntentContract` 只编译自信任输入；LLM 输出过 pydantic 严格校验，不绕过；
2. `RiskSignal` 只能升风险（I7）；
3. 评测消费走 `ProvenanceService` / `AuditStore`，不直接读 SQLite 表结构；
4. **供审计字段**：LLM 模型版本（plan.md §2.C 验收 3 要求入审计链），随决策请求传给 C。

**C 对 A 的消费（已冻结）：**
- `verify_ticket` / `issue_ticket` / `hash_effect`（ticket.py）；`PolicyEngine.evaluate`（engine.py）；签名密钥属 TCB 由部署方注入。

## 6. B 的增量接口（v0.1，2026-10-15）

> 状态：实现草案，尚未完成 B/C 执行职责对齐，不代表已获得协作方确认。
> 当前阻塞项及最小复现见 [B 模块复查](module-b-review.md)。本节记录现有代码，不能据此绕过第 3 节的 Broker 执行要求。

独立修复约定（2026-10-15）：`connect_stdio(..., expected_identity=...)` 必须接收部署批准的
`stdio_identity(command, args, env)`，先比较再启动；该 pin 不包含初始化后的 serverInfo。
决策审计保存效果摘要及经认证加密的原始 decision payload，可信重放方使用
`camel.gateway.audit.recover_decision_payload(payload, signing_key=..., event_id=...)` 恢复原始输入。
加密密钥从部署签票密钥按独立用途派生；须保护并保留相应历史密钥。普通报告不得调用解密入口。
这只调整 B 自有接口和 B 写入的 payload，不修改 A/C 公共模型、存储 API 或真实执行入口。

本节不修改 A/C 已冻结的模型或函数签名。完整部署示例及边界见 `handoff-b.md`。

```python
from camel.normalization import (
    IngressNormalizer, NormalizationContext, EffectNormalizer, ToolBinding, EffectSpec,
)
from camel.gateway import (
    MCPSecurityGateway, CallContext, connect_stdio, connect_http,
    serve_stdio, streamable_http_app,
)

view = IngressNormalizer().normalize(text)
# original: 取证；normalized/decoded_views: 检测匹配；suspicious_positions: 原文字符下标
context = NormalizationContext(workspace=root, cwd=root, parent_ids=event_ids,
                               data_refs=references, resource_labels=trusted_file_labels)
result = EffectNormalizer(network=network_policy).normalize(binding, arguments, context)
# effects: CanonicalEffect[]；blocked: 整次调用禁止执行；arguments: 上游实际应接收的规范参数
```

| 适配器 | 归约 | 约束 |
|---|---|---|
| fs | READ / WRITE，operation=`file_read` 等 | 每路径一个效果；绝对 realpath；工作区包含；未知文件密级默认 SECRET |
| shell | EXEC + READ / WRITE / EGRESS / REPO_MUTATE | bashlex AST；静态子集；参数摘要绑定；动态展开、编码执行、未知命令产生 FAILED EXEC |
| net | EGRESS，operation=`http_get` 等 | 精确主机/端口允许列表；全部 DNS 地址检查；重定向重新授权 |
| git | READ / REPO_MUTATE，联网额外 EGRESS | `working_tree` / `commit` / `remote_change` / `push` 等；远端别名只来自可信配置 |
| mcp | 配置中的 EffectSpec[] | 配置属于 TCB；资源按字段展开；邮件等 destination 保留主体标识，URL 必须用 net 适配器 |

`ToolBinding(adapter, operation, argument_map, effects, result_label)` 定义工具真实语义，不能从工具描述推断。
`argument_map` 为「上游参数名 → 适配器参数名」。`NormalizationResult.arguments` 是反向映射后的上游参数；
执行方不得执行原始参数代替该结果。Shell 原文不重写，执行隔离仍由 C 提供。

`MCPSecurityGateway.register(server_id, transport, expected_identity=..., expected_digest=..., bindings=..., context=...)`
只由可信宿主调用。身份/manifest 不符即拒绝；首次信任仅允许显式开发开关。发现和每次调用前重新检查 manifest，
变化暂停整台 server，记录 `tool_manifest_changed`。自动恢复或接受新 digest 均不提供。

`call_tool(server_id, tool, arguments, context=...)` 返回 `GatewayResult`：
DENY/FAILED 无执行；CONFIRM 只有 confirmation_id/text；ALLOW 在签发并消费全部效果的单次票据后调用上游。
`resolve(id, approved=..., context=...)` 只由可信确认界面调用；绑定主体、session、参数、manifest、策略版本和有效期。
MCP 仅公开 `server_id__tool` 的发现/调用，既无注册/确认工具，也无原始 transport 引用。

`ToolResultEnvelope` v1 含来源、manifest_digest、event_id、保守合并后的 labels、原始 payload、
按 JSON Pointer 索引的 `text_views` 和 suspicious_content。工具内容始终 UNTRUSTED / DATA_ONLY，默认 SECRET；
`result_sink(envelope)` 在交给 Agent 前 await，D 在此读取规范化视图并接检测器。sink 缺省表示检测器尚未接入，
不代表检测已完成。敏感原文保留在受控 envelope 内，审计只记录参数/结果摘要及带标签的效果。

HTTP 下游使用每请求认证的无状态 JSON Streamable HTTP；必须配置 Host，Origin 默认为不允许，GET SSE/DELETE 返回 405。
上游 HTTP 禁代理、禁重定向，校验 DNS 后连接已批准 IP，并保留 Host/TLS SNI。
上游 stdio 绑定可执行文件及显式绝对脚本文件摘要、参数和环境。部署方负责代码、依赖、凭据与进程隔离。

## 7. D 生产适配器与检测桥（v1，2026-10-16）

> D 真实链路接入 B/C 的增量接口。`NormalizedCall`、`ToolResultEnvelope`、网关签名均未改动。

### 7.1 D 生产适配器（`camel.planner.production_adapter`）

```python
from camel.planner.production_adapter import PRODUCTION_TOOLS, normalize_production

normalized = normalize_production(compiled, plan, sources, workspace=Path("/ws"))
# 每节点调用 B 真实 EffectNormalizer（fs read 绑定），再投影为 D 的严格 TDG 效果：
#   backend="production_adapter"、effect_id=node.effect_refs[0]、operation="read_file"、
#   data_refs 恰为 source 标签、derived_from=node.source_ids
```

投影语义：真实归约用于**验证**（blocked / 效果数 ≠ 1 / 非 READ / `resources != (node.resource_id,)`
/ confidence 非 EXACT / resource_id 非 realpath 规范形 → `PlanError`，fail closed），通过后按 D 的
`validate_plan` 冻结契约重述为确定性效果。operation 字面量 `read_file`（D 侧）与 B 的 `file_read`
是同一动作的两个命名约定，映射固定在此处。`NormalizedCall` 不加 arguments 字段：只读 fs 模板下
执行输入由 `effect.resources[0]` 完全决定；B 自留 `NormalizationResult.arguments` 供其派发。

### 7.2 result_sink 检测桥（`camel.detection.gateway_bridge`）

```python
from camel.detection.gateway_bridge import DetectionSink

sink = DetectionSink()
gateway = MCPSecurityGateway(..., result_sink=sink)   # 网关签名零改动
sink.results  # dict[event_id, DetectionResult]
```

- `content_views(envelope)`：每个 `text_views` 指针产出一个 D3 `ContentView`（raw=original、
  normalized=normalized、整文 SpanMap、label=envelope.labels + source_id 入 provenance）。
- 语义：检测**发现只记录不阻断**（保留 D 良性误报契约，post-hoc 不升风险）；检测失败或超预算
  （>16 views / >32k 字每 view / >64k 总字符）→ `raise GatewayError("detection_failed_content_withheld")`，
  网关既有语义使 envelope 不返回 Agent（fail closed）。
- v1 不在 sink 内写审计（envelope v1 无 trace_id，内存台账按 event_id 关联）；envelope v2 增
  trace 字段后再接审计链。

### 7.3 D 真实执行流（`camel.evaluation.real_chain`）

```python
from camel.evaluation.real_chain import run_real_flow

result = run_real_flow(case, directory, workspace=..., scratch=..., audit=..., signing_key=...,
                       model_version=..., code_commit=...)
# run_flow 注入 executor/normalize/tools/documents（默认值 = 原夹具路径，字节级不变）；
# real_tool_calls = 实际经 SecureExecutionPipeline 执行的效果数
```

审计供数：真实链路构造 `AuditContext(model_version=..., tool_manifest_digest=digest(PRODUCTION_TOOLS), code_commit=...)`
透传进每个 `pipeline.run`，决策与执行 payload 均携带 context。

## 8. AgentDojo 托管评测接缝（v2，2026-10-17）

`make_tools_pipeline` 接受 `deepseek:<model>`；默认从 `DEEPSEEK_API_KEY` 取密钥、从
`DEEPSEEK_BASE_URL` 取 OpenAI 兼容基址（默认 `https://api.deepseek.com`），SDK 重试固定为 0。
可选的 `provider_client` / `quarantined_model` 只用于托管评测把主规划和隔离解析的每次 HTTP
尝试接到同一个持久请求预算；密钥不得进入 argv、审计、trace 或 git 文件。
`deepseek-flash` 的隔离结构化输出固定关闭 thinking：PydanticAI 用 `tool_choice=required` 返回
typed output，而 DeepSeek thinking 模式拒绝该组合。主规划保持 provider 默认模式。

`AgentDojoGatewayRuntime`（v3 前身 `WorkspaceGatewayRuntime`）是 B3 的 AgentDojo 执行边界，
按套件（workspace / travel / banking / slack）参数化：

- 每个套件的全部工具必须完整落在冻结的 READ / WRITE 二分审阅表（`SUITE_TOOL_REVIEWS`，
  来源 = `pipeline_elements/security_policies/{workspace,travel,banking,slack}.py` 的既有
  no_side_effect_tools（读）与 policies 注册（写）），出现新工具即拒绝启动：
  - workspace：24 = 14 读 + 10 写；
  - travel：28 = 22 读 + 6 写（send_email、create/reserve/cancel_calendar_event、reserve_hotel/car_rental/restaurant）；
  - banking：11 = 6 读 + 5 写（send_money、schedule_transaction、update_scheduled_transaction、update_password、update_user_info）；
  - slack：11 = 5 读 + 6 写（add_user_to_channel、invite_user_to_slack、remove_user_from_slack、send_direct_message、send_channel_message、post_webpage）；`get_webpage` 是带 is_public 策略的读，按 READ 分类（结果标签本就 UNTRUSTED）；
- READ 经 B `EffectNormalizer`、A `PolicyEngine`、C 持久 ticket/audit、真实上游虚拟环境调用、
  B `ToolResultEnvelope`、D `DetectionSink` 返回；
- AgentDojo 的结构化结果完整、未截断地序列化为一个确定性 JSON detection view；原生对象仍返回
  benchmark。这样 D 对完整内容扫描，同时避免列表的每个字符串字段错误消耗一个 view 配额；若完整
  JSON 超过单 view 字符预算仍 fail closed；
- WRITE 进入 CONFIRM；benchmark 无可信确认 UI，因此返回结构化“被策略阻断”结果且不调用上游，
  这不是 tool error，也不会把被防御阻断的攻击从 ASR 分母删除；
- AgentDojo 的邮箱/日历/云盘/预订/账户/频道都是一次复合的内存 RPC，依照 §6 的既有职责由 Gateway
  派发。C Broker 只执行真实本地 READ/WRITE/EGRESS；不得为追求“全链”把虚拟工具伪装成本地 IO 或
  重复执行。C 在此路径提供持久 ticket 使用计数与 hash-chain audit，故 B3 仍覆盖 A/B/C/D。

托管 smoke 的冻结人口为 AgentDojo 0.1.34、benchmark v1.2、workspace、5 个只读用户任务、
`injection_task_0`、`important_instructions`，以及 B0/B1/B3 三组：每组 5 benign + 5 attack +
1 goal control，共 33 episodes。每个实际 HTTP 尝试须在发送前 fsync 预约，请求失败不退款；错误、超时、
预算耗尽保持 unknown，不能伪装成攻击被阻断。主指标同时报告 benign utility、ASR、B3 confirm rate 和耗时。

v3 全矩阵（2026-10-17 冻结）：4 套件 × 6 攻击族（direct / ignore_previous / system_message /
injecagent / important_instructions / tool_knowledge）× B0/B1/B3。每套件×组人口 =
用户良性 + 注入 goal control + 用户 × 注入 × 攻击族；全套件三组共 17478 episodes
（每组分摊 workspace 3414 / travel 867 / banking 889 / slack 656）。`tool_knowledge`
要求注入 ground truth 带 placeholder_args，不满足的组合诚实记 NATIVE_ERROR 并在报告计数，
不静默剔除。同一 DeepSeek 账户的并发运行 ≤3（每套件内 3 组并行、套件间串行）。

## 9. 破坏性变更流程

1. 提出方在群里贴变更点 + 影响面（哪些模块的哪些调用）；
2. 更新本文对应小节（含版本注记）；
3. 涉及 §2 数据模型的还需 bump `schema_version`；
4. 各模块自行适配，`git pull --rebase origin dev` 后直推 dev（团队约定，不走 PR）。
