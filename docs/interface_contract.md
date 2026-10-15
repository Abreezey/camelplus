# 公共接口契约（跨模块合作说明）

> 维护规则：本文是 A/B/C/D 四个模块之间的**接口单一事实来源**。任何跨模块签名的变更必须先改本文、在群里同步、再改代码。各模块内部私有函数不在契约范围内。
> 当前状态：A（安全内核）、C（执行与审计）已交付；B（归约/网关）、D（规划/检测/评测）待开工。

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
# v0 仅 READ/WRITE；其余效果 UnsupportedEffectError（fail closed + 审计 rejected）
# WRITE 需要 POSIX O_NOFOLLOW；缺少该能力时在票据消费和 IO 前 UnsupportedEffectError，审计 rejected
# 配置 vault 时：票据校验后 HMAC 派生短期凭据（绑定票据、随票据过期），
#   result.credential_handle 与审计 payload 只记 opaque handle（"cred_" 前缀），secret（SecretBytes）绝不外泄

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

## 6. 破坏性变更流程

1. 提出方在群里贴变更点 + 影响面（哪些模块的哪些调用）；
2. 更新本文对应小节（含版本注记）；
3. 涉及 §2 数据模型的还需 bump `schema_version`；
4. 各模块自行适配，`git pull --rebase origin dev` 后直推 dev（团队约定，不走 PR）。
