# 模块 A（安全内核）交接文档

> 完成日期：2026-10-14。负责人角色：plan.md 中的 **A · 安全内核**。
> 读者：接手 B / C / D 模块的工程师或 agent。读完本文应能直接使用 A 提供的接口，无需读全部源码。

## 1. 干了什么

按 plan.md §2.A 完成安全内核的**全部首版职责**：

1. 5 个版本化 Pydantic 核心模型（`TrustLabel` / `IntentContract` / `CanonicalEffect` / `Decision` / `CanonicalEvent`），均可生成 JSON Schema；
2. 三态 Decision Composer（ALLOW / CONFIRM / DENY，硬 DENY 不可被覆盖，风险只能升级）；
3. 强类型、默认拒绝的 YAML 策略 DSL v0（Pydantic 编译为纯谓词，加载期 fail closed）；
4. IFC：机密性/完整性双维格 + 引擎内置 I4 硬规则；
5. 一次性能力票据（HMAC 签名，绑定 subject + effect hash + resource + destination + expiry + max_uses）；
6. 旧 `Capabilities` / `Allowed|Denied` 兼容转换层；
7. 不变量 I1–I7 测试 + 旧策略语义黄金对比测试。

**未改动任何现有文件**（迁移原则：先新增稳定模型，不移动旧代码）。新增三个目录：`src/camel/core/`、`src/camel/policy/`、`tests/unit/`。

## 2. 验证命令与当前状态

```bash
.venv/bin/ruff check            # All checks passed
.venv/bin/ruff format --check   # 77 files already formatted
.venv/bin/pyright               # 0 errors
.venv/bin/python -m pytest -q   # 194 passed（126 既有 + 68 新增）
```

注意：`uv run` 在本机需要联网下载 Python 会失败，直接用 `.venv/bin/` 下的工具。

## 3. 文件地图

| 文件 | 内容 |
|---|---|
| `src/camel/core/labels.py` | `TrustLabel` + `Integrity`/`Confidentiality`/`Authority` 格；`join`（只降完整性/权限、只升机密性、收窄 readers）；`declassify`/`endorse` 显式特权操作（需 `LabelPrivilege` 理由记录） |
| `src/camel/core/effect.py` | `CanonicalEffect`、`DataReference`（内联携带 TrustLabel）、`EffectType`、`is_side_effecting`/`is_high_impact` |
| `src/camel/core/contract.py` | `IntentContract`、`AllowedEffect`（operation/resource glob）、`validate_child_contract`（I2 委派校验） |
| `src/camel/core/events.py` | `CanonicalEvent`（trace/session/parent_ids/span_map/labels） |
| `src/camel/core/decision.py` | `Decision`、`RiskSignal`、`HardVerdict`、`DecisionComposer` |
| `src/camel/policy/dsl.py` | `Conditions`（10 个条件键，extra=forbid）、`PolicyRule`、`load_rules`（多文档 YAML） |
| `src/camel/policy/engine.py` | `PolicyEngine.evaluate`（固定优先级，见 §4）、`DestinationClassifier` |
| `src/camel/policy/ticket.py` | `issue_ticket`/`verify_ticket`/`hash_effect`、`TicketStore` 协议 + `InMemoryTicketStore` |
| `src/camel/policy/compat.py` | `trust_label_from_capabilities` / `decision_from_legacy` / `legacy_from_decision` |
| `src/camel/policy/fixtures/*.yaml` | 4 个策略 fixture（2 个 arch.md 示例 + 2 个旧策略语义复现） |
| `tests/unit/core/`、`tests/unit/policy/` | 68 个测试 |

## 4. 不变量 → 测试映射（验收依据）

| 不变量 | 实现位置 | 测试 |
|---|---|---|
| I1 硬 DENY 即最终 | `DecisionComposer.compose` | `test_decision.py::test_i1_*` |
| I2 委派权限不扩张 | `validate_child_contract` | `test_contract.py::test_*delegation*` |
| I3 低完整性不扩权 | DSL `any_data.integrity_at_most` + fixture | `test_compat.py::test_golden_parity_trusted_fields_policy` |
| I4 机密性不越 clearance | `PolicyEngine.evaluate` 第 2 步 | `test_engine.py::test_i4_*`、`test_unknown_destination_*` |
| I5 执行需有效授权 | `verify_ticket`（全失败路径 raise） | `test_ticket.py`（篡改/跨主体/换效果/过期/超次数） |
| I6 规范化失败 fail closed | `PolicyEngine.evaluate` 第 1 步 | `test_engine.py::test_i6_*` |
| I7 风险只能升级 | `DecisionComposer`（signals 只进 CONFIRM） | `test_decision.py::test_i7_*`、`test_engine.py::test_i7_*` |

引擎固定评估顺序（arch.md §7 的 A 层子集）：①规范化失败 → ②IFC → ③Intent Contract → ④DSL 规则 → ⑤Composer 合并风险信号。ALLOW 必须有显式 ALLOW 规则命中，否则默认 DENY。

## 5. 给 B / C / D 的接口（已冻结，只增量演进）

**B（归约/网关）**：你的产物是 `CanonicalEffect`。每个归约出的数据参数构造 `DataReference(ref="value://...", label=TrustLabel(...))`；归约失败时设 `normalization_confidence=NormalizationConfidence.FAILED`（高影响效果会被 I6 硬拒）。策略匹配的目的地域由 `DestinationClassifier`（glob→domain→clearance）提供，配置归你或部署方。

**C（执行/审计）**：用户 CONFIRM 后调用 `issue_ticket(key, subject=..., effect=..., expires_at=...)` 拿票据；执行前 `verify_ticket(key, ticket, effect, subject=..., store=..., now=...)`，任何失败抛 `TicketVerificationError`。签名密钥属 TCB，由你保管。`TicketStore` 是协议，请用审计存储实现持久版替换 `InMemoryTicketStore`。每个 `Decision.policy_version`（`sha256:...`）必须进审计事件。

**D（规划/检测/记忆）**：你产出 `IntentContract`（编译自信任输入）和 `RiskSignal`（只能升风险）。调 `PolicyEngine.evaluate(effect, now=..., contract=..., risk_signals=...)`。LLM 输出构造 `IntentContract`/`RiskSignal` 时 pydantic 严格校验天然拒绝畸形输出；不要绕过校验。

**最小用法示例**：

```python
from datetime import datetime, timezone
from camel.core import CanonicalEffect, DataReference, EffectType, TrustLabel, Confidentiality
from camel.policy import PolicyEngine, DestinationClassifier, load_rules

rules = load_rules(open("src/camel/policy/fixtures/deny_secret_egress.yaml").read())
engine = PolicyEngine(rules, DestinationClassifier(domains={"https://*.corp.com/*": "corp"}))
effect = CanonicalEffect(effect_id="fx_1", type=EffectType.EGRESS, operation="http_post",
                         data_refs=(DataReference(ref="value://env", label=TrustLabel(confidentiality=Confidentiality.SECRET)),),
                         destination="https://evil.invalid/")
decision = engine.evaluate(effect, now=datetime.now(timezone.utc))  # DENY
```

## 6. 与 arch.md 的有意偏差（均已记录在代码 docstring）

1. `CanonicalEffect.data_refs` 内联携带 `TrustLabel`（arch 画的是裸 `value://` 字符串）——IFC 裁决不能依赖外部值存储。
2. `TrustLabel` 增加 `data_classes` 字段（arch 放在 contract 的 forbidden 侧）——数据类别是数据的属性，不是引用的属性。
3. 引擎合同违约（效果/目的地/预算超合同）给 CONFIRM 而非 DENY，对应 arch.md §8.2「确认或按组织策略拒绝」；组织要硬拒可加 DSL DENY 规则。
4. `validate_child_contract` 的目的地包含检查是近似（glob 子集不可判定）：只接受完全相同 pattern 或父级 `**`。
5. `declassify`/`endorse` 的理由记录由调用方审计层落盘，本模块只要求传入 `LabelPrivilege`。

## 7. 已知问题与留给后续的事

0. **（v0.2 已修）CaMeL 核心习语 `recipients ⊆ readers` 已内建**：引擎 IFC 步的放行条件为「域 clearance 足够 **或** 目的地主体显式在 readers 集合中」（`engine.py` 第 2 层）。注意：readers 通道要求**显式非空 readers 集合**，`readers=None`（public）只走 clearance 通道，未知目的地保持默认拒绝。语义对齐旧 `can_readers_read_value`，测试：`test_camel_recipients_subset_readers_idiom` 等 3 个。归约层（B）注意：消息类效果应把 destination 设为接收方主体标识（如邮箱地址），才能命中 readers 通道。
1. **发现旧代码 bug（未修，外科式原则）**：`security_policy.py` 的 `base_security_policy` 把 `get_all_readers` 返回的整个 `(readers, visited)` 元组与 `Public()` 比较，导致对任何非无副作用工具**无条件 DENY**。实际生效路径是 `check_policy` 里的 `is_public` 检查，所以没暴露。建议另开 issue。
2. **四套 AgentDojo 旧策略只做了语义等价黄金测试**（`base` 公开性门禁 + `make_trusted_fields_policy` 可信字段模式，fixture 见 `base_public_only.yaml` / `trusted_parameters_only.yaml`）。需要查 AgentDojo 环境的策略（如 workspace 的附件共享名单）**无法用 DSL v0 表达**——等 B 的 Normalizer 把这些信息归约进 `CanonicalEffect` 后再转换，届时把旧 fixture 扩展为全量黄金测试。
3. `verify_ticket` 的 `destination_mismatch` 分支不可达（destination 已含在 effect_hash 内，会先触发 `effect_mismatch`），保留作纵深防御。
4. ~~`InMemoryTicketStore` 非线程安全~~（v0.6 已修复：`TicketStore` 协议改为 `uses` + `try_consume` 原子检查并消费，内存实现加锁、SQLite 实现单条条件 upsert；`record_use` 已移除）。
5. 本机 agentdojo 包有跨版本循环导入，涉及它的测试文件须先 `import agentdojo.task_suite`（见 `test_compat.py` 头部注释）。
6. 性质测试用全枚举代替 hypothesis（不在依赖中），格公理（交换/结合/幂等/单调）已全覆盖。

## 8. 下一个 agent 开工前请确认

- [ ] 跑 §2 四条命令确认全绿（环境损坏时先修环境再动手）；
- [ ] 读 plan.md §3 的接口冻结表——修改 `core/` 五个模型的字段属于破坏性变更，需全员对齐并 bump `schema_version`；
- [ ] 遵守 CLAUDE.md 与 arch.md §12：PR 首部四要素、外科式修改、安全修复先写复现测试。
