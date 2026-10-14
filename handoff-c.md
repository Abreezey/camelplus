# 模块 C（执行与审计）交接文档

> 完成日期：2026-10-14。负责人角色：plan.md 中的 **C · 执行与审计**。
> 读者：接手 B / D 模块的工程师或 agent，以及负责最终联调的人。读完本文应能直接把效果送进执行管道、消费审计与溯源数据，无需读全部源码。

## 1. 干了什么

按 plan.md §2.C 完成执行与审计的**首版核心链路**（arch.md §6.9 Broker、§6.10 Provenance、§13 任务 6–7）。范围取舍与未达成项见 §6/§7，**不是全部职责**：

1. **审计层 `audit/`**：追加式哈希链事件存储（`AuditStore`，SQLite 落盘、`:memory:` 可测）、可重放决策载荷（`decision_event`/`decision_payload`）、执行事件（`execution_event`/`execution_payload`，三态 outcome：executed / rejected / failed）、脱敏（`redact`：秘密 → sha256 前 16 位受控引用）、链完整性校验（`verify_chain`，篡改/删行必 `ChainIntegrityError`）；
2. **票据持久化** `SQLiteTicketStore`：实现 A 的 `TicketStore` 协议，`ON CONFLICT DO UPDATE` 原子递增计数，跨进程、跨重启持久；
3. **溯源** `ProvenanceService`：`timeline(trace_id)` 时间线、`dag(trace_id)` 双来源边（事件 `parent_ids` + 效果 `derived_from`）、`report(trace_id)` 脱敏 markdown 报告；
4. **沙箱 profile v0** `SandboxProfile`：只读工作区根 + 可写 scratch 目录；`realpath` 全解析后包含检查（防 `..` 与 symlink 逃逸），写路径 `O_NOFOLLOW + 0o600`；
5. **执行代理** `ExecutionBroker`：v0 仅支持 `READ` / `WRITE`，其余效果类型 fail closed（`UnsupportedEffectError`）；固定校验顺序 **静态沙箱 → verify_ticket → IO → 审计**，每次执行尝试（无论成败）都落一条审计事件；
6. **确认流** `ConfirmationAuthority`：仅接受 CONFIRM 决策 → 生成 `ConfirmationRequest`（`render()` 渲染资源/目的地/后果/原因/安全替代/策略版本）→ `approve()` 签发单次能力票据 / `deny()` 只审计不签票；
7. **集成管道** `SecureExecutionPipeline`：DENY 阻断零执行 / CONFIRM 永不自动执行（挂起等用户 `resolve`）/ ALLOW 现签单次票据再执行（I5：每个已执行效果都有可验证授权）；
8. **48 个新测试**（单测 43 + 集成 5），见 §4。

**未改动任何现有文件**。新增四个目录：`src/camel/audit/`、`src/camel/broker/`、`tests/unit/audit/`、`tests/unit/broker/`、`tests/integration/`。

## 2. 验证命令与当前状态

```bash
.venv/bin/ruff check            # All checks passed
.venv/bin/ruff format --check   # 96 files already formatted
.venv/bin/pyright               # 0 errors, 0 warnings
.venv/bin/python -m pytest -q   # 245 passed（197 基线 + 48 新增）
```

注意：`uv run` 在本机需要联网下载 Python 会失败，直接用 `.venv/bin/` 下的工具。

## 3. 文件地图

| 文件 | 内容 |
|---|---|
| `src/camel/audit/store.py` | `AuditStore(path)`（`append` 返回 record_hash、`events(trace_id)`、`payload_of(event_id)`、`verify_chain()`）；两张表 `audit_events`（seq/event_id/trace_id/…/prev_hash/record_hash 哈希链）+ `audit_payloads`（payload 与事件分离）；`redact`；`decision_event`/`decision_payload`（可重放决策，含 policy_version）；`execution_event`/`execution_payload`；`ChainIntegrityError` |
| `src/camel/audit/tickets.py` | `SQLiteTicketStore`（A 的 `TicketStore` 协议持久实现：`uses`/`record_use`，原子递增） |
| `src/camel/audit/provenance.py` | `ProvenanceService(store)`：`timeline` / `dag`（parent_ids + derived_from 双来源边）/ `report`（markdown，脱敏） |
| `src/camel/broker/profile.py` | `SandboxProfile.workspace(root, scratch)`、`resolve_read`/`resolve_write`（realpath 包含检查）、`to_path`（剥 `file://`、拒相对路径）、`SandboxViolationError` |
| `src/camel/broker/executor.py` | `ExecutionBroker(signing_key, profile, ticket_store, audit)` → `execute(effect, ticket, subject=..., trace_id=..., session_id=..., content=...)`；`UnsupportedEffectError`（v0 仅 READ/WRITE）；写用 `os.open(O_WRONLY\|O_CREAT\|O_NOFOLLOW, 0o600)` |
| `src/camel/broker/confirm.py` | `ConfirmationAuthority(signing_key, audit)`：`request`（仅 CONFIRM）/ `approve`（签单次票据）/ `deny`；`ConfirmationRequest.render()`；`ConfirmationExpiredError`（默认 TTL 5 分钟） |
| `src/camel/broker/pipeline.py` | `SecureExecutionPipeline(engine, broker, confirmations, audit, signing_key)`：`run(effect, ...)` 三分支 + `resolve(request, approved=..., ...)`；`PipelineResult(decision, execution, confirmation)` |
| `tests/unit/audit/`（15）、`tests/unit/broker/`（28）、`tests/integration/`（5） | 48 个测试，见 §4 |

## 4. 验收 → 测试映射（plan.md §2.C）

| 验收标准 | 实现 | 测试 |
|---|---|---|
| Broker 之外无路径执行效果（旁路阻断） | `ExecutionBroker.execute` 先 `profile.resolve_*` 再 `verify_ticket`，任一失败 raise 且审计 rejected | `test_executor.py`：伪造票据/错签名 key/错主体/过期/超次数全部拒绝（6 个）+ 沙箱拒绝不烧票据 |
| 能力票据不可复用（I5） | A 的 `verify_ticket` + C 的 `SQLiteTicketStore` 持久计数 | `test_tickets.py`（3 个，含跨重启持久、与 `verify_ticket` 互操作）+ `test_executor.py` 单次使用即失效 |
| 事件凭审计链可重放 | `decision_payload` 含重建 Decision 的全部字段（含 policy_version） | `test_secure_pipeline.py::test_decisions_replayable_from_audit_alone` + `test_store.py` 决策重放。**部分达成**：模型版本 / 工具 manifest digest / 代码提交三个审计字段未实现，数据源在 B/D/部署方（见 §7.1） |
| 审计脱敏 | `redact`：秘密值 → `sha256:<16hex>` 受控引用 | `test_store.py::test_redact_*` + `test_provenance.py` 报告内容 |
| 哈希链防静默篡改 | `record_hash = sha256(prev_hash \| seq \| event_json)` | `test_store.py`：篡改检测、删行检测、链验证 |

沙箱（arch.md §13 任务 6「无网、只读工作区 profile」）：`test_profile.py` 10 个（包含检查、`..` 逃逸、相对路径拒绝、symlink 逃逸、写域限定）。
确认流（arch.md §13 任务 7「scoped confirmation ticket + 完整审计链」）：`test_confirm.py` 6 个 + `test_secure_pipeline.py` CONFIRM 分支事件序列（decision → confirmation → confirmation → execution）。

各文件测试数：`test_store.py` 8、`test_tickets.py` 3、`test_provenance.py` 4、`test_profile.py` 10、`test_executor.py` 12、`test_confirm.py` 6、`test_secure_pipeline.py` 5。

## 5. 给 B / D 的接口（公共契约详见 `docs/interface_contract.md`）

**B（归约/网关）**——你的产物 `CanonicalEffect` 直接是 pipeline 的输入：
- `resources` 必须是**绝对路径**（`file://` 前缀可选，`to_path` 会剥离）；相对路径被拒（`SandboxViolationError`）；
- v0 沙箱只执行 `READ` / `WRITE` 两类效果；你归约出的 `EXEC` / `EGRESS` / `REPO_MUTATE` 会 fail closed（`UnsupportedEffectError` 并审计 rejected）——这是设计内的安全默认，不是 bug；
- `effect_id` 必须全局唯一（审计 `event_id` 唯一约束）；`derived_from` 填上游事件的 `event_id`，溯源 DAG 用它建边。

**D（规划/检测/评测）**——你消费审计与溯源：
- 评测报告入口：`ProvenanceService(store).report(trace_id)`（脱敏 markdown）；
- 重放与统计：`store.events(trace_id)` + `store.payload_of(event_id)`（决策载荷含 `policy_version`，可复算任何历史裁决）；
- 你的 `IntentContract` 直接传 `pipeline.run(effect, contract=...)`，引擎会做合同校验。

**最小用法示例（全链路）**：

```python
from camel.audit import AuditStore, SQLiteTicketStore
from camel.broker import (
    ConfirmationAuthority, ExecutionBroker, SandboxProfile, SecureExecutionPipeline,
)
from camel.policy import DestinationClassifier, PolicyEngine, load_rules

key = b"test-signing-key"  # TCB 签名密钥，部署方保管
audit = AuditStore(":memory:")                      # 生产传文件路径
engine = PolicyEngine(load_rules(rules_yaml), DestinationClassifier())
broker = ExecutionBroker(signing_key=key,
                         profile=SandboxProfile.workspace(root="/ws", scratch="/ws/scratch"),
                         ticket_store=SQLiteTicketStore("tickets.db"), audit=audit)
pipeline = SecureExecutionPipeline(
    engine=engine, broker=broker, audit=audit,
    confirmations=ConfirmationAuthority(signing_key=key, audit=audit),
    signing_key=key,
)

result = pipeline.run(effect, subject="user:alice", trace_id="t1", session_id="s1")
# DENY   → result.execution is None（零执行、已审计）
# ALLOW  → result.execution.output（已签单次票据、已审计）
# CONFIRM → result.confirmation.render() 给用户看，之后：
pipeline.resolve(result.confirmation, approved=True,  subject="user:alice", trace_id="t1", session_id="s1")
pipeline.resolve(result.confirmation, approved=False, subject="user:alice", trace_id="t1", session_id="s1")
```

## 6. 与 arch.md 的有意偏差（均已记录在代码 docstring）

1. **ALLOW 分支也走票据**：arch §7 序列图中 ALLOW 不经票据、CONFIRM 才经票据。为统一 I5（每个已执行效果都有可验证授权），pipeline 在 ALLOW 时也现签**单次**票据再执行，执行后立即失效。
2. **沙箱是 Python 层强制**（realpath 包含检查 + `O_NOFOLLOW` 写入），非内核级（Landlock/seccomp/容器）——无 sudo 环境下的 v0 取舍，见 §7。
3. **v0 只支持 READ/WRITE**：`EXEC` / `EGRESS` / `REPO_MUTATE` 直接 fail closed，等 B 的网关与 egress 代理就位后再放行。
4. **确认 UI 是 `render()` 纯文本**（资源/目的地/后果/原因/安全替代/策略版本），Web UI 留给后续；过期请求 `approve` 时抛 `ConfirmationExpiredError`。

## 7. 已知问题与留给后续的事

1. **验收 3 部分未达成**：plan.md §2.C 要求审计事件含策略版本、模型版本、工具 manifest digest、代码提交四项。目前仅策略版本（`Decision.policy_version`）入审计；模型版本的数据源在 D（LLM 调用层）、工具 manifest digest 在 B（网关）、代码提交在部署方，三者未开工。B/D 就位后需把这三个字段接入 `decision_payload`（结构已预留：payload 是自由 dict，加键即可，不破坏哈希链）。
2. **TOCTOU 残余竞态**：`resolve_read` 的 realpath 检查与实际读 IO 之间理论上存在符号链接替换窗口；写路径已用 `O_NOFOLLOW` 缓解，读路径 v0 未做同等处理。生产建议内核级沙箱。
3. **无网络隔离（egress 代理）**：arch.md §6.9 的 egress 控制是 v0 非目标；当前"无网"靠效果类型白名单（只放 READ/WRITE）间接保证。
4. **凭据注入未实现**：plan.md §2.C 职责 1 的"Agent 进程不持有长期密钥，Broker 按票据注入短期凭据或 opaque handle"——v0 票据即授权凭据，但未做向工具进程注入短期凭据的机制，等 B 的工具网关定义工具进程模型后再做。
5. `AuditStore` SQLite 单写者；多进程高并发写需 WAL 模式或外部队列（票据计数已是跨进程安全的原子 SQL）。
6. `ConfirmationRequest` 不持久化（内存对象），进程重启后未决请求丢失，需用户重新走 `run`。
7. `ExecutionResult.output` 是 `bytes | None`，大文件读全量载入内存；流式读取留给后续。
8. `redact` 只做字符串→哈希引用替换，不做内容级 DLP 扫描（那是检测层 D 的地盘）。

## 8. 下一个 agent 开工前请确认

- [ ] 跑 §2 四条命令确认全绿（环境损坏时先修环境再动手）；
- [ ] 读 `docs/interface_contract.md`——`AuditStore` 表结构与 `ExecutionBroker.execute` 签名是公共契约，改动需全员对齐；
- [ ] 安全红线不可放松：沙箱边界只可收紧；Broker 校验顺序（沙箱 → 票据 → IO → 审计）不可重排；`verify_ticket` 失败必须 raise 不可吞。
