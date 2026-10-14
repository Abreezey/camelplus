# 审计字段补全 + 凭据注入 实现计划（模块 C v0.5）

> **For agentic workers:** 本计划按任务逐条执行，步骤用 checkbox（`- [ ]`）跟踪。执行方式：Native（当前会话直接实现）或 Subagent-driven 均可。

**Goal:** 补齐 plan.md §2.C 两个遗留项——审计事件缺失的三个字段（模型版本 / 工具 manifest digest / 代码提交），以及 Broker 按票据注入短期凭据的机制骨架。

**Architecture:** 审计字段走 payload 通道（与 `policy_version` 先例一致，不改 A 冻结的 `CanonicalEvent`——其 `labels` 是 `TrustLabel` 类型不可复用）；新增 `AuditContext` 值对象经 `pipeline → broker/confirm → payload` 透传。凭据注入新增 `KeyVault`（TCB 内持长期主密钥）+ `InjectedCredential`（HMAC 派生的短期凭据，绑定票据，`SecretBytes` 防泄漏），Broker 在票据校验后、IO 前派生，审计只记 opaque handle。

**Tech Stack:** Python 3.10、pydantic v2（`SecretBytes`）、stdlib `hmac`/`hashlib`/`os.environ`、pytest。

**Spec:** `plan.md` §2.C（职责 1、验收 3）、`arch.md` §6.9 L332（凭据注入）、L582（审计四字段）、`handoff-c.md` §7.1/§7.4（差距记录）。

## Global Constraints

- 不改 A 冻结模型：`core/` 五模型的字段一律不动（`CanonicalEvent.labels` 是 `TrustLabel`，审计字段**只走 payload**，与 `policy_version` 同通道）。
- 所有新增函数参数必须可选带默认值，不破坏既有调用方与 245 基线测试。
- Broker 校验顺序不可重排：静态沙箱 → `verify_ticket` → 凭据派生 → IO → 审计。
- secret 永不进审计事件、`ExecutionResult`、repr 或日志（用 pydantic `SecretBytes`）。
- 每次提交前四条验证全绿：`.venv/bin/python -m pytest -q`、`.venv/bin/ruff check`、`.venv/bin/ruff format --check .`、`.venv/bin/pyright`（0 errors）。
- 提交信息规范：`feat(audit)/feat(broker)/test/docs(scope): 说明`；推送前 `git pull --rebase origin dev`（凭证未换前推送可能仍 403，提交先落本地）。
- 不得为通过测试删除/跳过/放宽安全规则。

## Review Focus

1. **context 字段为 None（B/D 未供数）**：payload 诚实记 `null`，不崩溃、不假装有值 → Task 1 测试 `test_decision_payload_context_none_*`。
2. **环境变量只设一部分**：`from_env` 只带已设项，未设为 None → Task 1 测试 `test_from_env_partial`。
3. **凭据 secret 序列化泄漏**：`repr()` / `model_dump_json()` 均不可读 → Task 3 测试 `test_secret_never_serialized`。
4. **handle 进审计后链仍完整、重放可读**：带 context/credential_handle 的执行后 `verify_chain()` 通过 → Task 4 测试 `test_credential_handle_audited_chain_intact`。
5. **未配置 vault 的既有行为零变化**：245 基线全绿（回归门，Task 4 验证步骤 + Task 5 全量）。

---

### Task 1: AuditContext 值对象 + payload 注入

**Files:**
- Modify: `src/camel/audit/store.py`（`decision_payload` / `execution_payload` 签名）
- Test: `tests/unit/audit/test_store.py`（追加）

**Interfaces:**
- Produces:
  - `class AuditContext(BaseModel)`（`model_config = ConfigDict(frozen=True)`），字段 `model_version: str | None = None`、`tool_manifest_digest: str | None = None`、`code_commit: str | None = None`
  - `AuditContext.from_env() -> AuditContext`：读 `CAMEL_MODEL_VERSION` / `CAMEL_TOOL_MANIFEST_DIGEST` / `CAMEL_CODE_COMMIT`，未设或空串为 None
  - `decision_payload(decision, effect, context: AuditContext | None = None) -> dict`
  - `execution_payload(effect, ticket_id, outcome, detail=None, context: AuditContext | None = None) -> dict`
  - payload 结构：context 非 None 时加键 `"context": context.model_dump()`（含 None 字段，诚实记录）；context 为 None 时加 `"context": None`

- [ ] **Step 1: 写失败测试**（追加到 `tests/unit/audit/test_store.py`）

```python
def test_decision_payload_with_context() -> None:
    ctx = AuditContext(model_version="gpt-4o-2024-08", tool_manifest_digest="sha256:ab", code_commit="9c1f2e")
    payload = decision_payload(_DECISION, _EFFECT, context=ctx)
    assert payload["context"] == {"model_version": "gpt-4o-2024-08",
                                  "tool_manifest_digest": "sha256:ab", "code_commit": "9c1f2e"}

def test_decision_payload_context_none_is_explicit() -> None:
    payload = decision_payload(_DECISION, _EFFECT)
    assert payload["context"] is None  # 诚实记录"未提供"，不省略键

def test_execution_payload_with_context() -> None:
    payload = execution_payload(_EFFECT, "tk_1", "executed", context=AuditContext(code_commit="9c1f2e"))
    assert payload["context"]["code_commit"] == "9c1f2e"
    assert payload["context"]["model_version"] is None

def test_from_env_partial(monkeypatch) -> None:
    monkeypatch.setenv("CAMEL_CODE_COMMIT", "abc123")
    monkeypatch.delenv("CAMEL_MODEL_VERSION", raising=False)
    ctx = AuditContext.from_env()
    assert ctx.code_commit == "abc123" and ctx.model_version is None and ctx.tool_manifest_digest is None
```

（`_DECISION`/`_EFFECT` 复用该文件既有 fixture 构造；无则按 `test_store.py` 现有测试的构造方式补。）

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/python -m pytest tests/unit/audit/test_store.py -q`
Expected: FAIL（`AuditContext` 未定义 / `context` 参数不存在）

- [ ] **Step 3: 在 `src/camel/audit/store.py` 实现**

在 `redact` 之后新增 `AuditContext` 类与 `from_env`（用 `os.environ.get`，空串归一为 None）；`decision_payload` / `execution_payload` 按 Interfaces 加可选参数与 `"context"` 键。同时在 `src/camel/audit/__init__.py` 导出 `AuditContext`。

- [ ] **Step 4: 跑测试确认通过**

Run: `.venv/bin/python -m pytest tests/unit/audit -q`
Expected: PASS（原 15 + 新 4）

- [ ] **Step 5: 提交**

```bash
git add src/camel/audit/store.py src/camel/audit/__init__.py tests/unit/audit/test_store.py
git commit -m "feat(audit): AuditContext 值对象——审计事件补模型版本/manifest digest/代码提交字段"
```

### Task 2: 调用链透传 audit_context

**Files:**
- Modify: `src/camel/broker/pipeline.py`（`run` / `resolve`）、`src/camel/broker/executor.py`（`execute` / `_audit_attempt`）、`src/camel/broker/confirm.py`（`request` / `approve` / `deny` / `_audit_confirmation`）
- Test: `tests/integration/test_secure_pipeline.py`（追加）

**Interfaces:**
- Consumes: Task 1 的 `AuditContext` 与两个 payload 函数的新签名。
- Produces:
  - `SecureExecutionPipeline.run(effect, *, subject, trace_id, session_id, contract=None, content=None, audit_context: AuditContext | None = None)`
  - `SecureExecutionPipeline.resolve(request, *, approved, subject, trace_id, session_id, content=None, audit_context: AuditContext | None = None)`
  - `ExecutionBroker.execute(effect, ticket, *, subject, trace_id, session_id, content=None, parent_ids=(), audit_context: AuditContext | None = None)`
  - `ConfirmationAuthority.request/approve/deny(..., audit_context: AuditContext | None = None)`
  - 语义：`run` 内部的 decision 审计与（ALLOW 分支触发的）broker 执行、`resolve` 内部的 confirmation 与执行、`request/approve/deny` 的 confirmation 事件，payload 均携带传入 context。

- [ ] **Step 1: 写失败测试**（追加到 `tests/integration/test_secure_pipeline.py`）

```python
def test_run_threads_audit_context_into_all_payloads(tmp_path) -> None:
    # 用现有 pipeline fixture（ALLOW 分支场景），run 时传：
    ctx = AuditContext(model_version="llm-x", tool_manifest_digest="sha256:ff", code_commit="deadbe")
    result = pipeline.run(effect, subject=..., trace_id="t-ctx", session_id=..., audit_context=ctx)
    assert result.execution is not None
    events = audit.events(trace_id="t-ctx")
    payloads = [audit.payload_of(e.event_id) for e in events]
    assert all(p["context"] == ctx.model_dump() for p in payloads)  # decision + execution 都带
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/python -m pytest tests/integration/test_secure_pipeline.py -q`
Expected: FAIL（`audit_context` 参数不存在）

- [ ] **Step 3: 实现透传**

`pipeline.py`：`run`/`resolve` 加参数，`decision_payload(decision, effect, context=audit_context)`，并把参数传给内部 `broker.execute(...)` 与 `confirmations.request/approve/deny(...)`；`executor.py`：`execute` 加参数经 `_audit_attempt` 传给 `execution_payload(..., context=audit_context)`；`confirm.py`：三个公共方法加参数，`_audit_confirmation` 的 payload dict 加 `"context": audit_context.model_dump() if audit_context else None`。

- [ ] **Step 4: 跑全量测试确认通过（含基线回归）**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS（245 + Task1 新增 + 本任务新增）

- [ ] **Step 5: 提交**

```bash
git add src/camel/broker/pipeline.py src/camel/broker/executor.py src/camel/broker/confirm.py tests/integration/test_secure_pipeline.py
git commit -m "feat(broker): pipeline/executor/confirm 全链路透传 AuditContext"
```

### Task 3: KeyVault + InjectedCredential

**Files:**
- Create: `src/camel/broker/credentials.py`
- Modify: `src/camel/broker/__init__.py`（导出）
- Test: `tests/unit/broker/test_credentials.py`（新建）

**Interfaces:**
- Consumes: 无（纯新模块；`CapabilityTicket` 的 `ticket_id: str`、`subject: str`、`expires_at: datetime`）。
- Produces:
  - `class InjectedCredential(BaseModel)`（frozen）：`handle: str`（格式 `"cred_" + hex16`）、`secret: SecretBytes`、`subject: str`、`ticket_id: str`、`expires_at: datetime`；`def is_expired(self, now: datetime) -> bool`
  - `class KeyVault`：`__init__(self, master_key: bytes)`；`def derive(self, *, subject: str, ticket_id: str, expires_at: datetime) -> InjectedCredential`
  - 派生算法：`handle = "cred_" + sha256(master_key + "|" + ticket_id).hexdigest()[:16]`；`secret = HMAC-SHA256(master_key, f"{subject}|{ticket_id}|{expires_at.isoformat()}")`——同一票据重派生得到相同 handle（幂等，无存储），不同 master_key / subject / ticket / expiry 得到不同 secret。

- [ ] **Step 1: 写失败测试**

```python
def test_derive_deterministic_and_bound() -> None:
    vault = KeyVault(b"master")
    a = vault.derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    b = vault.derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    assert a == b and a.handle.startswith("cred_")
    assert vault.derive(subject="user:bob", ticket_id="tk_1", expires_at=LATER).secret != a.secret
    assert KeyVault(b"other").derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER).secret != a.secret

def test_secret_never_serialized() -> None:
    cred = KeyVault(b"master").derive(subject="u", ticket_id="t", expires_at=LATER)
    assert "b'" not in repr(cred) and str(cred.secret) == "**********"
    dumped = cred.model_dump_json()
    assert cred.secret.get_secret_value().hex() not in dumped

def test_expiry() -> None:
    cred = KeyVault(b"master").derive(subject="u", ticket_id="t", expires_at=LATER)
    assert not cred.is_expired(NOW) and cred.is_expired(LATER)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/python -m pytest tests/unit/broker/test_credentials.py -q`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `credentials.py`**

按 Interfaces 签名实现；模块 docstring 写明 TCB 边界：master_key 只存在于 vault/broker 进程，派生 secret 才注入工具进程，handle 是唯一可外泄引用。

- [ ] **Step 4: 跑测试确认通过**

Run: `.venv/bin/python -m pytest tests/unit/broker/test_credentials.py -q`
Expected: PASS（3 个）

- [ ] **Step 5: 提交**

```bash
git add src/camel/broker/credentials.py src/camel/broker/__init__.py tests/unit/broker/test_credentials.py
git commit -m "feat(broker): KeyVault 短期凭据派生——HMAC 绑定票据，SecretBytes 防泄漏"
```

### Task 4: Broker 凭据注入集成

**Files:**
- Modify: `src/camel/broker/executor.py`（`__init__` 加 `vault` 可选参数；`execute` 派生；`ExecutionResult` 加 `credential_handle`；`execution_payload` 记 handle）
- Test: `tests/unit/broker/test_executor.py`（追加）

**Interfaces:**
- Consumes: Task 3 的 `KeyVault`；`verify_ticket` 通过后的 `ticket.expires_at`。
- Produces:
  - `ExecutionBroker.__init__(..., vault: KeyVault | None = None)`
  - `ExecutionResult`（frozen）加字段 `credential_handle: str | None = None`
  - `execution_payload` 加键：派生了凭据时 `"credential_handle": cred.handle`（secret 绝不出现）
  - 行为：`vault` 配置且 `verify_ticket` 通过后、IO 前调用 `vault.derive(subject=subject, ticket_id=ticket.ticket_id, expires_at=ticket.expires_at)`；`vault=None` 时行为与 v0 完全一致（handle 为 None）。派生失败按 `failed` 审计并 raise。

- [ ] **Step 1: 写失败测试**（追加到 `tests/unit/broker/test_executor.py`）

```python
def test_execute_with_vault_returns_handle_audits_handle_only(tmp_path) -> None:
    # 现有 broker fixture 基础上传入 vault=KeyVault(b"k")
    result = broker.execute(effect, ticket, subject=..., trace_id=..., session_id=..., content=b"x")
    assert result.credential_handle and result.credential_handle.startswith("cred_")
    payload = audit.payload_of(<该次执行的 event_id>)   # 按现有测试取事件的方式
    assert payload["credential_handle"] == result.credential_handle
    assert "secret" not in payload

def test_no_vault_behavior_unchanged() -> None:
    # vault=None：credential_handle is None，payload 无 credential_handle 键
    ...

def test_vault_ticket_expiry_inherited() -> None:
    # ticket.expires_at == 凭据 expires_at（从 handle 重新 derive 验证一致性即可，或暴露断言）
    ...
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/python -m pytest tests/unit/broker/test_executor.py -q`
Expected: FAIL（`vault` 参数不存在）

- [ ] **Step 3: 实现集成**

`executor.py`：构造器存 `self._vault`；`execute` 在 `verify_ticket` 成功后、`_do_execute` 前派生（包 try/except 把派生异常转为 `failed` 审计 + raise）；成功路径 `ExecutionResult(..., credential_handle=cred.handle if cred else None)`、`_audit_attempt` 把 handle 传入 `execution_payload`。`execution_payload` 签名加 `credential_handle: str | None = None`（None 不加键）。

- [ ] **Step 4: 全量回归（Review Focus 5 的门）**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check && .venv/bin/ruff format --check . && .venv/bin/pyright 2>&1 | grep -E "^[0-9]+ error"`
Expected: 全部 PASS / 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/camel/broker/executor.py tests/unit/broker/test_executor.py
git commit -m "feat(broker): 票据校验后注入短期凭据——审计只记 opaque handle"
```

### Task 5: 文档更新与收尾

**Files:**
- Modify: `handoff-c.md`（§1 范围说明、§4 验收 3 行、§7.1/§7.4 差距状态）
- Modify: `docs/interface_contract.md`（§4 审计/执行接口补 `AuditContext`/`KeyVault` 用法；§5 B/D 供数义务不变）

- [ ] **Step 1: 更新 handoff-c.md**

§4 验收 3 行去掉"部分达成"标注，改为已实现（数据源未接时字段诚实记 null）；§7 删除第 1 条（验收 3）与第 4 条（凭据注入），或改写为"已实现，数据源待 B/D 供数"；§1 与 §3 文件地图补 `credentials.py`。

- [ ] **Step 2: 更新 interface_contract.md**

§4 补两段最小用法：`pipeline.run(effect, ..., audit_context=AuditContext.from_env())`；`ExecutionBroker(..., vault=KeyVault(os.environ["CAMEL_MASTER_KEY"]))`。

- [ ] **Step 3: 最终全量验证**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check && .venv/bin/ruff format --check . && .venv/bin/pyright 2>&1 | grep -E "^[0-9]+ error"`
Expected: 全绿（预期 245 + 约 12 新增 ≈ 257）

- [ ] **Step 4: 提交**

```bash
git add handoff-c.md docs/interface_contract.md
git commit -m "docs(handoff): C v0.5——审计四字段与凭据注入已达成，更新交接与契约"
```

---

## 已知边界（本计划不做）

- payload 不在哈希链覆盖内（`record_hash` 只覆盖 `event_json`）——既有设计，与 `policy_version` 同通道沿用；链覆盖增强需迁移已存数据，另立计划。
- `EXEC` / `EGRESS` 效果类型仍 fail closed；凭据注入的**消费端**（工具进程拿 secret 发请求）等 B 的网关定义进程模型后接入，本计划只落"派生 + 注入点 + 审计引用"骨架。
- `CAMEL_MASTER_KEY` 的生产分发（KMS/部署密钥管理）属部署方职责，本计划仅约定环境变量入口。
