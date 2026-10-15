# 模块 B（通道与规范化）交接

日期：2026-10-15。范围：plan.md §2.B。公共契约见 `docs/interface_contract.md` §6。
仓库未发现 `auth.md`，设计依据为 `arch.md`、`plan.md` 和 A/C 的冻结接口。

**复查更新：三处 B 自身缺陷已修复；C 真实执行联调仍未完成。**
详见 `docs/module-b-review.md`。阶段性提交不代表整条执行链已经通过安全验收。

## 实现

- `src/camel/normalization/`：保留原文的 NFKC/预算解码视图；fs realpath；Bash AST；网络允许列表、SSRF/DNS 检查；Git 分类；可信 MCP 效果映射。
- `src/camel/gateway/`：身份及 manifest pin；schema 校验；全效果先裁决后执行；单次票据；不可重放确认；带来源标签和文本视图的返回；检测器 hook；哈希链审计。
- stdio 和 Streamable HTTP 均有真正的协议往返测试。HTTP 实际连接批准 IP，保留 Host/TLS SNI，拒绝重定向；下游逐请求认证，禁止注册/确认/原始调用旁路。
- 依赖新增 bashlex（固定 0.18）、MCP SDK v1、jsonschema、httpx、starlette、cryptography；A/C 的源码和公开接口保持原样。

## 最小宿主接线

```python
from camel.audit import AuditStore, SQLiteTicketStore
from camel.gateway import CallContext, MCPSecurityGateway, connect_stdio, serve_stdio
from camel.normalization import EffectNormalizer, NormalizationContext, ToolBinding

context = CallContext(
    subject=authenticated_user, trace_id=trace_id, session_id=session_id,
    normalization=NormalizationContext(workspace=root, cwd=root),
    contract=trusted_intent_contract, model_version=model_version, code_commit=code_commit,
)
gateway = MCPSecurityGateway(
    engine=engine, normalizer=EffectNormalizer(network=network_policy),
    audit=AuditStore(audit_path), signing_key=key,
    ticket_store=SQLiteTicketStore(ticket_path), result_sink=detector_sink,
)
async with connect_stdio(
    absolute_executable, absolute_script_args, expected_identity=configured_process_pin,
) as transport:
    await gateway.register(
        "files", transport,
        expected_identity=configured_identity, expected_digest=configured_manifest_digest,
        bindings={"read": ToolBinding(adapter="fs", operation="read")}, context=context,
    )
    await serve_stdio(gateway, context)
```

pins 由可信部署配置预先批准，不应把当前 snapshot 自动设为生产 pin。
`configured_process_pin` 是部署审核阶段用 `stdio_identity(executable, args, env)` 生成的进程 pin，
与初始化后 `register` 使用的 `configured_identity` 不同；不能在每次启动时重新计算并自动批准。
HTTP 上游改用 `connect_http(canonical_url, network_policy, headers=trusted_headers)`；
HTTP 下游改用 `streamable_http_app(gateway, authenticate=..., allowed_hosts=...)` 并交给 ASGI 服务。
确认界面只调用宿主的 `gateway.resolve`，不能相信 Agent 自报 approved。

## C / D 接入与限制

C 当前本地 Broker 仅执行 READ/WRITE，不能执行一次 MCP RPC 的组合效果。因此本版网关在可信侧签发并验证
全部效果票据，再执行一次上游 RPC；没有把不支持的效果伪装为 C 已支持。C 后续接入 RPC Broker 时应保留
这个原子授权边界、执行意图审计和不确定失败语义。

MCP 组合效果保守传播整次 RPC 的文件输入标签，不按映射顺序推断内部数据流。
B 决策审计只明文记录效果摘要、原因代码及摘要值；完整输入使用 Fernet 认证加密保存，并绑定 event_id。
可信评审者通过 `camel.gateway.audit.recover_decision_payload` 配合历史部署签票密钥恢复完整效果，
再交给原策略引擎重放。密钥用途通过 HMAC-SHA256 派生隔离；密钥不写入 SQLite，也不对 MCP 暴露解密入口。
现有 C 存储和报告 API 不变；B 的 `payload["effect"]` 是摘要，不能直接当 CanonicalEffect 重放。

进程/容器隔离、禁止 Agent 直连上游、Shell/Git 的执行环境/配置/钩子限制、文件 open-handle 的 TOCTOU 防护
仍由 C 的部署执行层落实。B 的静态归约不是 OS 沙箱。HTTP MCP 连接有实际 IP pin；其他网络/ Git 工具
必须由其执行器同样落实批准 IP、禁止隐式重定向与额外请求，单有 EGRESS 效果不能替代执行约束。

D 通过 `result_sink` 消费 labels、provenance 和 `text_views`，匹配 normalized/decoded_views，取证引用 original。
sink 异常会阻断结果向 Agent 返回，但此前的上游副作用无法回滚。外部返回不因自报 role/source/labels 提升信任。
完整 AgentDojo 适配和 detector/verifier 属于 D，旧 `main.py` 尚未自动改线。

确认队列、合同副作用计数为单进程内存状态；重启丢弃确认，不恢复执行；生产多实例/跨重启配额需要 C 的持久协调。
确认执行前按最新预算重新裁决；新增确认原因使旧确认失效，调用方必须重新发起。A 对超预算的 CONFIRM 语义保持不变。
票据消费可使用 SQLiteTicketStore 持久化。上游异常/超时记录 uncertain，不能自动重试有副作用的 RPC。
Shell/Git 仅支持可解释的静态子集，未知选项 fail closed；这可能要求 D 选择更明确的工具调用。

## 验证

遵循 CLAUDE.md：先最小失败复现，再修复；检查真正写入、读取、上游调用次数与拒绝后的零副作用；
差分测试将原始 fs/Shell/Git 调用与归约效果比较。真实协议 fixture 的上游只在临时工作区读文件并记录调用次数。
测试不连接外部网络，不启动 LLM，不使用真实凭据。

```bash
.venv/bin/pytest -q --cov=camel --cov-report=term-missing:skip-covered
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
```

本环境沙箱会阻塞异步跨线程唤醒；真实 stdio/HTTP 与相关测试在获准的沙箱外执行。

最终结果：517 项全量测试通过（273 项原有 + 244 项新增）；B 的 13 个实现文件共 1104/1104 条语句覆盖，
覆盖率 100%（单元测试与真实协议集成合计，含子进程采集；不等同于分支覆盖或安全完备证明）。
与现有 audit 模块并列最高。Ruff、全仓格式检查、Pyright、`git diff --check` 均通过。
详细验证范围见 `docs/module-b-validation.md`。
