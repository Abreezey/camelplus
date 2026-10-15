# B 模块接口与代码复查（2026-10-15）

结论：下列三处 B 自身缺陷已独立修复，B/C 真实执行链仍待联调。此前 508 项测试和覆盖率没有检出这些问题，
不能据此认定安全完备。修复未修改 A/C 源码或真实执行接口。

验收范围说明：C 目前尚不完善，不能要求 B 独立证明真实沙箱执行安全。第一项属于 B/C 接口与联调缺口；
其余三项已在 B 内通过替身或本地 fixture 独立验证和修复。阶段性代码可提交供审查，但需明确标记
待 C 联调，不能将替身验证等同于 C 的真实执行验收。

## P1：Gateway 没有消费 C 的执行入口

位置：`src/camel/gateway/gateway.py:338`（`_dispatch`）。

当前网关自行签发/消费票据，随后直接调用 `server.transport.call_tool`；没有进入 C 的
`ExecutionBroker.execute` 或 `SecureExecutionPipeline`，也没有校验 `SandboxProfile`。
票据验证证明调用已授权，不能证明实际 IO 落在沙箱范围。

已复现：临时工作区配置「根只读、scratch 可写」；C 的 `resolve_write` 拒绝根下 scratch 以外的文件，
同一路径经 Gateway + fs/write + 模拟上游却成功写入。模拟工具只写临时文件，没有访问真实私人文件。

这是接口及执行边界缺口，不能仅在 handoff 中写“部署方负责”就视为满足 arch.md §6.9。
修正方向：B 产出完整效果/规范参数；C 的受控执行入口验证并消费票据、执行一次 RPC。
C 尚不支持某种 RPC/效果时，应拒绝真实执行；不能由 B 自动改走原始 transport。
具体 RPC 输入、批量效果的原子授权和返回格式需要先写入公共契约，由 C 对齐后再实现。

## P1：组合 MCP 效果缺失跨效果标签传播

修复状态：已修复。收集整次 RPC 的 READ 输入引用，保守传播到全部效果；SECRET/PUBLIC 与两种效果顺序回归通过。

位置：`src/camel/normalization/normalizer.py:82`。

`EffectSpec(READ, resource_fields=("path",))` 为 READ 加上文件 SECRET 标签；同次调用的
`EffectSpec(EGRESS, destination_field="to")` 没有继承该引用。A 的 IFC 只能看到 EGRESS 自己的
`data_refs`，因此无法阻断「读取秘密文件并发送」这个单次工具调用。

已复现（只记录上游次数，不进行外发）：

```text
COMPOSITE_READ_EGRESS {"decisions": ["ALLOW", "ALLOW"], "upstream_calls": 1, "returned": true}
```

修正方向：缺少更精确数据流声明时，保守地将整次 RPC 的文件输入引用传播到其全部外发效果；
保持 A 的模型和 IFC API 不变。增加「组合效果 + Gateway + 零上游调用」回归，不能只测单个 READ 的标签。

## P1：敏感 URL 进入审计明文

修复状态：已修复。完整 decision payload 经 Fernet 认证加密并绑定事件；公开效果只保留摘要，原因只保留代码。
可信恢复入口重建原始效果后可用原策略引擎重放；错误密钥、事件错配、摘要篡改及未知格式均拒绝。
SQL、报告、ALLOW/CONFIRM/DENY（含确认后重新裁决）路径有专项回归。

位置：`src/camel/gateway/gateway.py:230`，调用 C 的 `decision_payload`。

网关虽然为原始参数和返回值记录摘要，但完整效果中的 `destination` 仍会序列化到审计 payload。
当 URL query/path 中包含令牌或其他秘密时，即使 URL 参数被明确标为 SECRET、调用被 IFC 拒绝，
该秘密仍进入审计明文。

已复现，标记为纯合成数据：

```text
SECRET_AUDIT {"upstream_calls": 0, "decisions": ["DENY"], "plaintext_token_in_audit": true}
```

修正方向：B/C 共同约定可重放的受控载荷引用与脱敏展示。不能简单删除效果字段或仅替换 destination，
否则会破坏效果重放、合同匹配和票据摘要的一致性。至少要验证 SQLite、报告及异常路径均不含合成秘密。

## P1：stdio 身份拒绝发生在进程启动之后

修复状态：已修复此启动顺序缺陷。连接前必须提供部署批准的进程 expected_identity，比较成功才进入 stdio_client。
脚本被替换时验证启动函数未被调用。初始化后的 serverInfo/manifest 校验保留；真实 OS 隔离及 TOCTOU 仍待 C。

位置：`src/camel/gateway/transports.py:123`（`connect_stdio`）。

`connect_stdio` 计算本地身份后直接启动进程并 initialize，预期身份只在之后的 `register` 比较。
因此 register 的身份拒绝不能阻止未批准/已变化的本地脚本产生启动副作用。

使用已审阅的本地 fixture，仅在临时目录写启动标记，已复现：

```text
STDIO_PIN_ORDER {'registration_error': 'server_identity_mismatch', 'startup_side_effect_before_rejection': True}
```

修正方向：启动前验证部署批准的本地进程/脚本 pin；启动仍必须在 C 的进程隔离内。
初始化后再验证 serverInfo/工具 manifest。启动前文件摘要不等同于消除了脚本及依赖的并发替换风险。

## 对第二条协作要求的具体判断

共享模型从 A 导入，现有函数签名未被修改，这是兼容的部分。但“未改签名”不等于“端到端职责一致”：
本次新增的 B 侧确认、签票和执行桥接绕开了既有 C 执行入口。最需要先对齐的是 RPC 执行契约，
其次是敏感载荷如何在脱敏与可重放之间保持一致。当前旧主入口也尚未改线，不能声称系统已实现完整中介。
