# D0 修复实施记录

状态：**已应用到正式源码，完整 Linux D0 验收 PASS**。

用户于 2026-10-15 明确要求不再受协作审批限制，在本地验收完成后统一上传。之前的 A/C 候选已按该授权应用，随后完成严格输入及平台失败处理。本阶段验收已完成，按授权统一提交到 codex/d0-baseline 分支。

## 实施范围

- src/camel/core/decision.py：风险信号不能把默认 DENY 改为 CONFIRM；确定性确认路径保留。
- src/camel/core/contract.py：父子类型与资源/操作范围约束；未知字段拒绝；预算/深度严格非负整数。
- src/camel/broker/executor.py：无 O_NOFOLLOW 时在授权消费/IO 前拒绝并审计，保留 POSIX 写安全标志。
- tests/integration/test_secure_pipeline.py：正确序列化 YAML 字符串，合同与策略复用一致的资源 pattern。
- tests/unit/core/test_d0_scope_regression.py：已应用的 11 项候选回归。
- tests/unit/core/test_output_validation.py：22 项数值、类型、嵌套字段与 Schema 回归。
- tests/unit/broker/test_platform.py：缺失安全原语时，零文件效果、票据未消费且审计可验证。
- docs/interface_contract.md：同步实际公共语义；模型保留 v1 字段布局，输入校验收紧。

当前 Linux 复验：完整 320 通过 / 0 失败 / 0 错误 / 0 跳过，核心/策略 104 通过；其中 D0 边界探针 21 项、下载回归 8 项。lint/format/pyright 均通过。历史 Windows 完整结果仍为 306 通过 / 6 平台失败。详见 [D0_baseline.md](D0_baseline.md)。

## 语义选择与限制

- 显式确定性确认原因仍可进入确认；单独风险分数不能产生授权路径。
- 空 child_ceiling 不增加额外限制，但始终受父效果类型限制。
- 复杂 glob 只采用保守包含证明；无法证明的合法收窄也可能被拒绝。11 项回归包含该效用代价和跨父条目拼接反例。
- Schema 合法不是可信来源或用户授权证明；本轮没有宣称全部委派/系统不变量已被穷尽验证。
- 不支持的 Windows 写入明确拒绝；没有新增弱化后端或改旧预期。原生 Linux 上原有六项平台失败均已实测通过。

## 证据与后续

历史候选证据保存在 artifacts/d/D0_20261015_proposals_02/，含两个原始 patch、runner.py.txt、隔离源码和 JUnit。原候选脚本/重复补丁/测试文本已从当前源码交付移除，避免维护第二套实现。当前回归直接测试正式代码。

最新正式证据：artifacts/d/D0_wsl_return_20261015T032226Z/D0_linux_20261015T033310Z/；紧凑验证记录见 evidence/D0_linux_acceptance.json。Linux 入口与源码包见 [D0_linux_acceptance.md](D0_linux_acceptance.md)。Codex 直接启动受限，由用户普通终端完成本次真实验收。

完整本地门禁已通过，本轮统一提交/上传；D1–D8 未启动。
