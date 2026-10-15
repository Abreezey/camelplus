# D0 接口与环境缺口

日期：2026-10-15。基线 de78b715ebc0b90584b3a9b21fff15325b718e14，当前记录 D0_linux_20261015T033310Z。用户已授权直接本地修复，验收后统一上传。

| ID | 当前状态 | 已实施/验证结果 |
|---|---|---|
| ENV-01 | 已解决 | 项目 Python 3.10.12，冻结依赖 213 个，pytest/ruff/pyright 可运行 |
| ENV-02 | 已解决 | 测试子进程 UTF-8；旧策略 fixture 读取问题消失 |
| A-01 | 已修复，E1 | 无允许加风险保留 DENY；硬 DENY 与显式确认流程回归通过 |
| A-02/A-03 | 已修复，E1 | 子资源/操作须由同一父条目覆盖；原扩张反例转通过，具体正常收窄有对照 |
| A-04 | 已修复，E1 | 空 ceiling 下仍受父类型限制，不能 READ 扩为 WRITE |
| BOUNDARY-01 | 已修复，E1 | RiskSignal、IntentContract、AllowedEffect、DelegationSpec 拒绝未知字段 |
| BOUNDARY-02 | 已修复，E1 | 置信度字符串/布尔值、非有限与越界数值拒绝，合法 JSON 数字及 roundtrip 通过 |
| A-05 | 已修复，E1 | 预算和委派深度严格非负整数；负数/布尔/字符串/小数反例通过 |
| C-02 | 平台行为已明确，E1 | 缺 O_NOFOLLOW 则在消费票据前拒绝并审计；Windows 不是 POSIX 写验收替代品 |
| C-04 | 已修复，E1 | YAML 正确转义、合同/策略资源 pattern 一致，0 集成设置错误，Windows 正常读回归通过 |
| ENV-03/C-05 | Linux 已通过，E1 | 原六项 Windows 平台失败在 Linux 原生文件系统全部通过；Windows 历史失败保留 |
| LINUX-01 | 已解决，用户终端验收 | source_04 经用户普通终端运行：完整 320 通过、规范/类型全绿；Codex 直接启动限制仍存在，入口可重放 |
| A-06 | 后续 D3 封装 | RiskSignal 仍为四字段；失败状态和结构化证据由 D 结果封装携带，不复制公共模型 |
| D-01 | 后续 D1 | fixture loader 必须拒绝缺标签/来源；DataReference 的 DATA_ONLY 默认值不能代替完整真值 |
| C-01 | 后续集成 | pipeline.run 尚无 risk_signals 透传；需后续接入时实施并验证，当前不宣称已接通检测链 |
| C-03 | 后续 D5 | 当前 Python 路径/票据检查不证明 OS 隔离、禁网或旁路不可绕过 |
| B-01 | 后续依赖 | normalization/gateway 未就绪，D5 真实联调待接口 |

本轮原 21 项 D0 探针全部通过，9 项原失败没有删改预期。新增范围/输入/平台回归与原有核心/策略共 104 项通过。当前 Linux 完整 320 项全部通过、0 失败、0 错误、0 跳过，含 8 项下载回归。历史 Windows 312 项中 306 通过、6 平台失败；这些记录保留，不将 Windows 写成支持 POSIX 执行。

复验入口（在项目根目录，输出目录需更换）：

```powershell
& '.\.venv\Scripts\python.exe' scripts/d0_baseline.py --output artifacts/d/D0_repeat_01
```

[完整基线](D0_baseline.md)、[实施记录](D0_fix_proposal.md)、[Linux 验收入口](D0_linux_acceptance.md)。D0 整体 PASS，按用户要求在本地完整验收后统一上传；本轮不进入 D1。
