# D 实验成果、本地验收与剩余工作

更新日期：2026-10-15。当前已完成 D 自有离线模块、固定数据对照与工程运行设施；完整系统联调和真实模型 Agent 评测尚未完成。

## 已交付内容

| 内容 | 结果与范围 |
|---|---|
| 场景与评测器 | 24 对、48 例固定语料，保留 Dev/Validation/Test 边界与已知 Test 访问事实 |
| 规划器 | 合同编译、受限 IR/TDG、数据槽绑定；两个只读模板，B 规范化仍为夹具 |
| 检测与解析 | 固定规则、来源定位、受限解析；保留 6 FP / 3 FN。网关对照已完成，新增层不默认上线 |
| Memory Gate | SQLite、来源与标签继承、宿主写入绑定、TTL、隔离和完整性检查 |
| 消融与鲁棒性 | 8 组缓存检测组合、记忆开关；384 条表示变体，保留零宽/空白拆分/Base64 漏检 |
| 运行与复现 | 统一离线入口、基准预检、错误/未知结果适配器、预算与期限控制、D 串联流程及固定子进程 |

## 本轮统一验收

推送前本地版本（基于 bbd2a45，含 D 未提交成果）在 Windows 和 WSL 各 **622 项 D 专项及共享核心/策略测试通过**，0 失败、错误、跳过。两个平台均重新执行 D2、D3a、D4、表示变体与缓存消融，统一入口状态均为 PASS_OFFLINE_COMPONENTS。此次只读使用旧缓存，没有新增模型请求或下载。

原始记录为 `artifacts/d/D_closeout_windows_01/receipt.json`、`artifacts/d/D_closeout_linux_01/receipt.json`。这些是合并前结果；远端 dev 新增了 A/C 安全修复 64a9712，提交前需保留双方历史并合并复验。最终合并后结论将在本页更新。

统一复现命令（选新目录）：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
.\.venv\Scripts\python.exe scripts/d_offline_acceptance.py --harness-validation --with-cached-models --output artifacts/d/D_closeout_repeat_01
```

该入口不会自动安装依赖或请求模型；with-cached-models 仅重放已有 D3b/D7 缓存。最新子进程流程的独立复现见 [流程子进程报告](D_flow_process.md)。原始日志、缓存和快照位于 Git 忽略的 artifacts/d，不包含在源码推送中。

## 保留的失败与缺口

- D5 子链仍为 21 PASS / 1 严格 FAIL：完成审计失败前 WRITE 可能已发生，保留未决意图，不自动重试。本轮不将其改为通过。
- 固定规则仍有误报与漏报；良性引用误隔离、零宽文本漏检均保留。通过工程控制不等于达到安全质量阈值。
- D6 正式模型 Agent 回合为 0，ASR 与任务效用尚无正式结果。D3b 的既有网关对照不是 D6，其原授权生成预算已耗尽。
- B 的生产规范化/Gateway/MCP、C 的完整执行隔离、可信入口与 observer、真实各角色预算仍待接入。没有 OS 隔离、原子刷新并执行或完整生产审计链的验收结论。
- D7 的独立泛化、自适应与扩展基准，以及完整 D8 交付仍未完成。

此前各阶段报告和证据保持原样；本页用于当前收口状态，详细历史见 [接口缺口](interface_gaps.md)与[总计划](../D_EXPERIMENT_PLAN.md)。不改动用户的独立方案文件 docs/TECH_SCHEME_OVERVIEW.md。
