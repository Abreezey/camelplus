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

合并前 D 版本在 Windows/WSL 各 622 项 D 专项通过。随后保留本地 D 提交 5fe9cda 与远端 dev 安全修复 64a9712 的双方历史，解决资源范围收窄及测试导入冲突，完成合并后复验：

| 验收 | 合并后结果 |
|---|---|
| Windows D 专项及共享核心/策略 | 639 通过，0 失败、错误、跳过 |
| WSL D 专项及共享核心/策略 | 639 通过，0 失败、错误、跳过 |
| Linux 原生文件系统项目全套 | 909 通过，0 失败、错误、跳过 |
| D2/D3a/D4/表示变体/缓存消融 | 两平台统一入口 PASS_OFFLINE_COMPONENTS，保留原负结果 |
| D 流程子进程 | 两平台各 24 计划/21 启动并确认退出，7 条模拟 READ、1 条未决意图 |
| 原 D5 严格验收 | 21 PASS / 1 FAIL，原脚本退出码 1 保留，完整链路仍未通过 |
| 代码规范与类型 | Ruff check/format 通过，179 文件；Pyright 0 errors/warnings/informations |

Windows 全项目 POSIX 执行验收不在本轮结论内。原始记录见 `artifacts/d/D_closeout_merged_windows_01/`、`D_closeout_merged_linux_01/`、`D_closeout_full_linux.xml`、`D_closeout_D5_linux_report.json` 与两平台的 `D_closeout_merged_process_*_01/`。独立核验及紧凑结果见 [D_closeout_acceptance.json](evidence/D_closeout_acceptance.json)。本轮没有新增模型请求或下载。

统一复现命令（选新目录）：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
.\.venv\Scripts\python.exe scripts/d_offline_acceptance.py --harness-validation --output artifacts/d/D_closeout_repeat_01
.\.venv\Scripts\python.exe scripts/d_flow_process_eval.py --source-pin docs/d/evidence/D_release_source_pin.json --output artifacts/d/D_closeout_process_repeat_01
```

入口不会自动安装依赖或请求模型；具备原缓存时，可给第一个命令增加 --with-cached-models 重放 D3b/D7。合并改变了 A/C 源码，第二个命令显式采用当前已审阅基线；该基线只对 Git 的 LF/CRLF 做规范化，实际源码改变仍会拒绝。旧报告/协议/摘要不覆盖；历史版本的旧基线命令可能因当前源码变化而拒绝，这是预期检查。

Python 源码在 Git 中固定 LF，实验报告与 JSON 证据保留原始字节，D1 冻结 fixture 继续保留原始字节。原始日志、模型缓存和快照位于 Git 忽略的 artifacts/d，不包含在源码推送中；旧缓存对照需要本地缓存，不能用新 API 请求冒充原缓存。

## 保留的失败与缺口

- D5 子链本轮实测仍为 21 PASS / 1 严格 FAIL：完成审计失败前 WRITE 已发生，保留未决意图，不自动重试。909 项 pytest 不包含该未解决的严格断言；它由独立 d5_eval 运行并原样返回失败。
- 固定规则仍有误报与漏报；良性引用误隔离、零宽文本漏检均保留。通过工程控制不等于达到安全质量阈值。
- D6 正式模型 Agent 回合为 0，ASR 与任务效用尚无正式结果。D3b 的既有网关对照不是 D6，其原授权生成预算已耗尽。
- B 的生产规范化/Gateway/MCP、C 的完整执行隔离、可信入口与 observer、真实各角色预算仍待接入。没有 OS 隔离、原子刷新并执行或完整生产审计链的验收结论。
- D7 的独立泛化、自适应与扩展基准，以及完整 D8 交付仍未完成。

本次提交介绍：交付 D 的规划、检测、记忆、离线对照与运行设施，合并远端已有 A/C 安全修复并复验，保留全部已知负结果；目标分支为 dev，不作生产可用性或正式模型成绩声明。

此前各阶段报告和证据保持原样；本页用于当前收口状态，详细历史见 [接口缺口](interface_gaps.md)与[总计划](../D_EXPERIMENT_PLAN.md)。用户独立方案文件 docs/TECH_SCHEME_OVERVIEW.md 保留在本地、不纳入本次提交。
