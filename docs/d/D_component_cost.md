# D 自有组件的离线性能实验

2026-10-15：按用户最新要求，先专注 D 模块与离线实验，B 完成后再调整集成。当前不扩展 C 的核查工具，不实现 B 的 Gateway，不启动 D6 的真实 Agent 或完整 D7 消融。

本轮完成合同编译、计划校验、固定规则检测和 Memory Gate 检索的局部耗时测量。状态 PASS 表示计时协议、结果校验与原始记录完整；不代表完整系统的性能或安全目标已达成。

## 实际结果

正式运行 `artifacts/d/D_component_cost_linux_02/`，WSL2 Ubuntu / Linux 6.18.54.1，Python 3.10.12，Intel Core Ultra X7 358H，16 个逻辑 CPU，WSL 可见内存约 15.4 GiB。记忆数据库位于 Linux 原生目录 `/home/abreeze/camelplus-d5-h62jdr9t/d_component_cost_02/`。pydantic 2.11.5、PyYAML 6.0.2，具体版本以 summary.json 为准。

每项预热 100 次、计时 1000 次；P50/P95 使用最近秩分位数，无异常值删除。正式测量没有与本轮 pytest/Pyright 并行，未绑核，未控制宿主其他进程和 CPU 频率。结果描述本机这一次运行，不据此比较不同机器或推断显著性。

| D 组件 | 输入范围 | P50（毫秒） | P95（毫秒） | 包含 I/O |
|---|---|---:|---:|---|
| 合同编译 | 2 个既有只读模板，各 500 次 | 0.069 | 0.151 | 否 |
| 计划校验 | 2 个单节点/单来源/单效果计划，各 500 次 | 0.268 | 0.534 | 否 |
| 固定规则检测 | 原冻结 48 例，每例 20 或 21 次 | 0.026 | 0.089 | 否 |
| 记忆检索 | 根记录与两级祖先记录，各 500 次 | 23.813 | 30.185 | 是 |

计划校验包含合同重编译核对、TDG/标签/指纹校验及真实 A 策略调用；B 的 fixture 效果提前准备，不计规范化成本。该项与单独合同编译存在工作重叠，不能把两行直接相加得到生产链路时延。

固定规则使用原 D3a 版本和原 48 例文字，来源标签按既有父链继承；identity view 构造在计时外。未使用 Test 选择阈值或修改规则，原 6 FP / 3 FN 结论保持不变。此处只测规则函数，不能替代规则+IFC、模型分类或完整输入链路的指标。

记忆测试只预置 3 条良性记录，测正常可读路径；包含 SQLite 读取、HMAC 验证、TTL/ACL/祖先检查和 read 事件提交，初始化及种子写入不计时。最终 1104 条已验证事件 = 1 条来源 + 3 条写入 + 100 次预热读 + 1000 次计时读。30.185 毫秒描述这组含落盘的局部调用，不证明具体哪一内部步骤占主导；尚未测大库、深链、异常路径或并发负载。

## 计时与结果约束

- 使用 perf_counter_ns；时钟调用和函数调用的微小开销未扣除。
- 输入选择、结果验证、结果序列化/哈希、汇总和文件写出均在计时外。规则视图、计划 fixture 及记忆种子预先准备。
- 4000 条测量全部保存，另外执行 400 次预热；4400 次调用均通过结果检查。重复输入的完整返回值哈希一致，错误会使实验退出，不静默删除样本。
- 1000 次重复不是 1000 个独立任务或攻击样本，不计算 ASR、泛化优势或任务完成率，也不把重复次数用于显著性结论。
- Windows `_windows_01`、Linux `_linux_01` 是功能预跑，其中存在与检查任务并行的阶段，仅保留诊断，不用于本表或跨平台性能比较。正式结果只采用 `_linux_02`。

## 复现

本地可直接运行，无需密钥、模型或外部连接，输出目录须为新的 artifacts/d 子目录：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
& '.\.venv\Scripts\python.exe' scripts/d_component_cost.py --output artifacts/d/D_component_cost_repeat_01
```

在现有 WSL 环境复现正式范围：

```powershell
wsl -d Ubuntu-24.04 --exec /usr/bin/env PYTHONPATH=/mnt/d/Project/Camelplus/camelplus/src PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 /home/abreeze/camelplus-d0-e5zvkxkr/camelplus-d0/.venv/bin/python /mnt/d/Project/Camelplus/camelplus/scripts/d_component_cost.py --output /mnt/d/Project/Camelplus/camelplus/artifacts/d/D_component_cost_repeat_02 --storage-root /home/abreeze/camelplus-d5-h62jdr9t/d_component_cost_repeat_02
```

源码从 Windows 项目读取，导入、载入与输入准备不计时；SQLite 文件在 Linux 原生目录。不要把数据库放到 /mnt/d 后称为相同存储条件。正式计时前先结束本轮回归检查，不同时运行另一个实验；后续耗时变化须另存结果，不覆盖原始记录。

## 工程检查与后续边界

新增 11 项计时协议测试在 Windows、Linux 均通过，覆盖预热/验证的计时边界、错误与输出变化拒绝、最近秩及异常值保留。Windows 全套 667 通过、6 个原有平台失败，Ruff/Pyright 通过。当前 Linux 仅新增协议测试及性能入口已运行；上一快照的 662 项 Linux 全套通过记录保持原范围，不升级为本轮 673 项全套通过。

原 D1 样本/划分/真值、D3 规则和既有模型缓存未修改，模型调用 0、下载 0、Git 提交 0。本轮只新增 D 的评测入口、计时工具、测试和报告；A/B/C 生产代码与此前 Linux 验收快照一致。

后续优先继续 D 自有组件的离线消融或成本分解；B 接口、C 的隔离与完整系统性能暂列待联调，不在本轮扩展。D5 的 21 PASS / 1 严格故障 FAIL 保留，正式 D6/D7 仍未启动。紧凑证据见 [D_component_cost.json](evidence/D_component_cost.json)。
