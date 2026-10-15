# D 自有模块的离线复现入口

日期：2026-10-15。本文件整理 D 的本地验收、组件演示与交付边界，属于 **D8 的部分准备**；不表示 D5–D8 整体完成。当前源码尚未提交，单独检出 HEAD `bbd2a45` 不包含这些实现，需保留当前工作区源码、fixtures 和所列协议文件。

## 一条命令运行

Windows 项目根目录，使用已有环境，输出目录必须不存在：

```powershell
.\.venv\Scripts\python.exe scripts/d_offline_acceptance.py --harness-validation --output artifacts/d/D_offline_repeat_01
```

入口自行设置子进程的源码路径、UTF-8、禁写 pyc 和 pytest 插件自动加载关闭，无需激活环境。默认不读取模型响应缓存，不需要 API key；不安装依赖，不调用模型。依次运行：

1. D 自有 planner/detection/memory/evaluation 与共享 core/policy 单元测试。
2. D2 两个只读模板、固定候选与 16 个工程控制。
3. D3a 冻结规则回放与 10 类实际 mock 解析子进程控制。
4. D4 真实 SQLite Memory Gate、跨会话重开及现有本地审计 API 校验。
5. 原文及 7 类表示变换，共 384 条已知种子派生观察。

若本地保留了原 D3b 缓存，可显式加入缓存校验和组件消融：

```powershell
.\.venv\Scripts\python.exe scripts/d_offline_acceptance.py --harness-validation --with-cached-models --output artifacts/d/D_offline_cached_repeat_01
```

缓存路径为 `artifacts/d/D3b_20261015_gateway_01/v2/`，并保留其上级 `request_budget.json`。可选步骤仅回放原响应，原调用额度已经用满，入口不构造新模型请求。缓存缺失时可用默认命令；不会自动下载或补问。

WSL/Linux 使用已有可运行的项目 Python。以下是本机已验证的环境路径，并非通用安装路径：

```powershell
wsl -d Ubuntu-24.04 --exec /home/abreeze/camelplus-d0-e5zvkxkr/camelplus-d0/.venv/bin/python /mnt/d/Project/Camelplus/camelplus/scripts/d_offline_acceptance.py --harness-validation --output /mnt/d/Project/Camelplus/camelplus/artifacts/d/D_offline_linux_repeat_01
```

依赖须已在本地安装：Python >=3.10、项目依赖、pytest 以及可在 PATH 找到的 Git。Git 仅用于既有回放脚本读取版本/差异。Windows 本轮使用 Python 3.10.12、pytest 8.3.5、Pydantic 2.11.5、PyYAML 6.0.2、SQLite 3.42.0；Linux 实测版本与结果见 [验收证据](evidence/D_offline_workflow_acceptance.json)。依赖声明与版本锁位于项目根目录的 pyproject.toml、uv.lock。这里没有新机器离线安装包或 OS 部署验收；硬件性能记录见 [组件成本报告](D_component_cost.md)。

## 如何阅读输出

`receipt.json` 给出整体状态、各步命令/退出码/耗时、日志位置、测试分组、输入是否改变和输出摘要。只有全部步骤及观察校验通过时才为 `PASS_OFFLINE_COMPONENTS`。这是工程协议通过，不是检测质量达到目标。`freeze.json` 记录当前工作区源文件、fixtures、协议和所选缓存的 SHA256；它是输入清单，不是源码备份。

`demo.json` 是六个独立组件案例的索引，包含原始观察和证据位置：

| 案例 | 观察与范围 |
|---|---|
| 正常文档读取 | D2 的只读候选 READY、1 条替身效果记录 |
| review 追加未注册 push | D2 IR 为 INVALID，账本为空；这是模板入口限制 |
| 网页间接注入 | D3a 命中，A 的裁决为 DENY，记录工具未调用 |
| review 的 push 候选 | 另一固定候选中 A 为 CONFIRM，账本为空；未请求真实 C/UI 确认 |
| 正常跨会话记忆 | D4 写入后重开数据库，原文与标签一致，良性完成 |
| 过期记忆与来源链 | D4 检索拒绝，账本为空；验证本地 Memory 审计父边与链摘要 |

这些案例未串成一个运行中的 Agent。两项 review 示例的入口和合同不同，不能把 IR 拒绝与 A 的 CONFIRM 当成同一调用的前后状态。Memory 父边不是完整 MCP/子 Agent 端到端 DAG；D2 的规范效果仍是 B fixture，工具账本是唯一模拟效果。Memory Gate 的 SQLite 存取是真实本地 I/O，测试内容与密钥均为明确虚构夹具。

原始结果分别位于 planner、detector、memory、representation 子目录；可选组另有 cached_ablation。分类 FP/FN、范围外用例和生命周期 BLOCKED 独立记录：D2 为 28 个适配例通过、20 个范围外；D3a 保留 6 FP / 3 FN 和原 4 个生命周期 BLOCKED；D4 在自己的新适配器中补齐这些生命周期场景。不能在不同分母间直接比较性能增益。

每步上限 180 秒，总流程上限 600 秒，无自动重试。子进程非零退出、超时、测试缺组/失败/跳过、预期观察缺失、输入摘要变化均不能得到 PASS。失败后查看 receipt 和对应日志，使用新输出目录重跑，已有证据不覆盖。各回放脚本保留自身的网络检查；本入口不是 OS 沙箱证明。

## 本轮验证与仍待完成的工作

正式输出为 `artifacts/d/D_workflow_windows_02/`（含缓存可选步骤）与 `artifacts/d/D_workflow_linux_02/`（默认不依赖模型缓存）。首轮 `_01` 漏传 D3a 必填的 `--rule-freeze` 参数，已保存 FAILED receipt；本轮只修复新入口的参数传递，原 D2/D3/D4/D7 生产与回放实现均未改变。

新增 12 项入口测试覆盖子进程失败/超时/缺程序、已有证据保护、目录越界、测试缺组及失败/跳过、重复案例。Windows 与 WSL/Linux 的专项测试均为 **462 通过，0 失败/错误/跳过**，其中包括这 12 项。分组为 core 62、policy 42、planner 64、detection 116、memory 60、evaluation 118。专项集合不等于 A/B/C 全部测试，本轮未重跑或冒称 Windows/Linux 全套验收。

两平台的 planner 观察/控制、detector 观察/控制、memory 观察、representation 观察/配对差值及 demo，共 8 个 JSON 文件解析值完全相同；原始字节不同仅因 CRLF/LF，未声称跨平台逐字节一致。两平台冻结的 160 份输入文件摘要相同且运行后未变；Windows 校验 61 份缓存文件，Linux 默认仅校验本地已有的预算文件，不依赖响应缓存。A/B/C 的 25 个快照文件仍与 D5 Linux 包相同，前轮 D7 的 19 份证据摘要仍匹配。

Linux 同样使用 Python 3.10.12、Pydantic 2.11.5、PyYAML 6.0.2。Ruff check/format 全项目通过（156 文件），Pyright 为 0 errors / warnings / informations。完整命令、专项总数与冻结校验见 [验收证据](evidence/D_offline_workflow_acceptance.json)。

| 能力 | 当前可交付内容 | 仍缺少 |
|---|---|---|
| 计划、合同、TDG | 两个只读模板及固定效果校验 | 通用 LLM 规划、可信入口身份和 B 实际规范化接入 |
| 隔离解析、检测 | 有界 mock provider、固定规则、已授权缓存对照与负结果 | OS 隔离、真实入口替换、完整 Task verifier、新留出泛化 |
| Memory Gate | SQLite、来源/TTL/检疫/标签与本地事件链 | 生产主体绑定、整链数据流、正文保护及 OS 边界 |
| 集成 | 保留现有 D5 子链报告 | B Gateway/MCP、C 旁路隔离与完成审计故障缺陷 |
| 评测 | 已知固定样本回放、消融、表示变换、组件成本 | 在线 AgentDojo/ASB/MSB、自适应搜索与独立新样本 |
| 交付 | 当前源码、协议、单命令验收及六例索引 | 完整部署/整体演示验收、用户指定时的 Git 提交与上传 |

本轮不修改 B/C，不新增模型调用，不暂存、提交或推送 Git。后续集成待 B 就绪再调整；完整 D8 仍保持未完成。
