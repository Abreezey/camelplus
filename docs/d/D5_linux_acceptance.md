# D5 当前源码的 Linux 验收入口

2026-10-15 已实际完成 WSL2/Ubuntu 原生目录验收：**完整 662 测试通过、0 失败/错误/跳过，Ruff/Pyright 全通过**；214 个已安装包匹配锁文件。入口冻结当前 D2–D5 源码，复用 D0 已验收环境，没有模型调用、环境下载、全局安装或 Git 写入。完整 D5 仍为 PARTIAL_FAIL，不能把工程通过写成系统安全验收通过。

正式回传为 `artifacts/d/D5_wsl_return_20261015T091256Z/`，原生目录 `/home/abreeze/camelplus-d5-h62jdr9t/camelplus-d5`。共 158 个源码/配置文件，源码包 SHA256 为 `dab645ad1d2db8c2fd48cc08942fa05644247520d7273ec12928ad0d86665135`，总耗时约 64 秒。原 Codex 上下文的 Wsl/E_ACCESSDENIED 本轮没有复现，获准的直接启动已成功；无需根据旧错误重装 WSL。

## 执行命令

已准备的默认源码包为 `artifacts/d/D5_linux_source_01.tar.gz`。在用户自己的 PowerShell 终端执行：

```powershell
wsl -d Ubuntu-24.04 --exec python3 /mnt/d/Project/Camelplus/camelplus/scripts/d5_linux_acceptance.py
```

命令不依赖 PowerShell 当前目录，不需要再次运行 D0 下载器。默认读取已成功的 `D0_wsl_return_20261015T032226Z/receipt.json`，复用其 `/home/abreeze/camelplus-d0-e5zvkxkr/camelplus-d0/.venv/bin/python` 和回执中的 Node。运行时必须仍存在、位于该 Linux 原生目录内，并且旧项目与新快照的 uv.lock 相同。缺少前提会保留错误并退出，不自动安装或下载。

## 实际执行范围

1. 在新的原生目录安全解包，拒绝目录穿越、符号/硬链接、设备成员、重复或大小写冲突名字、未知文件与哈希不符；不包含 .env、.git、旧结果或 Windows .venv。新快照内建立到原 Linux .venv 的链接供现有 Pyright 配置定位依赖，不修改原环境。
2. 复用现有 `d0_baseline.py` 作为**当前源码**的工程检查器，运行完整 pytest、规则/类型检查、依赖锁匹配与 D0 回归。子报告内 stage=D0 是检查器名称，不表示重新使用旧的 320 项结果。当前所有新增测试均来自新源码包。
3. 新增真实 C broker 的三个 POSIX WRITE 探针：正常写入准确内容且权限 0600；执行意图写入失败时原文件不变；完成结果写入失败时原文件已改变、抛 ExecutionAuditError，重开数据库仍能查到未决意图。第三项检验可追溯性，**不能当作文件回滚或严格原子性通过**。
4. 运行 D5 原 22 个子链探针，完整保留已知的 `execution_audit_fault` 严格失败。

成功路径使用虚构文件和公开测试密钥；WRITE 探针直接使用宿主签发的规范效果/票据，只验收 C 的实际机制，不代表 B 的规范化/Gateway 或完整 A/B/C 授权链已验收。B 的两个生产模块在本轮复查中仍缺失。

## 返回结果与退出码

结果返回 Windows 项目下的 `artifacts/d/D5_wsl_return_<UTC>/`。返回回执、日志、XML、JSON 与脱敏 trace；不复制 .venv、下载缓存、数据库、测试临时目录或工具正文。Linux 原生测试目录保留，以便诊断。

- `engineering_status=PASS`：当前源码完整测试与规范/类型门禁，以及 POSIX 机制探针通过。
- 默认完整 D5 仍为 PARTIAL_FAIL，入口退出 **1**：预期 D5 21 PASS / 1 严格故障 FAIL；回执的 `only_known_strict_failure` 应为 true。
- 退出 **2**：环境缺失、哈希/锁不符、超时、工程失败或结果不完整，需查看 receipt.json / launcher_error.txt / 对应日志；不能将其当作 Linux 通过。

即使工程全绿，完整系统仍未通过 D5：B 入口、真实 MCP/网络执行、OS 旁路隔离与未决操作核查流程仍待补齐。操作系统原生文件权限通过也不能证明 Agent 无法绕过 Python 中介。

正式结果中 baseline=0、native_write=0、d5_probes=1，`engineering_status=PASS`、`only_known_strict_failure=true`。正常 WRITE 得到准确内容和 0600 权限；意图审计故障为 0 次 I/O、原文件不变；完成审计故障为 1 次 I/O、文件改变、1 条重开数据库后仍存在的未决意图。D5 22 个原探针为 21 PASS / 1 FAIL，与 Windows 的子链语义结果一致。原 6 个 Windows 平台失败在本次 Linux 快照中全部通过，未跳过。

入口新增 20 项本地测试通过，覆盖归档路径/链接/哈希/覆盖保护、运行时范围与回传过滤。当前 Windows 完整结果为 656 通过、6 个历史平台失败；Linux 正式结果为 662 全通过。紧凑证据见 [D5_linux_acceptance.json](evidence/D5_linux_acceptance.json)。

重新冻结源码时，使用新文件名，不能覆盖已有包：

```powershell
& '.\.venv\Scripts\python.exe' scripts/d5_linux_acceptance.py --prepare-bundle --bundle artifacts/d/D5_linux_source_02.tar.gz
```

随后在 WSL 命令末尾显式指定 `--bundle /mnt/d/Project/Camelplus/camelplus/artifacts/d/D5_linux_source_02.tar.gz`。包中 manifest 记录基线提交、文件哈希；tracked diff 保存为 working_tree.patch，新文件包含正文。只读 Git 查询不构成提交。
