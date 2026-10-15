# D0 基线与接口核验

- 状态：**PASS**。本轮安全/输入修复已在原生 Linux 文件系统完成完整验收。
- 正式运行：D0_linux_20261015T033310Z，2026-10-15 11:33:11–11:33:50（Asia/Shanghai），验收约 39 秒。
- 含环境准备的用户终端运行约 11 分 25 秒；准备耗时与测试耗时分列。
- 基线提交：de78b715ebc0b90584b3a9b21fff15325b718e14；交付分支 codex/d0-baseline。
- 用户已授权跨模块本地修复，验收后一次上传。本阶段不包含 D1–D8。

## 验收结果

| 检查 | 通过 | 失败 | 错误 | 跳过 |
|---|---:|---:|---:|---:|
| Linux 完整 pytest，无排除 | 320 | 0 | 0 | 0 |
| 其中核心/策略 pytest（也独立运行） | 104 | 0 | 0 | 0 |
| 其中 D0 边界探针 | 21 | 0 | 0 | 0 |
| 其中下载故障回归 | 8 | 0 | 0 | 0 |

上述子集及独立复验不能累加为额外独立实验。D0 unittest 独立复验 21 项通过。所有 8 个正式检查命令退出 0；ruff check、ruff format --check、pyright 全部通过，pyright 为 0 errors / 0 warnings。AST 检查 105 个 Python 文件无语法错误，Ruff 格式检查覆盖 105 个文件。

实测平台为 Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39；Python 3.10.12 与 .python-version 一致，uv 0.13.1，项目专用 Node v24.22.0。uv 冻结同步的 214 个包均匹配 uv.lock；Pydantic 2.11.5、pytest 8.3.5、ruff 0.11.12、pyright 1.1.401、AgentDojo 0.1.34。uv 是独立工具，不计入项目安装包集合。

在 Linux 用户主目录的新目录解压并运行，已实际验证文件权限 0600、符号链接及 O_NOFOLLOW 拒绝跟随链接。正式运行没有使用 /mnt/d 验收文件权限，结果通过挂载目录回传 Windows。没有模型调用或外部攻击基准。

## 修复与语义边界

1. Composer：硬 DENY 优先；确定性确认原因保留确认路径；仅风险信号不能从默认 DENY 创造确认授权。
2. 子合同：效果类型始终受父类型约束，非空 ceiling 进一步收窄；操作和资源必须同时由同一父条目覆盖。相同 glob、全局父 pattern、具体子值命中父 glob 可证明包含；其他复杂 glob 子集保守拒绝，会拒绝部分合法收窄。
3. RiskSignal、IntentContract、AllowedEffect、DelegationSpec 拒绝未知字段；置信度只接受有限数字 [0,1]，拒绝字符串和布尔转换；预算、委派深度要求非负严格整数。保持 v1 字段布局，但输入校验变严。
4. WRITE 在消费票据前验证有效 O_NOFOLLOW；缺失时明确拒绝、审计 rejected，不消费票据或创建文件；保留 POSIX 写标志和 0600 要求。
5. 集成 fixture 使用 JSON 字符串转义嵌入 YAML，合同/策略复用平台一致的资源 pattern。旧断言没有为通过而放宽。
6. 新增 11 项权限范围回归、22 项输出边界回归、1 项缺失平台原语回归；原 21 项 D0 探针中的 9 项失败已转通过。
7. Linux 准备入口增加长度与 SHA256 检查、最多三次重试、下载诊断和验证缓存复用，另有 8 项故障回归。

真实 PolicyEngine 观察：无显式允许加高风险仍为 DENY；过期合同为 DENY。空规则策略版本为 sha256:a1c53591629fdf4f；重放还需匹配代码版本。5 个公共模型加 RiskSignal 的字段和 Schema 均已导出。Schema 合法本身不证明来源可信或授权合法。

## Windows 结果与环境故障

保留历史 Windows 运行 D0_20261015_applied_02：完整 312 项中 306 通过、6 失败、0 错误、0 跳过；当时尚未加入 8 项下载回归，因此总数与当前 Linux 不同。核心/策略 104 项、独立 D0 探针 21 项及规范/类型检查通过，安装包 213 个。

| Windows 原有失败 | 原因 | 当前 Linux |
|---|---|---|
| test_write_executes_with_private_permissions | 缺 POSIX O_NOFOLLOW | 通过 |
| test_vault_write_also_gets_handle | 同上 | 通过 |
| test_confirm_branch_requires_user_approval | 确认后的 POSIX WRITE 不支持 | 通过 |
| test_audit_context_threaded_into_all_payloads | 同上 | 通过 |
| test_symlink_escape_rejected | 创建链接时 WinError 1314 | 通过 |
| test_to_path_strips_scheme | POSIX 绝对路径语义 | 通过 |

Windows 失败没有被删除、跳过或改写为通过；用户选择 Linux/WSL/容器执行后，完整平台门禁以本次 Linux 实测为准。D0 PASS 不表示 Windows 支持安全 WRITE。

Codex 进程启动 WSL 仍返回 Wsl/E_ACCESSDENIED；用户普通 PowerShell 可启动 Ubuntu-24.04，使用本地启动器完成了验收，没有安装服务或修改系统配置。第一次用户终端准备运行 D0_wsl_return_20261015T031405Z 因 uv SHA256 不符退出 2，未进入测试；原失败文件大小和实际哈希未记录，根因未定。Windows 独立下载同文件后，长度 17,279,385、SHA256 均匹配 PyPI 元数据；缓存经再次校验后用于当前成功运行。这些历史故障不计为测试失败，也不被覆盖成成功记录。

## 版本与可复现证据

- 完整原始回传：artifacts/d/D0_wsl_return_20261015T032226Z/，含 receipt.json、launcher.txt、下载诊断和正式运行目录。
- 正式目录：上述目录内 D0_linux_20261015T033310Z/，含 run.json、两个 JUnit、全部检查日志、installed_packages.json、Schema、source_manifest.json、working_tree.patch 和源码快照。
- 源码包：D0_linux_source_04.tar.gz，SHA256 为 cfb42e902de714ad1e3d30b65be770a830d75561401c1023f3fe809754beb1b4。
- 已独立核验包内 117 个源码/配置文件与报告更新前的工作区逐字节一致；两个运行器/探针源码快照匹配，包哈希与回传 receipt 一致。
- Linux 使用源码包，不含 .git；run.json 如实记录 git_checks_run=false。不能将源码包验收写成 Linux Git checkout 验收。
- 可随源码提交的紧凑证据：[evidence/D0_linux_acceptance.json](evidence/D0_linux_acceptance.json)，包含检查结果、环境、原始文件 SHA256 和六项原 Windows 失败的通过核验。

原始 artifacts、源码压缩包、运行时、依赖缓存不提交；.gitignore 与 Ruff 排除 artifacts/d。当前交付直接更新正式源码，无第二套候选实现。source_01–03 与旧轮次保留在本地 artifacts 作为诊断历史。

重放入口与用户终端命令见 [D0_linux_acceptance.md](D0_linux_acceptance.md)。重复运行需要新输出目录；准备阶段可联网，pytest 子进程拒绝 socket/DNS/urllib 请求，此 Python 防护不是 OS 沙箱。报告整理后仅修改文档、紧凑证据及 Git 分发属性（.gitattributes 为 scripts/*.sh 固定 LF），不改变验收过的业务源码、脚本、测试、依赖或运行配置。

## 出口与后续

D0 基线可运行、原缺口有复现与修复回归、完整 Linux 门禁通过，**本阶段 PASS**。证据限 E0/E1 的固定输入与被测 WSL2 环境，不构成真实模型抗注入能力、ASR 或 OS 旁路不可绕过性的结论。

下一阶段为 D1：冻结攻击/良性配对、族级划分及真值，建立离线评测器；本轮没有启动 D1。pipeline 风险信号透传、B normalization/gateway 和 OS 旁路隔离仍按后续阶段推进，详见 [interface_gaps.md](interface_gaps.md)。
