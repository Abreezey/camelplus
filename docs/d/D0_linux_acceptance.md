# D0 原生 Linux 验收入口

状态：**Linux 完整验收 PASS**。用户普通 PowerShell 已运行 source_04：320 项测试通过，0 失败/错误/跳过，全部规范和类型检查通过。Codex 直接启动 WSL 仍受访问限制，用户终端入口可重放。

用户已选择 Linux/WSL/容器承担真实执行，Windows 保留 D 的离线验证。以下入口只执行 D0，没有模型、API、训练或攻击基准。

## 用户终端重放入口

用户已在普通 PowerShell 成功执行 wsl --list --verbose，确认 Ubuntu-24.04 为 Stopped、WSL2。Codex 获准提权后的启动仍返回 Wsl/E_ACCESSDENIED；这提示上下文访问差异，不能据此证明发行版损坏。

在用户自己打开的 PowerShell 执行以下一条命令，路径不依赖当前工作目录：

```powershell
wsl -d Ubuntu-24.04 --exec python3 /mnt/d/Project/Camelplus/camelplus/scripts/d0_wsl_acceptance.py
```

该本地入口使用 D0_linux_source_04.tar.gz，在 Linux 用户主目录创建全新的 camelplus-d0-* 目录；只在此目录下载/准备 uv 0.13.1、Python 3.10.12 和冻结依赖。优先复用已有 Node；缺少时在该目录下载官方 Node v24.22.0 LTS 二进制并核对官方 SHA256，不安装全局 Node、不修改服务、shell 配置或旧 Conda 环境。uv wheel 同样核对 PyPI SHA256；元数据来源为 [PyPI uv 0.13.1](https://pypi.org/pypi/uv/0.13.1/json) 与 [Node 官方发布索引](https://nodejs.org/dist/index.json)。

准备阶段需要联网，耗时单列；随后完整 D0 仍使用测试进程禁网规则。入口实时显示验收输出；完成或失败后将 receipt.json、launcher.txt 和正式结果复制回 Windows 的 artifacts/d/D0_wsl_return_<UTC>/。不复制运行时或 pytest 临时目录；保留 Linux 工作目录以便诊断。主机入口通过静态及合成路径校验不代表 Linux 验收已通过。

首次用户终端运行 D0_wsl_return_20261015T031405Z 已进入 Linux，但 uv wheel 的 SHA256 不符，准备阶段退出 2，尚未启动 pytest。原入口未记录失败文件大小和实际哈希，暂不能断言是传输截断还是内容损坏。Windows 随后独立下载同一官方文件：17,279,385 字节、SHA256 为 696dcf6d807d85da978f4db8472da81dccc1254b18b52cbd1367c4d923c421e0，与 PyPI 元数据一致；耗时约 113 秒，原始记录见 artifacts/d/D0_bootstrap_download_check/result.json。

当前入口优先读取 Windows 项目的 artifacts/d/.bootstrap_cache/，仅复用哈希及长度匹配的文件，并在复制到 Linux 后再次核对哈希；本次已放入验证成功的 uv Linux wheel。网络下载同时检查 PyPI 文件长度、HTTP Content-Length 与 SHA256，最多三次重试；失败的 .part 文件及 downloads.jsonl 保留，校验未通过的文件不发布为目标文件。下载诊断会随结果回传。未删除或放宽完整测试。

离线故障回归 tests/unit/d0/test_download.py 共 8 项通过（artifacts/d/D0_download_regression_02.xml）；覆盖截断、同长度损坏、持续损坏、可信缓存、损坏缓存、HTTP 长度不符、断连及禁止覆盖。初次使用沙箱默认临时目录的 4 项 rename 权限失败单列在 _regression.xml；将 pytest 临时目录设为项目 artifacts/d 后原断言全通过。此回归结果不替代 Linux 全套验收。

## 执行位置与前提

将本轮源码包解压到可写的 **Linux 原生文件系统**，例如当前 Linux 用户主目录下的新项目目录。不要直接在 /mnt/d 的 Windows 挂载目录验收 POSIX 私有权限，也不要把 Windows 的 .venv 复制到 Linux。

容器可使用相同入口，但需要在容器原生文件系统解压源码；执行结果只证明容器内被测行为，不能替代 C 的宿主 Agent 旁路隔离验收。

依赖前提：可启动的 Linux、python3、uv 0.13.1、Node.js。验收使用 Python 3.10.12，uv.lock 按 Linux 平台选择依赖，包数可能不同于 Windows 的 213。完整安装版本必须随 run.json / installed_packages.json 返回。

如果只有 python3/pip，可以在解压后的项目目录将 uv 放入项目生成目录：

```sh
python3 -m pip --isolated install --no-deps --only-binary=:all: --no-cache-dir \
  --target artifacts/d/.tools uv==0.13.1
export D0_UV="$PWD/artifacts/d/.tools/bin/uv"
```

不在入口中安装 WSL、Docker、系统服务或全局 Node。缺少这些前提时，保留错误并记录 BLOCKED。

## 验收命令

工具、Python 和依赖缓存齐备时，默认离线：

```sh
sh scripts/d0_linux.sh
```

首次准备项目依赖时可显式选择联网准备；只下载 Python 与锁定项目/dev 包：

```sh
sh scripts/d0_linux.sh --prepare-online
```

两者均先使用独立临时目录检查：创建文件能否保持 0600、是否支持符号链接、O_NOFOLLOW 是否拒绝打开链接。随后同步项目专用 .venv，运行完整 D0；不删除安全标志，不跳过既有测试。临时探针只操作虚构文件并自动清理。

正式入口是 scripts/d0_baseline.py，执行核心/策略 pytest、无排除的全套 pytest、ruff check、ruff format --check、pyright、字段/Schema 导出及 D0 探针。pytest 子进程禁止网络连接尝试；环境准备的联网与测试阶段分开。单项检查最多 120 秒，预计 smoke 总量低于 10 分钟。

## 源码版本与证据

Windows 制包命令（输出路径必须在 artifacts/d 内，且不能覆盖旧包）：

```powershell
& '.\.venv\Scripts\python.exe' scripts/d0_make_linux_bundle.py --output artifacts/d/D0_linux_source_01.tar.gz
```

包内包括当前 src/tests/scripts、锁文件和必要配置；排除 .env、.git、解释器、缓存、已生成结果及模型。source_manifest.json 标明基线提交、包内文件列表和本地差异，working_tree.patch 保留受跟踪改动；新文件直接包含在源码包中。

源码包没有 .git，运行器会明确记录 source_bundle 与 git_checks_run=false，并复制源码 manifest/差异到结果目录，**不会伪造 Git 检查通过**。在真实 Git checkout 中仍执行实际 Git 检查。

Ruff 配置显式排除 artifacts/d，避免源包脱离 Git 后检查下载的第三方运行时/缓存；原 src/tests 仍完整纳入。配置依据 [Ruff extend-exclude 官方文档](https://docs.astral.sh/ruff/settings/#extend-exclude)。

每轮输出到 artifacts/d/D0_linux_<UTC 时间>/。需要返回完整目录，至少包括：

- run.json、installed_packages.json；
- core_policy.xml、full_suite.xml 及对应文本日志；
- ruff_check.txt、ruff_format.txt、pyright.txt、d0_probes.txt；
- public_fields.json、public_schemas.json、source_manifest.json、working_tree.patch。

只有完整 pytest、规范/类型检查及 D0 探针均退出 0，依赖版本匹配 lock，才可记录 Linux 门禁 PASS。缺包、超时、未进入测试、设置错误、skip 均单列；零攻击成功率不是本阶段指标。

正式成功运行是 D0_linux_20261015T033310Z，完整回传位于 artifacts/d/D0_wsl_return_20261015T032226Z/。Linux 214 个包均匹配锁文件，Python 3.10.12；验收约 39 秒、含准备约 11 分 25 秒。完整测试、规范和类型检查及 D0 探针均通过，0 skip。核验报告见 [D0_baseline.md](D0_baseline.md)，紧凑证据见 [evidence/D0_linux_acceptance.json](evidence/D0_linux_acceptance.json)。本轮按用户授权统一提交源码、测试和报告；原始运行时/缓存留在本地。
