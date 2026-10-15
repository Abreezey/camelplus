# Conda 开发环境

已安装 Miniconda/Anaconda 后，在初始化过 Conda 的终端运行：

```bash
python scripts/setup_conda.py
conda activate camelplus
python -m pytest -q
ruff check .
ruff format --check .
```

Windows 使用 Anaconda Prompt 或已执行 `conda init powershell` 的 PowerShell；Linux/macOS 使用初始化过 Conda 的终端。
脚本可从任意工作目录通过其绝对路径运行。首次创建需要下载依赖；再次运行复用 `camelplus` 并同步依赖。
已有同名环境的 Python 版本不符合 `.python-version` 时停止，不自动删除或重建环境。

`environment.yml` 只定义 Python 3.10.12、pip 和 uv 0.11.7；项目运行和开发依赖仍以 `pyproject.toml`、`uv.lock`
为唯一来源。脚本将锁定依赖安装到 Conda 环境本身，保留 Conda 管理的包，不覆盖仓库原有 `.venv`。

手动创建及同步等价命令（在仓库根目录执行）：

```bash
conda env create -f environment.yml
conda activate camelplus
```

Linux/macOS：

```bash
UV_PROJECT_ENVIRONMENT="$CONDA_PREFIX" uv sync --locked --inexact --group dev --no-python-downloads
```

PowerShell：

```powershell
$env:UV_PROJECT_ENVIRONMENT = $env:CONDA_PREFIX
uv sync --locked --inexact --group dev --no-python-downloads
Remove-Item Env:UV_PROJECT_ENVIRONMENT
```

激活后直接使用 `python`、`pytest`、`ruff`；普通 `uv run` 默认会选择仓库 `.venv`，需要使用 uv 时应明确设置
`UV_PROJECT_ENVIRONMENT`。测试真实 stdio/本地 HTTP 时，执行环境须允许创建本地进程、线程与监听端口。

仓库 Pyright 配置指向 `.venv`。检查 Conda 环境时，用 `python -c "import sys; print(sys.executable)"`
获取解释器路径，再运行 `pyright --pythonpath <解释器路径>`。
