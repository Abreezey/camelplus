# Module B 验证记录

日期：2026-10-15。Python 3.10.12；MCP SDK 1.9.2；bashlex 0.18。

远程合并验证：在 `9f35a98` 上合入 `Abreezey/camelplus:dev` 的 `6347172` 后，
全仓 1153 项测试通过（50.07 秒）；Ruff、205 文件格式检查、Pyright、依赖锁检查与差异检查均通过。
这证明当前代码回归兼容，不替代下述 C 真实执行联调验收。

后续复查的三处 B 自身缺陷已修复，见 `module-b-review.md`。以下为修复后结果；
C 的真实执行入口与沙箱联调仍未完成，不能据此判定整条链路安全验收通过。

## 结果

| 检查 | 结果 |
|---|---|
| 全仓 pytest | 517 passed；273 项原有测试、244 项新增测试；Conda 环境 25.06 秒 |
| B 语句覆盖率 | 100%，1104/1104；13 个实现文件，单测及真实协议集成合计，包含子进程 |
| Ruff | All checks passed |
| Ruff format | 125 files already formatted |
| Pyright | 0 errors, 0 warnings |
| git diff --check | 通过 |

覆盖率沿用仓库原有配置：不统计 `__init__.py`、测试文件、`main.py` 和已有的抽象方法排除项。
未新增 coverage 排除规则。B 的每个实现文件均为 100%，与现有 audit 模块并列最高。
语句覆盖率不表示分支全覆盖或安全完备。

专项回归覆盖 RPC 效果顺序、SECRET/PUBLIC 文件标签、拒绝后的零上游调用；
ALLOW/CONFIRM/DENY 及确认后的敏感 URL 审计；SQLite/报告无合成秘密；
加密载荷恢复后原策略重放一致，错误密钥、事件错配、摘要篡改、未知格式拒绝；脚本变化时 stdio 零启动。

Conda 环境 `/root/miniconda3/envs/camelplus` 已实际创建并通过上述全仓测试。
`python scripts/setup_conda.py` 再次运行成功，复用环境、核对 216 个已安装包并完成导入验证，未重建环境。

## 验收证据

| 要求 | 测试与可观察结果 |
|---|---|
| 原文与匹配视图 | NFKC、零宽/控制位置、HTML/percent/base64、输入/输出/深度预算；detector envelope 同时保留原文与视图 |
| 文件边界 | 绝对路径、file URI、symlink 逃逸/环、cwd 逃逸、多路径；允许调用的实际文件内容与规范效果一致 |
| Shell AST | 管道/重定向/子命令；动态展开、赋值、未知命令、curl 管道执行、base64 执行均失败关闭；实际 Bash 文件复制差分 |
| 网络 | 私网、metadata、mapped IPv4、混合 DNS、空 DNS、rebinding、重定向；检查连接 IP、Host、TLS SNI、请求体 |
| Git | 只读/工作树/commit/remote/push 分类；远端覆盖、未知选项和越界路径拒绝；实际 git status 差分 |
| MCP pin | 身份、描述、schema、工具移除变化均暂停；发现与调用均检查；登记并发无法覆盖已有 pin |
| 整次调用授权 | 任一效果 DENY/FAILED，零上游调用；危险语料通过 Gateway 再次验证，不只检查 parser 的返回值 |
| 确认 | 主体/session/参数/policy/manifest/过期绑定；一次消费、拒绝不可重放；挂起期间预算变化使旧确认失效 |
| 标签与审计 | 上游 role 仍为不可信数据；默认 SECRET；传播参数和文件标签；返回前调用检测 hook；manifest 与参数摘要进入哈希链 |
| 故障 | 审计不可写时不派发；超时/SDK 错误脱敏且记录不确定执行；超大/无效返回不向 Agent 暴露 |
| 真实协议 | Agent → stdio Gateway → stdio upstream；Streamable HTTP upstream；下游真实 JSON-RPC、认证隔离、Host/Origin/帧预算、分块及断连 |

先用最小用例复现了纯注释 bashlex 异常、失效本地 schema 引用、SDK 错误泄露、陈旧确认预算和畸形 URI 异常，
再修改实现并回归。测试只使用临时目录、假凭据与本地协议服务，不调用外部 LLM 或外部网络。

## 复现

```bash
.venv/bin/pytest -q --cov=camel --cov-report=term-missing:skip-covered
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
git diff --check
```

pytest-cov 6 的 COV_CORE_* 变量仅在测试子进程间传递，以采集真实 stdio 代码；不传递开发环境凭据。
本环境沙箱内的跨线程异步唤醒会阻塞，真实协议测试使用已批准的沙箱外运行权限。
C 的 OS/网络隔离及 D 的旧入口接线、检测器/评测仍按各自分工完成，详见 `handoff-b.md`。
