# D8 托管全量运行日志与 summary（入库副本）

本目录是 `artifacts/d/`（gitignore）中真实运行目录的**只读副本**，入库目的是让队友不必拿到
几十 MB 的 `episodes/` 也能核对 D8 的托管结论。原始目录与本目录内容逐字节一致（见下方 sha256）。

## 来源与命令

| 子目录 | 原始目录 | 规模 | 命令要点 |
|---|---|---|---|
| `D8_full_3way_20261017_124346_B0_original_agent/` | `artifacts/d/D8_full_3way_20261017_124346_B0_original_agent/` | 614 计划 | `--population full --group B0_original_agent --max-requests 3000 --total-seconds 28800` |
| `D8_full_3way_20261017_124346_B1_original_camel/` | 同名 | 614 计划 | 同上，`--group B1_original_camel` |
| `D8_full_3way_20261017_124346_B3_ABCD/` | 同名 | 614 计划 | 同上，`--group B3_ABCD` |
| `D8_b0_multiattack_20261017_145517/` | `artifacts/d/D8_b0_multiattack_20261017_145517/` | 36 计划 | `--population smoke --group B0_original_agent` + 六个 `--attack` + `--max-requests 240 --total-seconds 3600` |

三组全量各含 14 goal control + 40 benign + 560 attack（40 用户任务 × 14 注入任务）；
`deepseek-flash`，benchmark v1.2，AgentDojo 0.1.34。三组按组拆分并行运行，每组进程内串行，
因此账户在途请求不超过 3。

## 文件与哈希

| 文件 | 字节 | sha256 |
|---|---:|---|
| `D8_full_3way_20261017_124346_B0_original_agent/run.log` | 47 | `b84a1e404fcf682c…` |
| `D8_full_3way_20261017_124346_B0_original_agent/summary.json` | 2802 | `b9f40f18957488a3…` |
| `D8_full_3way_20261017_124346_B1_original_camel/run.log` | 675001 | `ecee133948184bd2…` |
| `D8_full_3way_20261017_124346_B1_original_camel/summary.json` | 2891 | `81f3b3e0e3dd63a0…` |
| `D8_full_3way_20261017_124346_B3_ABCD/run.log` | 1316298 | `6bdc16ccf1d000b0…` |
| `D8_full_3way_20261017_124346_B3_ABCD/summary.json` | 2872 | `272e873772def74d…` |
| `D8_b0_multiattack_20261017_145517/run.log` | 64 | `6ba86e24a9d53180…` |
| `D8_b0_multiattack_20261017_145517/summary.json` | 11329 | `94401dfb71f4bed4…` |

哈希为完整 sha256 的前 16 位；校验完整值可直接对原始目录 `sha256sum`。

## 关键口径（summary.json 内可直接核对）

| 运行 | 完成/计划 | attack_goal true / false / unknown | benign utility | B3 confirm rate |
|---|---:|---|---:|---:|
| B0 全量 | 547 / 614 | 0 / 500 / **60** | 36 / 40 | — |
| B1 全量 | 614 / 614 | 0 / 560 / 0 | 20 / 40 | — |
| B3 全量 | 614 / 614 | 0 / 560 / 0 | 24 / 40 | 170 请求 / 9 批准 = 11.93% |
| B0 六攻击族筛选 | 29 / 36 | 0 / 24 / **6** | 4 / 5 | — |

- B0 的 60 个 attack unknown 就是 `TOOL_ERROR` 回合，按严格适配器排除出完成计分，**不当作
  攻击被阻断**；B0 的 ASR 因此给逻辑界 `[0, 0.107]` 而不是一个点估计。
- 六攻击族筛选的 6 个 unknown 经日志人工裁决全部是可恢复的良性查询错误（年份/日期格式、
  条件过窄、多余联系人查询），没有一次攻击工具调用，日志裁决口径为 `0/30 = 0%`。
- `summary.json` 里的 `metrics.<group>.attack_goal` 是 AgentDojo 原生 oracle 判定；
  `environment_observer` / `attack_extra_effect_positives` 是独立的 AGENTDOJO_ENV_DIFF_V1
  环境差分观察，只作旁证，不替代 oracle。
- 日志按 `print` 逐回合输出模型在 workspace 里读到的内容，**不含密钥**：DEEPSEEK_API_KEY 只经
  环境变量注入，未出现在日志、summary 或 request_budget 中。

## 未入库内容

原始目录下的 `episodes/`（逐回合轨迹，B0 30 MB / B1 31 MB / B3 80 MB）、`normalized.json`
（约 0.6 MB/组）、`security.json`、`request_budget.json` 仍只留在本机 `artifacts/d/`。需要时在
本机按上面的目录名取用，不要把它们提交进仓库。

同日的合并运行 `D8_deepseek_full_20261017_01` 在中途死亡（无 `summary.json`，日志止于
provider JSONDecodeError，疑似与拆分版并行抢账户限速），其 502 个 B0 回合与拆分版冗余，
**不入库、不作证据**，以本目录的拆分版为准。
