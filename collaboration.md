# CaMeL Plus 四人协作说明与 Git 操作守则

> **适用项目**：[InnoSamY/camelplus](https://github.com/InnoSamY/camelplus/tree/dev)（以 `dev` 分支为协作基线）  
> **参考资料**：[四人零基础开发与分工方案](./CaMeL_Plus_四人零基础开发与分工方案.md) · [arch.md](https://github.com/InnoSamY/camelplus/blob/dev/arch.md) · [ref.md](https://github.com/InnoSamY/camelplus/blob/dev/ref.md)  
> **版本**：v1.0 · 2026-10-14  
> **适用人群**：四人初学者开发团队；默认使用 Windows PowerShell，也适用于 Git Bash/WSL。  
> **文档用途**：统一合作方式，避免多人覆盖代码、把未验证功能合入主线，以及误提交密钥或误执行危险操作。

---

## 一、合作目标：四个人写一个系统，不是四个人写四个项目

CaMeL Plus 在现有 CaMeL 基础上新增安全防御链路：

```text
用户提出任务
    ↓
A：可信任务合同 + 数据来源标签
    ↓
CaMeL 规划 / 提出候选工具调用（保留原有代码）
    ↓
B：网关接收请求 + 规范化工具效果
    ↓
C：安全策略判定（ALLOW / CONFIRM / DENY）
    ↓
C：仅执行已获批准、受控范围内的操作
    ↓
D：记录事件 + 回归测试 + 演示报告
```

**共同优先级**：① 四个模块能连起来；② 没有允许路径的高风险操作默认拒绝；③ 已有 CaMeL 功能不被破坏；④ 结果能复现、可解释。不要为追求模块数量而同时开发尚不需要的功能。

### 1.1 四人的职责边界

| 成员 | 分工 | 主要负责目录或文件 | 日常任务 | 交给下游什么 |
|---|---|---|---|---|
| **A：入口与基础模型** | 用户意图、数据标签、CaMeL 接入 | `src/camel/core/`、`src/camel/adapters/agentdojo/` | 定义公共数据结构，记录可信用户授权、标签；负责接回原版 CaMeL | `IntentContract`、`TrustLabel` 以及兼容适配 |
| **B：工具网关** | 工具调用拦截与效果识别 | `src/camel/normalization/`、`src/camel/gateway/` | 检查工具名称、参数，把调用转成统一效果 | `CanonicalEffect[]`，附来源信息 |
| **C：策略与执行** | 安全规则、三态决定、受控执行 | `src/camel/policy/`、`src/camel/broker/` | 根据用户授权与来源标签判断允许/拒绝，并控制实际执行 | `Decision`、执行结果或拒绝原因 |
| **D：测试与审计** | 测试、日志、演示、集成验证 | `src/camel/audit/`、新增的 `tests/`、`demo.py`、`docs/demo_report.md` | 提供测试数据，验证接口与防御结果，整理日志/报告 | 自动化测试、可复现演示及缺陷记录 |

**强调**：D 牵头测试体系，**不等于其他三人可以不写测试**；A、B、C 各自负责模块的正常、拒绝、异常测试。接口和安全问题是四人共同责任。

### 1.2 公共文件与高风险文件

以下现有文件应尽量保留，**不可自行大范围修改**：

- `src/camel/interpreter/`：原有解释器，初期不重写。
- `src/camel/capabilities/`、`src/camel/security_policy.py`：现有安全元数据与策略，先做兼容层。
- `src/camel/pipeline_elements/privileged_llm.py`、`src/camel/models.py`、`main.py`：现有主调用链；需要联调改动时由 A 牵头，经有关成员审阅。
- `arch.md`、`ref.md`：共同架构和依据；涉及安全语义、项目范围或论文依据的修改须先讨论。
- 原有 `tests/` 文件：不能为了通过测试而删除、跳过或随便调整预期结果。

**跨目录改动原则**：先在任务讨论里写清「改哪个文件、为何要改、影响哪些人」，相关负责成员同意后再动手。Git 只能发现文本冲突，不能自动发现接口语义冲突。

---

## 二、团队每天如何协作

### 2.1 一项任务如何流转

```text
提出任务（GitHub Issue / 项目任务表）
    ↓
确认负责人、交付物和验收标准
    ↓
从最新 dev 新建个人任务分支
    ↓
开发 + 本地测试 + 自查
    ↓
推送个人分支，发起 Pull Request（PR）
    ↓
至少 1 名其他成员审查（安全核心改动建议 2 人）
    ↓
检查通过 → 合并到 dev
    ↓
其他成员同步 dev，继续下一项任务
```

一个任务推荐半天到两天完成；太大的任务拆成能独立测试的几个 PR，但**不要把功能拆成大量没有实际价值的小提交**。

### 2.2 会议与报告

- **每天 10–15 分钟同步**：每人说三件事——已完成什么、下个任务是什么、遇到什么阻塞。
- **接口变化立即通知**：例如 A 更改 `Decision` 字段，须先通知 B/C/D 并更新接口样例。
- **联调时四人一起看一次完整流程**，不要只证明各自模块单独能运行。
- **超过半天解决不了的阻塞**，在任务记录中写下复现方法并求助，不要无声卡住。
- **每个合并后的功能都留有证据**：测试命令、测试结果或演示截图、变更说明。

建议在 GitHub Issues/Projects 里维护四列：`待做` → `进行中` → `待审查` → `已完成`。项目简单时，用一份共享 `TASKS.md` 也可以；不必为任务管理引入复杂平台。

### 2.3 任务卡模板

```markdown
## 任务：实现最小只读文件效果识别
- 负责人：B
- 目的：将读取仓库文件的工具调用转成 READ 效果
- 修改范围：src/camel/normalization/fs.py
- 输入：工具名、参数及来源标签
- 输出：CanonicalEffect[]
- 验收：普通文件 READ；敏感路径能识别；未知调用不能误报安全
- 依赖：A 已提供公共数据模型
```

---

## 三、Git 最重要的规则（先记这六条）

1. **`main` 不参与日常开发**；`dev` 是四人共用的集成分支，**也不要直接向 `dev` 推送代码**。
2. **每人每项任务开自己的 `feature/` 分支**，完成后通过 PR 合并到 `dev`。
3. **每次开始新任务，先更新本地 `dev`**；不要在已经落后的分支上无限开发。
4. **提交前一定执行 `git status` 和 `git diff`**，检查没有混入别人的文件、密钥、日志或无关改动。
5. **禁止强制推送共享分支、禁止改写已共享提交历史**；发现问题用新的修复提交或 `git revert`。
6. **不能为了合并成功而删除安全检查、注释掉测试、放宽 `DENY` 规则**。

### 3.1 分支结构

```text
main                         原项目默认主分支；不直接修改
  └── dev                    四人共同集成与演示基线
        ├── feature/a-core   A 的当前任务分支（示例）
        ├── feature/b-gateway
        ├── feature/c-policy
        └── feature/d-audit
```

这里 `feature/a-core` 等只是**第一轮任务分支名称**，不是必须长期保留的四条永久分支。第一个 PR 合并后，下一项任务可从最新 `dev` 创建 `feature/a-intent`、`feature/b-git-effect` 等新分支，这样更容易减少合并冲突。

分支命名建议：

| 分支 | 谁使用 | 什么时候创建 |
|---|---|---|
| `feature/a-core` | A | 初次建立基础模型 |
| `feature/b-gateway` | B | 初次开发工具网关 |
| `feature/c-policy` | C | 初次开发策略模块 |
| `feature/d-audit` | D | 初次开发日志模块 |
| `fix/b-path-check` | B | 修复路径判断缺陷 |
| `test/d-integration` | D | 添加集成测试 |
| `docs/a-interface` | A | 修改共享接口说明 |

**权限建议**：GitHub 仓库管理员在 Settings → Branches / Rulesets 中为 `dev`、`main` 设置禁止直接推送、必须 PR 和至少一名审查者；安全边界 PR 建议两人审查。若四人没有该仓库的写入权限，先获得授权，或采用 Fork 后向指定仓库发 PR，不要假设任何成员能直接推送到原仓库。

---

## 四、从零开始：每个新人第一次使用 Git

以下命令复制到 **PowerShell** 中逐行执行。命令中的 `feature/a-core` 以 A 为例，B/C/D 换成自己的任务分支名。

### 4.1 第一次配置 Git（每人做一次）

```powershell
git --version
git config --global user.name "你的 GitHub 显示名称"
git config --global user.email "你的 GitHub 提交邮箱"
git config --global --list
```

邮箱可使用 GitHub 提供的隐私保护提交邮箱。这里的名字、邮箱用于提交记录，不等于给你仓库写入权限。

### 4.2 下载项目（只做一次）

```powershell
git clone -b dev https://github.com/InnoSamY/camelplus.git
cd camelplus
git branch --show-current
git status
```

预期：当前分支为 `dev`，工作区干净。`clone` 会在当前位置创建 `camelplus` 文件夹；已有同名目录时应换路径，不要直接覆盖。

### 4.3 同步共享基线，再建自己的分支

```powershell
git switch dev
git pull --ff-only origin dev
git switch -c feature/a-core
git branch --show-current
```

说明：

- `git switch dev`：切到公共基线。
- `git pull --ff-only origin dev`：只接收能安全快进的远程更新，不意外产生合并提交；如报错先检查本地改动。
- `git switch -c feature/a-core`：从当前 `dev` 复制出一个新的个人任务分支。
- 后续**所有开发都在该任务分支上完成**。

### 4.4 修改后，先检查再提交

```powershell
git status
git diff
git add src/camel/core/models.py
git diff --cached
git commit -m "feat(core): add shared data models"
```

- `git status`：看哪个文件被改、当前在哪个分支。
- `git diff`：看还没暂存的修改。
- `git add 指定文件`：只挑属于当前任务的文件加入提交。
- `git diff --cached`：再次审查将要进入提交的内容。
- `git commit`：在本机保存一个版本，**还没有上传 GitHub**。

**新手尽量不用 `git add .`**，直到确定没有意外的密钥文件、生成日志或不相关改动。

### 4.5 把个人分支推送到 GitHub

```powershell
git push -u origin feature/a-core
```

首次 push 可能要求浏览器认证或 GitHub 凭据。无仓库写入权限则不要反复尝试，应请仓库管理员邀请，或改用个人 Fork。

### 4.6 发起 PR（Pull Request，合并请求）

在 GitHub 页面进入 **Pull requests → New pull request**，核对：

- **base（要合入的分支）：`dev`**
- **compare（你的改动分支）：`feature/a-core`**
- 标题：`feat(core): add shared data models`
- 描述：做了什么、修改了哪里、怎么测试、有什么已知限制。
- 请求另一位成员 Review；安全策略/执行/授权改动尽量由 C + 另一人共同审查。

**注意**：PR 方向选反会把 `dev` 合进个人分支，不能达到预期的集成目的。

### 4.7 PR 通过后再开始下一项任务

```powershell
git switch dev
git pull --ff-only origin dev
git switch -c feature/a-intent
```

旧任务分支合并后可以通过 GitHub 删除远端旧分支，再按团队约定删除本地旧分支；**不要删仍有未合并改动的分支**。

---

## 五、日常开发应当怎么操作（固定流程）

### 5.1 每天开工前

```powershell
git status
git branch --show-current
git fetch origin
```

先确认自己是否有未提交工作；如果要开始**新任务**，回到 `dev`、`git pull --ff-only origin dev` 后新建分支。不要无脑切分支或拉更新。

### 5.2 已在个人分支开发，别人又合并了代码怎么办？

最简单的方式是**合并最新公共基线到个人分支**（建议新手用 `merge`，暂不使用 `rebase`）：

```powershell
git status                    # 确保无未提交的改动
git fetch origin
git merge origin/dev          # 当前必须是自己的 feature 分支
```

没有冲突就继续开发并提交；有冲突按第六节处理。注意 `git merge origin/dev` **不能在 `main`、`dev` 或错误分支上随意执行**。

### 5.3 改了一半需要临时切换怎么办？

推荐优先保存一个完整、可理解的本地提交；不适合提交时，也可临时暂存：

```powershell
git stash push -u -m "wip: my unfinished change"
git status
git switch dev
# 处理完其他事情后：
git switch feature/a-core
git stash list
git stash pop
```

`stash` 是**本机临时储藏**，不会自动上传 GitHub；`stash pop` 若有冲突仍需手工解决。不要把 stash 当备份系统；有重要工作应正常提交并推送到个人分支。

### 5.4 标准提交信息

统一用英文类别 + 中文或英文解释，方便在历史记录里检索：

```text
feat(core): 新增用户任务合同模型
feat(gateway): 规范化文件读取调用
feat(policy): 拒绝未授权的外部数据发送
fix(gateway): 修复相对路径识别
 test(audit): 增加完整链路拒绝用例
 docs: 更新四人接口说明
```

建议类别为 `feat`（新增功能）、`fix`（修复）、`test`（测试）、`docs`（文档）、`refactor`（不改变外部行为的重构）、`chore`（维护）；提交信息不必过度格式化，但要看得出**为什么改**。

---

## 六、遇到 Git 冲突怎么办（新手版）

冲突例子：A 和 B 都改了 `src/camel/core/models.py`，Git 不知道保留哪一版。

### 6.1 正确处理

1. 先通知该文件负责人，**不要直接点“全部接受我的修改”**。
2. 在发生冲突的个人分支执行 `git status`，查看冲突文件。
3. 打开文件，查找冲突标记：

   ```text
   <<<<<<< HEAD
   你当前分支的内容
   =======
   来自 dev 的内容
   >>>>>>> origin/dev
   ```

4. 和相关负责人确认最终应保留的代码及接口字段，编辑成正确版本，删除所有冲突标记。
5. 执行检查、测试，确认没有只在语法上解决冲突却改变安全语义。
6. 标记文件已解决并结束合并：

   ```powershell
   git add src/camel/core/models.py
   git status
   git commit
   git push
   ```

`git commit` 未提供消息时 Git 可能打开编辑器填写合并说明，保存退出即可。部分 Git 版本在没有冲突时会自动创建合并提交。

### 6.2 如果发现自己解决不了

在合并还没有提交、且需要回到合并前状态时，可执行：

```powershell
git merge --abort
```

然后联系相关负责人。**不要使用 `git reset --hard` 或 `git push --force` 试图消除冲突**，这很容易丢失其他成员的工作。

### 6.3 共享分支已经合入了错误代码怎么办？

先告知全员并暂停依赖该功能的开发；由指定负责人创建修复分支，用 `git revert <提交ID>` 在新提交中撤销错误，再通过 PR 合入 `dev`。`revert` 保留历史，比事后覆盖共享历史更适合团队协作；涉及敏感信息泄露时另按安全事件流程处理。

---

## 七、PR 审查与合并守则

### 7.1 一个合格的 PR 应包含

```markdown
## 本次改动
- 完成的功能：
- 修改文件：
- 为什么需要此改动：

## 输入/输出与接口
- 输入是什么：
- 输出是什么：
- 是否影响 A/B/C/D 其他模块：

## 验证
- [ ] 正常用例
- [ ] 拒绝或异常用例
- [ ] 本地测试命令及结果
- [ ] 未修改无关的原版文件
- [ ] 未包含 API Key、真实密码及敏感日志

## 风险与未完成部分
- 风险：
- 后续工作：
```

### 7.2 Reviewer（审查者）要看什么

| 检查项 | 重点 |
|---|---|
| 功能 | 实现是否符合任务卡？代码是否有实际使用者？ |
| 接口 | 与其他成员约定的数据类型、枚举、默认值是否一致？ |
| 安全 | 异常会不会意外 `ALLOW`？是否先执行后检查？未知效果会不会被忽略？ |
| 测试 | 是否有正常用例、拒绝用例、异常用例？新增失败是否说明原因？ |
| 范围 | 是否顺便重写原解释器、删除旧测试或扩大依赖？ |
| 隐私 | 是否提交真实 API Key、私人文件或含敏感信息的完整日志？ |

**普通 PR 至少一人审查；涉及 `policy/`、`broker/`、`gateway/`、可信标签或核心授权语义的 PR 建议至少两人审查，其中至少一名是相邻模块负责人。作者不能把“自己测试过”视为已完成审查。**

### 7.3 哪些情况必须拒绝合并

- 工作分支选错合并目标或 PR 包含大量无关文件。
- 无法说明行为变更，或公共接口变更没有通知依赖者。
- 通过更改预期结果、跳过测试、吞掉异常或删除保护规则来让测试变绿。
- 安全硬拒绝可能被模型输出、确认按钮或不可信工具结果覆盖。
- 有真实密钥/私人文件/需要授权的敏感数据。
- 代码不能运行、存在新失败且没有经全员认可的明确处理方案。

**测试基线原则**：如果原仓库某项检查一开始就失败，单独记录旧失败；不能把它归罪于新代码，也不能借此忽略本次新增问题。

---

## 八、开发前后的检查命令

项目当前使用 `uv` 管理环境，仓库 `.python-version` 为 Python `3.10.12`，`pyproject.toml` 要求 Python `>=3.10`。建议四个人统一使用仓库推荐版本，减少环境差异。

```powershell
# 首次安装依赖：在项目根目录执行
uv sync

# 每次提交/发 PR 前，检查工作区和提交范围
git status
git diff
git diff --cached

# 运行仓库测试与规范检查
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

以上是**推荐运行的命令**，不表示当前仓库已全部通过。若某项存在环境依赖、原版已知故障或暂未覆盖，请在 PR 里记录真实结果，禁止造假。切勿在全仓库直接运行 `ruff check --fix` 或自动格式化所有原版文件后顺手提交，避免产生大量不相关改动。

**新增业务代码最低要求**：能导入、核心场景能执行、正常/拒绝/异常路径有测试、不会输出秘密。对真实模型 API 的调用须事先确认预算及密钥管理方式；初期优先使用离线模拟工具验证安全机制。

---

## 九、共享接口的特殊协作规则

四人最容易发生的不是 Git 文本冲突，而是**A 改了字段，B/C/D 没同步，导致程序运行时报错**。

因此约定：

1. 第一轮由 A 建立公共模型：`TrustLabel`、`IntentContract`、`CanonicalEffect`、`Decision`、`CanonicalEvent`；由 B/C/D 共同审查。
2. 字段名称、枚举值和含义确认后，写在 `docs/interface_contract.md`，连同一个最小 JSON 样例；该文件是团队约定，不是生产级 API 文档。
3. **不允许 B/C/D 分别复制一个自己的 `Decision` 或 `CanonicalEffect` 类**。所有模块从公共位置导入。
4. 若要新增/删除字段、改 `ALLOW/CONFIRM/DENY` 语义、改变标签信任规则，必须先提 Issue 或 PR，列清楚受影响的模块和示例。
5. 安全接口不得“为了方便”把可信任务合同直接从网页或工具返回重新生成；来源和权限必须在边界上保留。
6. 公共接口的变更 PR 需相邻模块负责人审查，并更新测试与示例。

**合并顺序建议**：先合并 A 的公共数据模型，再分别合并 B、C、D 各自依赖的新功能；D 可以先在自己分支写测试场景和桩数据，但正式联调必须使用统一模型。

---

## 十、安全与保密守则（必须遵守）

CaMeL Plus 研究的是安全防御，所以开发操作本身也要安全：

- `.env`、API Key、密码、私钥、令牌、客户/个人敏感数据**不能进入 Git 提交、PR、截图和测试日志**；项目中 `.env.example` 只能放变量名或虚构占位值。
- 不使用真实秘密做“外发演示”；只用假数据和本地受控地址，危险工具操作默认在模拟环境测试。
- **不在宿主机直接执行不可信脚本**；`curl | sh`、未知 Git hooks、外部 MCP 服务器等须经审查并在隔离环境验证。
- 禁止未授权的真实 `git push`、文件删除、网络外发；Git 协作所需的 `git push` 仅指把**本项目代码提交**上传到已授权仓库，不代表允许智能体任意运行 Git 工具。
- 审计日志记录来源 ID、效果类型、决策及原因即可；秘密保留受控引用或脱敏表示，不要为追踪方便把完整密钥写进 SQLite。
- 模型输出、工具返回、网页文字都是不可信数据，**不能自己修改可信合同或降低安全标签**。

**如果不小心提交了真实密钥**：立即停止传播、通知团队和密钥所有者、撤销或轮换密钥；不要认为只提交一个“删除密钥”的新 commit 就能清除历史中的密钥。Git 历史清理必须在仓库管理员统一协调下处理，并检查所有副本、PR 和日志。

---

## 十一、常见错误速查表

| 我遇到的问题 | 先检查/做什么 | 不该做什么 |
|---|---|---|
| 不知道自己在哪个分支 | `git branch --show-current` | 直接 push |
| 不知道改动了什么 | `git status`、`git diff` | 直接 `git add .` |
| 忘了提交的文件 | `git status` 后指定文件 `git add` | 把整个目录无差别加入 |
| 当前分支落后于 dev | `git fetch origin`，个人分支上 `git merge origin/dev` | 在错误分支上乱拉取 |
| 合并冲突 | 联系文件负责人，手工解决，重新测试 | 全部接受一侧、删除保护逻辑 |
| PR 合错方向 | 核对 `base: dev ← compare: 个人分支` | 未核对直接合并 |
| 误改了文件但还未暂存 | 先看 `git diff`，必要时联系负责人；确需丢弃才用 `git restore -- 文件路径` | 对整个工作目录执行硬重置 |
| 误暂存了某文件 | `git restore --staged 文件路径` | 为取消暂存删除文件 |
| push 被拒绝 | 核对分支权限、远程和认证；联系管理员 | 尝试 `--force` 绕过 |
| 共享分支合入错误功能 | 新建修复分支，通过 `git revert` 撤回 | 改写共享历史 |
| 误提交密钥 | 立即报告、撤销密钥并协调清理历史 | 只删最新文件就宣布安全 |

> **提醒**：`git restore -- 文件路径` 会丢弃该文件尚未提交的本地修改；执行前先用 `git diff` 确认没有需要保留的内容。

---

## 十二、合并前的团队检查清单（可直接复制到 PR）

```markdown
### 开发者自检
- [ ] 我在个人任务分支，不在 main / dev 上直接开发
- [ ] 我只改了本次任务相关文件
- [ ] 我检查过 git status / git diff / git diff --cached
- [ ] 我没有提交 .env、密钥、私有数据或无关输出
- [ ] 我说明了输入、输出和失败处理
- [ ] 我补充了正常、拒绝、异常情况的测试
- [ ] 我运行了适用的测试命令，并如实记录结果
- [ ] 我没有削弱安全策略、跳过旧测试或重写无关模块

### 审查者自检
- [ ] PR 的 base 为 dev，compare 为个人任务分支
- [ ] 涉及的其他模块负责人知道接口变化
- [ ] 不会出现未授权操作被意外执行
- [ ] 审计与测试能解释实际效果
- [ ] 不存在阻塞合并的安全问题
```

## 十三、四人约定与冲突决策机制

- **A** 维护公共模型及 CaMeL 接入的变更协调；**B** 审核规范化效果是否准确；**C** 对硬策略和执行授权作技术审核；**D** 维护测试、审计与集成验收证据。
- 模块内部的小实现由该模块负责人决定；公共接口、安全不变量、分支保护、演示范围由四人讨论后确定。
- 不能达成一致时，**先保留现有安全行为，不合并争议 PR**；在 Issue 里写下两种方案、风险、测试证据，之后再定。
- 任何人都可以对可能泄密、绕过网关、跳过策略或破坏测试的改动提出**暂停合并**，直到风险处理清楚。
- 如果开发期限不足，减少附加功能而不是减少安全检查。必须明确区分“演示级拦截”与“真实执行环境不可绕过的强制隔离”。

### 最简执行口诀

> **先沟通接口，后修改代码；先切个人分支，后开始开发；先跑测试，后提 PR；先审查，后合并；只做自己负责的改动，发现安全风险立即停止合并。**

---

## 附录：新手最常用的 12 个 Git 命令

| 命令 | 一句话理解 |
|---|---|
| `git clone -b dev 地址` | 下载项目并切到 dev |
| `git status` | 查看分支与文件改动 |
| `git branch --show-current` | 查看当前分支 |
| `git switch dev` | 切到公共基线 |
| `git pull --ff-only origin dev` | 安全更新本地 dev |
| `git switch -c feature/a-core` | 从当前分支创建自己的任务分支 |
| `git diff` | 看具体修改内容 |
| `git add 文件路径` | 选择要提交的文件 |
| `git diff --cached` | 审查即将提交的内容 |
| `git commit -m "说明"` | 在本地保存版本 |
| `git push -u origin 分支名` | 首次把个人分支上传 GitHub |
| `git fetch origin` | 获取远程更新信息，但不自动合并 |

**最终约定**：`main` 保存原项目主线；`dev` 保存四人已审核、可集成的成果；每个 `feature/` 或 `fix/` 分支只承担一项明确任务。真正的成果不是提交数量，而是**每一次合并都能运行、能验证、能追溯、不降低安全性**。
