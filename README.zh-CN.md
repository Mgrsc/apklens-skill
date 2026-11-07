# Android 静态分析 Skill

[English](README.md)

> **面向 AI Agent 的零依赖 Android 隐私与遥测静态分析 Skill** —— 仅依赖 Python 3.10+ 标准库，在任意工作区或受限沙箱中检查应用权限、SDK、网络端点及有界隐私数据流。

## 特性

- **零依赖与沙箱即用**：纯 Python 3.10+ 标准库实现，无需 JVM、编译构建或第三方包。
- **全量 APK 与设备快照分析**：直接解构单包或 Split APK，支持通过 ADB 只读采集已授权设备的包元数据与 APK 快照。
- **有界隐私数据流与严守证据边界**：区分 E0–E2 静态声明/线索与 E3/E4 建模可能路径，未知调用与预算上限明确保留为覆盖缺口，不将静态路径夸大为实测上传。
- **上下文友好与默认脱敏**：生成轻量摘要与 SQLite 分页按需查询（`has_more` / `next_offset`），默认自动打码 URL 凭据与查询参数。
- **持久批量存储与资源保护**：使用 SQLite v4 保存检查点并支持跨目录 `--resume` 恢复，分析前执行硬性可用磁盘余量预检（`预计新增峰值 + max(4 GiB, 20%)`）并配合协作式内存与调度时限。
- **结构化 AI 评估与处置建议**：通过 `assessment.json` 全量登记目标应用，校验证据引用与前提条件，生成可操作的 `user-advice.md` 报告。

## 快速上手

**环境要求**：`Python >= 3.10`（仅需标准库）。可选依赖：真机快照采集需 `adb`，反编译文本补充扫描需 `jadx`。

### 方式一：远程免安装（推荐）

直接将以下提示词与链接发送给具备联网与命令执行能力的 AI Agent：

> 请读取并遵循这个 Skill，先在当前工作区准备项目，再分析我提供的 APK 或已授权设备。请完整读取说明后再执行：
>
> https://github.com/Mgrsc/apklens-skill/blob/main/online-static-analysis/SKILL.md

AI 会通过 [online-static-analysis/SKILL.md](online-static-analysis/SKILL.md) 检出项目、记录已校验提交并移交主 Skill 执行分析（若网页未展示全文可读取 [Raw 正文](https://raw.githubusercontent.com/Mgrsc/apklens-skill/main/online-static-analysis/SKILL.md)）。

### 方式二：本地工作区

若已将本仓库克隆到本地工作区，直接指示本地 AI 助手：

> 请读取当前项目根目录下的 [SKILL.md](SKILL.md)，并按照其中的规范分析我提供的 APK（或已授权的测试设备）。

- **终端直接运行（可选）**：无需 AI，可直接运行确定性分析脚本：
  ```sh
  python3 scripts/analyze.py scan --apk path/to/app.apk --output output_dir
  ```
- **真机分析说明**：开启 USB 或无线调试并确认 `adb devices -l` 状态为 `device`，AI 会交互式引导完成配对与只读快照拉取。

## 输出产物

分析引擎在任务目录中生成的标准文件：

- `report.md`：确定性生成的 Markdown 审计报告，包含事实汇总与核查提示。
- `summary.json`：面向 AI 上下文优化的轻量摘要（含 `summary.facts` 与 Top 20 优先列表）。
- `analysis.sqlite3`：包含检查点与索引事实的权威 SQLite 数据库，大任务优先通过 `scripts/query_results.py` 分页查询。
- `analysis.json`：兼容的机器可读全量导出（可通过 `--skip-analysis-json` 省略）。
- `snapshot.json` / `progress.json` / `performance.json`：可复用采集快照、最新执行里程碑及阶段耗时/资源峰值记录。
- `domains.txt` / `telemetry-domains.txt`：保留的网络端点候选与遥测标签域名候选（非直接可用的屏蔽表）。

AI 通过 `scripts/assess_results.py` 在独立目录生成的评估产物：

- `assessment.json`：覆盖全部应用组的评估账本，记录证据核查、延期原因与处置前提。
- `user-advice.md`：经校验生成的用户处置建议报告，包含核对范围、证据结论、处置建议（`retain` / `restrict` / `uninstall` / `disable` / `defer`）及完整登记统计。

## 详细文档指引

- [主 Skill 入口](SKILL.md)：本地 Agent 完整执行流程、结果解读规则与安全边界。
- [联网引导 Skill](online-static-analysis/SKILL.md)：远程检出、版本校验与移交说明。
- [使用与参数参考](references/usage.md)：完整 CLI 语法、`--resume` 恢复、`--executor process` 进程并发、资源预检与分页查询示例。
- [证据与覆盖定义](references/evidence-and-coverage.md)：E0–E4 证据等级、端点候选收敛策略与阶段/覆盖状态。
- [隐私模型与限制](references/privacy-analysis.md)：已建模敏感来源、传播规则、条件变体预算、`review_required_total` 语义与停止边界。
- [评估账本契约](references/assessment.md)：`assessment.json` 结构、`prepare` / `validate` / `render` 流程与校验规则。
- [用户处置建议规范](references/user-advice.md)：处置判断标准、核查范围、前提核实、影响披露与恢复说明。
- [实现与架构说明](references/implementation.md)：模块权责归属、SQLite v4 存储架构与性能基准说明。
- [手机遥测屏蔽规则素材](mobile-telemetry-domains.txt)：按服务分组的带注释域名与关键词素材，供用户编写防火墙/DNS 规则。

## 开发验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

若本地具备 Ruff：

```sh
ruff check --no-cache --target-version py310 scripts tests
ruff format --check --no-cache --target-version py310 scripts tests
```

## 参与贡献与许可证

- 参见 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 遵循 [MIT 开源许可证](LICENSE)。
