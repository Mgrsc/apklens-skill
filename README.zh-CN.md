# Android 静态分析 Skill

[English](README.md)

一套专为 AI Agent 设计的 Android 静态分析 Skill。内置由纯 Python 3.10+ 标准库驱动的轻量确定性分析引擎，无需 JVM、编译构建或第三方依赖，赋能 AI 在任意工作区或沙箱环境中开箱即用，高保真提取应用权限、遥测线索、SDK 与网络端点。

## 特性

- **零依赖与沙箱友好**：纯 Python 3.10+ 标准库实现，免安装第三方包与复杂运行时，天然契合 AI 容器与受限执行沙箱。
- **上下文友好与安全脱敏**：结构化生成轻量摘要与分段查询机制，避免大文件撑爆大模型 Context Window，自动对网络凭据与敏感参数打码。
- **全方位静态解构**：支持单个或多个 Split APK，高保真提取 DEX 引用、资源字符串池、Manifest 权限、导出组件与候选端点。
- **设备快照采集**：支持通过 ADB 连接已授权实体设备，一键完成已安装应用的元数据与 APK 静态采集。
- **批量持久化与恢复**：使用标准库 SQLite 逐制品保存检查点，从磁盘合并和导出，支持在新目录恢复中断任务。采集快照可离线复用，无需再次复制 APK。
- **有界隐私数据流**：跟踪已建模的敏感来源，经载荷构造、编码/加密、可解析方法和部分回调到达网络出口；未知调用与资源上限保留为覆盖缺口。
- **严守事实边界**：区分 E0–E2 线索与 E3/E4 静态可能路径，不将其当作已观察到上传或已确认的隐私违规。
- **具体处置建议**：AI 逐应用判断保留并限制权限、不需要时卸载，或核查依赖后考虑停用，说明证据、前提、功能影响和恢复方式；未知状态明确保留。

## 快速上手

### 方式一：远程免安装（推荐）

无需事先下载本仓库。直接将以下提示词与链接发送给具备联网与命令执行能力的 AI：

> 请读取并遵循这个 Skill，先在当前工作区准备项目，再分析我提供的 APK 或已授权设备。请完整读取说明后再执行：
>
> https://github.com/Mgrsc/apklens-skill/blob/main/online-static-analysis/SKILL.md

AI 会通过 [online-static-analysis/SKILL.md](online-static-analysis/SKILL.md) 自动检出完整项目并交由主 Skill 执行分析。若网页无法展示全文，可指示 AI 读取同一入口的 [Raw 正文](https://raw.githubusercontent.com/Mgrsc/apklens-skill/main/online-static-analysis/SKILL.md)。

### 方式二：本地工作区使用

若已将本仓库克隆到本地工作区，直接指示本地 AI 助手：

> 请读取当前项目根目录下的 [SKILL.md](SKILL.md)，并按照其中的规范分析我提供的 APK（或已授权的测试设备）。

- **开发者直接运行（可选）**：无需 AI，亦可在终端直接执行分析脚本：
  ```sh
  python3 scripts/analyze.py scan --apk path/to/app.apk --output output_dir
  ```
- **真机分析说明**：若分析实体手机，请确保已开启 USB/无线调试且 `adb devices -l` 状态为 `device`。AI 会根据环境交互式引导完成配对与拉取。

## 输出产物

分析完成后会在输出目录中生成以下标准文件：

- `report.md`：结构清晰的 Markdown 综合审计分析报告。
- `summary.json`：针对 AI 上下文优化的轻量高优先摘要。
- `analysis.json`：包含 E0–E4 发现项和有界方法/字段结构的机器可读证据导出。
- `analysis.sqlite3`：持久检查点与最终事实，大任务查询和重新导出的首选输入。
- `snapshot.json` / `progress.json`：可复用的采集状态与最新执行阶段。
- `performance.json`：本地阶段耗时、资源峰值、有效配置与代码身份。
- `domains.txt` / `telemetry-domains.txt`：归一化的网络端点与第三方遥测域名候选。

通过 Skill 执行分析时，AI 先准备覆盖全部应用组的 `assessment.json`，核查证据并记录逐应用决策，再校验并生成独立的 `user-advice.md`。[评估契约](references/assessment.md) 定义命令与评估状态。校验 PASS 不等于每个应用都已审查，待核查、延期和只有元数据的目标始终明确展示。脚本生成的 `report.md` 包含事实和核查提示。使用 `--section apps --package PACKAGE` 可查询已有安装上下文和有界建议证据样本。建议不代表已授权修改设备，审查分数高也不表示应用可以安全停用。

使用 `summary.facts` 读取应用层端点候选、SDK 匹配记录／名称／涉及应用数、权限来源及各自的输入与解析分母，不要叠加制品层和应用层统计。摘要与 Markdown 上限仅限制展示，使用 `has_more`／`next_offset` 分页检查全部目标。系统标记不能证明出厂预装或用户主动安装。两阶段方法保留与根级额度让晚位敏感区域获得分析机会，同时披露未保留方法体、未启动根和模型缺口。

大任务优先查询 `analysis.sqlite3`，避免整体读取 JSON 导出。数据库为 ID、分页和证据引用建立索引，轻量视图避免摘要全量扫描。新任务写入数据库版本 4，通过不可变事实正文共享和应用更新时复制减少重复；JSON 继续保持 schema 1，版本 1/2/3 数据库仍可只读查询，无需迁移。可用 `python3 scripts/analyze.py scan --resume previous_task_dir --output new_task_dir` 恢复任务；请保留原任务目录及其引用的 APK。恢复时在新目录重建应用分析与索引。仅采集、离线快照及内存预算详见使用参考。

Linux 上的 CPU 密集批量任务可显式使用 `--executor process --jobs 2`，默认仍为 `thread`。进程 worker 使用私有结果库、最终库单写者、任务进程树 RSS 检查和有界退出。进程需要更多内存和临时 I/O，请按实际任务比较本地测量结果。`--skip-analysis-json` 可明确省略完整 JSON，同时保留 SQLite 和轻量报告。预检估算新增磁盘占用并保留安全余量；估算与 RSS 保护均为协作式软限制。预检是分析启动前的硬门槛：可用空间不足“预计新增峰值 + max(4 GiB, 预计新增峰值的 20%)”时拒绝启动分析；小任务和仅元数据任务同样适用，且没有覆盖开关。

端点记录现仅包含显式 URL/IP 和带网络上下文的主机名。其他裸点分文本保持未知，其计数与有界溯源样本见覆盖及 `summary.facts.endpoints.selection`；端点变少不代表风险降低。域名导出仅包含保留的网络候选。

摘要中的 `review_required_total` 统计具有声明能力或敏感线索、需要审查的应用，不是已证实的隐私问题或传输路径数。审查排序按独立证据路径和地址分组计数，条件变体不重复加分；发现项计数仍表示实际保留记录数。每组最多保留 4 个条件变体，截断会标为 PARTIAL。方法/字段事实保留量与解释范围上限分别计算，具体预算及 E3/E4 共享覆盖指标见[隐私模型与限制](references/privacy-analysis.md)。

畸形或不受支持的 URL 常量会产生带位置的数据流缺口，分析继续进行。普通应用自有的版本字段本身不触发敏感指纹审查。信号派生的能力保留同类别最高证据等级，权限声明仍为 E0。

## 详细文档指引

- [主 Skill 入口](SKILL.md)：本地 Agent 完整指令、分析流程与安全边界。
- [联网引导 Skill](online-static-analysis/SKILL.md)：单文件远程引导、检出复用与移交规则。
- [使用与参数参考](references/usage.md)：完整 CLI 参数、高级过滤、配置项与查询用法。
- [证据与覆盖定义](references/evidence-and-coverage.md)：E0–E4 证据等级、解码与阶段状态。
- [手机遥测屏蔽规则素材](mobile-telemetry-domains.txt)：供用户编写屏蔽规则的带注释 TXT，按服务分组，保留精确域名、域名后缀与关键词的匹配类型。
- [隐私模型与限制](references/privacy-analysis.md)：支持的来源、传播、异步交接、查询示例及明确停止边界。
- [用户处置建议](references/user-advice.md)：保留、限制权限、卸载或考虑停用的判断条件，以及证据、影响、恢复和未知项。
- [实现与架构说明](references/implementation.md)：模块权责归属、流水线设计与性能考量。

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
