# Android 静态分析 Skill

[English](README.md)

一套专为 AI Agent 设计的 Android 静态分析 Skill。内置由纯 Python 3.10+ 标准库驱动的轻量确定性分析引擎，无需 JVM、编译构建或第三方依赖，赋能 AI 在任意工作区或沙箱环境中开箱即用，高保真提取应用权限、遥测线索、SDK 与网络端点。

## 特性

- **零依赖与沙箱友好**：纯 Python 3.10+ 标准库实现，免安装第三方包与复杂运行时，天然契合 AI 容器与受限执行沙箱。
- **上下文友好与安全脱敏**：结构化生成轻量摘要与分段查询机制，避免大文件撑爆大模型 Context Window，自动对网络凭据与敏感参数打码。
- **全方位静态解构**：支持单个或多个 Split APK，高保真提取 DEX 引用、资源字符串池、Manifest 权限、导出组件与候选端点。
- **设备快照采集**：支持通过 ADB 连接已授权实体设备，一键完成已安装应用的元数据与 APK 静态采集。
- **严守事实边界**：明确划分 E0–E2 静态证据等级，严禁大模型在隐私与遥测分析中臆测虚构数据流。

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
  python3 scripts/analyze.py --apk path/to/app.apk -o output_dir
  ```
- **真机分析说明**：若分析实体手机，请确保已开启 USB/无线调试且 `adb devices -l` 状态为 `device`。AI 会根据环境交互式引导完成配对与拉取。

## 输出产物

分析完成后会在输出目录中生成以下标准文件：

- `report.md`：结构清晰的 Markdown 综合审计分析报告。
- `summary.json`：针对 AI 上下文优化的轻量高优先摘要。
- `analysis.json`：包含所有 E0–E2 静态证据与调用关系的机器可读全量事实。
- `domains.txt` / `telemetry-domains.txt`：归一化的网络端点与第三方遥测域名候选。

## 详细文档指引

- [主 Skill 入口](SKILL.md)：本地 Agent 完整指令、分析流程与安全边界。
- [联网引导 Skill](online-static-analysis/SKILL.md)：单文件远程引导、检出复用与移交规则。
- [使用与参数参考](references/usage.md)：完整 CLI 参数、高级过滤、配置项与查询用法。
- [证据与覆盖定义](references/evidence-and-coverage.md)：E0–E4 证据等级、解码与阶段状态。
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
