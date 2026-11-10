# ReadOnly Observer

[English](README.md) · [Linux / 多节点部署](docs/deployment.zh-CN.md) · [systemd 219](docs/systemd219.md)

让 MCP 客户端依据证据，只读访问你在本机明确批准的项目和单个 Codex 会话。

**0.1.0 · Alpha / 实验阶段。** 公开版本从 0.1.0 开始；同一代码支持 macOS 与独立 Linux 节点。Linux 推荐使用下方交互向导，测试证据见[向导审计](docs/linux-wizard-audit.md)。请使用包含脚本的已审核版本；本轮向导改造尚未提交或推送，等待人工审核。

## Linux 推荐入口：交互式安装与升级

前置条件：root/sudo、Bash、Python **3.14+**（含 venv/ensurepip）、`/usr/bin/git` **2.28+**、正在运行的 systemd **219+**、至少 1 GiB 空间，以及已安装并由操作者核验的官方 Tunnel Client。向导会检查这些条件，不自动升级系统/systemd，不下载 Tunnel 可执行文件。

```bash
git clone https://github.com/liuhuijiayou/readonly-observer.git
cd readonly-observer
sudo bash scripts/install_linux_node.sh
```

逐项提示 Node Name、安装目录、独立 home、项目路径/alias、可选精确 JSONL/alias、Tunnel 显示名、必须明确输入的 Tunnel ID、自动探测后确认的客户端路径、隐藏 Runtime Key、代理选择及隐藏 URL、unit 名和是否启动。无需编辑 Shell、JSON 或环境变量。项目/会话分别输入 `approve`；密钥仅交给 Observer 的现有隐藏 TTY CLI。Platform 资源和 ChatGPT 连接仍由你手动创建。

```bash
sudo bash scripts/install_linux_node.sh --dry-run
sudo bash scripts/install_linux_node.sh --no-start
sudo bash scripts/upgrade_linux_node.sh --home /var/lib/readonly-observer/linux2 --ref REVIEWED_COMMIT_OR_TAG
```

参数只能预填非秘密配置，实际授权和密钥输入仍要求人工 TTY。已有 home/unit 会拒绝覆盖；中断后可显式 `--resume --install-dir ...`，升级保留旧 release/venv 并支持回滚。完整步骤见[安装、升级与恢复 SOP](docs/deployment.zh-CN.md#终端向导-sop)。原有 Mac 操作保持不变；手动 Linux 流程保留作故障恢复。

## 功能

- **理解代码库。** 浏览、搜索已批准的源码，跨文件追踪实现，并引用路径、行号和源码哈希。
- **回顾 Codex 会话。** 从单个已登记 JSONL 读取公开上下文和执行结果，支持长输出分页；不发现全部历史。
- **对照证据。** 将会话记录与当前源码、有界 Git 状态、差异和 HEAD 历史关联，不把“已结束”当成正确性证明。

连接后可以这样提问（以下不是实际运行结果）：

- “在 `app` 中跨文件追踪启动到注册的实现，引用路径和行号。”
- “已批准的 `task` 会话记录了哪些执行结果，还有什么无法确定？”
- “将这段会话的证据与当前源码对照，区分记录中的说法和可验证的观察。”

**只读边界：** 新实例没有数据源，只有本机操作者能批准项目或准确会话文件。MCP 不能登记来源、运行项目命令或测试、控制会话，也不能读取隐藏推理。在聊天中提到路径不会产生授权。

已批准的 UTF-8 源码可能包含安全的忽略/未跟踪文件。敏感路径、符号链接和硬链接会被拒绝，但脱敏不能识别所有秘密。Git 使用密封快照，元数据、对象与选定工作树内容的**合计预算为 100 MB（100,000,000 字节）**，支持普通本地/远端 refs 与 pack。paths 同时限定工作树复制和 Git 查询；历史、暂存区差异无需工作树。不支持的布局或超限会明确失败，不会返回干净状态。这是单操作者服务，不提供逐用户授权。详见[安全边界](SECURITY.md)。

## 快速开始

### 1. 从源码安装

需要 **macOS 或 Linux、带 `venv`/`pip` 的 Python 3.14+，以及支持 stdio 的本地 MCP 客户端**。Git/联合证据需要 Git 2.28+，普通读取不需要。Linux Tunnel 支持 systemd 219+（旧版受限 tmpfs 暂存，247+ 原生 LoadCredential），见[完整部署指南](docs/deployment.zh-CN.md)。既有 Mac 的 Keychain、v1 配置与生命周期实现保留，无需操作当前稳定实例。Windows 不支持。当前版本真实 macOS 与远端接入仍待验收，见[工作审计](docs/implementation-audit.md)。

从 [v0.1.0 Release](https://github.com/liuhuijiayou/readonly-observer/releases/tag/v0.1.0) 下载并解压源码包，或克隆[源码仓库](https://github.com/liuhuijiayou/readonly-observer)。目前**没有公开的 PyPI 安装方式**。在包含 `pyproject.toml` 的源码目录执行：

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install .
OBSERVER="$PWD/.venv/bin/observer"
"$OBSERVER" --version
```

依赖来自你配置的包索引，通常需要网络。安装后不要移动虚拟环境。源码安装不捆绑 Python、Git 或可选的 Secure MCP Tunnel 客户端。

### 2. 建立空实例

```sh
"$OBSERVER" init --non-interactive
```

这只创建私有实例文件，不启动服务、不授予来源访问权限。macOS 默认 home 是 `~/Library/Application Support/ReadOnlyObserver`。如需自定义，在**每条**子命令前加 `--home /absolute/private/instance`，包括客户端的 `serve` 参数。实例须位于被观察项目和安装目录之外，路径应短、私有且无符号链接祖先。详见[实例配置](docs/config-reference.md#实例布局)。

### 3. 在本机批准一个项目

将路径替换为你有权开放的项目：

```sh
"$OBSERVER" project add /absolute/path/to/project --alias app
"$OBSERVER" project list
"$OBSERVER" config validate --check-sources
"$OBSERVER" doctor --level local --probe
```

审阅展示的范围，在终端输入 `approve`。`project list` 应列出 `app`；校验应报告 `service_can_start=true`。成功的 probe 报告 `local_protocol_verified`，不代表远端 ChatGPT 已连通。

### 4. 连接本地 MCP 客户端

将 stdio 服务的命令配置为 `printf '%s\n' "$OBSERVER"` 打印的**绝对路径**，参数为 `serve`。对于使用 `mcpServers` 配置的客户端，条目形式如下：

```json
{
  "mcpServers": {
    "observer": {
      "command": "/absolute/path/to/source/.venv/bin/observer",
      "args": ["serve"]
    }
  }
}
```

替换示例路径；客户端设置不一定展开 shell 变量或 `~`。外围配置格式以所用客户端文档为准。客户端负责启动和停止该进程；**使用 `serve` 不需要先执行 `observer start`**。另一个选项是托管的 `start`/`connect`，见[用户手册](docs/product-manual.md#本地-mcp-与可选菜单)。

### 5. 确认首次读取成功

在该客户端中请求以下 MCP 调用：

```text
observer_info({})
workspace_read({"alias":"app","path":"README.md"})
```

这是工具调用示例，不是 shell 命令。如果项目没有 `README.md`，先调用 `workspace_list({"alias":"app"})`，选择其中已有、无敏感内容的 UTF-8 文件。

核对 `observer_info` 返回 `ok=true`、已安装的 `version`，且 `workspaces` 包含 `app`。读取结果应含该文件的脱敏内容、物理行位置和来源版本。若返回 `next_cursor`，继续到 `selection_complete=true` 且 `next_cursor=null`；预览不等于读完。失败时参阅[故障排查](docs/troubleshooting.md)。

### 可选：批准一个 Codex 会话

会话读取已经实现，但须由你选定一个已持久保存的 JSONL 文件，单独批准：

```sh
"$OBSERVER" session add /absolute/path/to/chosen.jsonl --alias task
"$OBSERVER" session list
```

在本机审阅文件和 metadata ID 范围，然后重新连接 MCP 客户端。只批准该文件，不批准所在目录或其他会话。支持准确 ID 和显式映射的链接；无法恢复未映射的云链接或未持久保存的会话。详见[会话登记与精确引用](docs/product-manual.md#会话登记与精确引用)。

来源授权配置变更（包括新增、移除和映射）需要新的 MCP 进程：重新连接直接使用 `serve` 的客户端，或停止/启动托管实例并重新连接其客户端。旧进程停止前仍保有原授权快照。

## 接入普通 ChatGPT

**普通远端 ChatGPT 同时需要账号/工作区支持自定义 MCP 连接，以及独立受保护的传输。** 本地 stdio 快速开始不提供这两个条件，Observer 本身也没有 HTTP 服务。

可选适配器支持独立安装的官方 Secure MCP Tunnel 客户端和已有 tunnel；不创建 tunnel、不安装客户端、不创建凭据、不授予账号权限。存在适配器，不等于每个 ChatGPT 账号都能使用该接入方式。

按 [Tunnel 配置与验证手册](docs/product-manual.md#普通-chatgpt-的-tunnel-适配)和当前 [OpenAI 连接说明](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)检查自己的账号。不要将密钥放入聊天、命令参数或配置。从实际 ChatGPT 连接验证 `observer_info` 和无敏感内容的文件；`doctor` 从不证明远端就绪。

## 文档

- [用户手册](docs/product-manual.md)：会话、传输、证据与分页。
- [CLI 与配置参考](docs/config-reference.md)：命令、实例布局与全部 13 个 MCP 工具。
- [故障排查](docs/troubleshooting.md)：拒绝原因和未完成的读取。
- [升级、回退与卸载](docs/migration.md)：保留原实例和授权。
- [架构设计](docs/product-design.md) · [安全边界](SECURITY.md) · [分发范围](docs/release-scope.md)。

## 开发与贡献

[开发指南](docs/repository.md)包含隔离合成测试、SDK 检查、构建、干净导出步骤及贡献要求。测试不需要真实会话、凭据或 ChatGPT 连接。普通问题通过 [Issues](https://github.com/liuhuijiayou/readonly-observer/issues) 提交，代码变更通过 pull request 提交。补丁中不要包含私有数据；安全问题报告遵循 [SECURITY.md](SECURITY.md)。

## 许可证

ReadOnly Observer 采用 [MIT 许可证](LICENSE)，版权署名为 2026 liuhuijiayou。依赖保留各自许可条款，详见[第三方声明](THIRD_PARTY_NOTICES.md)及[分发范围](docs/release-scope.md)。
