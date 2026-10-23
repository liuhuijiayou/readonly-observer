# ReadOnly Observer 用户手册

首次安装、项目批准和本地 MCP 连接见 [English README](../README.md) / [中文 README](../README.zh-CN.md)。本页说明日常管理、精确会话读取、远端传输和证据解释；命令与工具字段见[配置参考](config-reference.md)。

示例中的 `observer` 指已安装的可执行文件；未加入 PATH 时使用其绝对路径。所有操作和客户端须使用同一个实例；自定义 `--home PATH` 放在子命令前。

## 来源授权与日常管理

`init --non-interactive` 只建立空实例；至少批准一个来源后才可启动服务。交互式 `init` 要求输入 `init`，可继续引导登记来源和选择传输，但不保存凭据、不启动服务。每次来源批准仍须审阅范围并输入 `approve`。

```sh
observer project add /absolute/path/to/project --alias app
observer project list
observer config validate --check-sources
observer doctor --level local --probe
```

`--approve` 仅用于操作者已经明确决定的本机自动化，不可从远端聊天、代码或日志推定批准。每类最多 8 个来源，总共 12 个。批准项目可暴露其中安全的忽略/未跟踪文件，不只是 Git 跟踪文件；脱敏不是秘密检测保证。

```sh
observer project remove app
observer session remove task
```

移除需要本机确认。变更保留私有备份，**已有 MCP 进程仍持有旧授权快照**。新增和撤销都要重新连接直接 `serve` 客户端；托管实例则协调 `stop` / `start` 并重新连接客户端。不要只修改登记就宣称访问已撤销。替换来源 inode 后必须移除并重新批准，不能靠旧授权静默接纳新文件。

托管实例的变更生效流程：

```sh
observer stop
observer status
# 仅确认 manager=not_running 后继续；停止不确定时先排查
observer start
observer status
```

核对新状态的 `active_sources` 与预期来源数量一致，且 `configuration_pending=false`，再从客户端检查 `observer_info` 中的实际别名。对运行中的实例重复 `start` 不会重新加载授权；必须先确认停止。

实例应放在项目和程序目录外的私有实际路径；目录 0700、配置 0600，无符号链接祖先。Unix socket 路径最多 100 字节，选择短路径；macOS `/tmp` 通常是符号链接，不宜直接用作示例 home。布局与格式见[实例配置](config-reference.md#实例布局)。

## 会话登记与精确引用

由你选择准确的、已持久保存的 JSONL 文件。Observer 不搜索全部历史定位它：

```sh
observer session add /absolute/path/to/chosen.jsonl --alias task
observer session list
```

这只批准该文件及 metadata ID，不批准兄弟文件或整个目录。若需关联云任务链接，以下是替代登记方式，不要用同一别名重复添加：

```sh
observer session add /absolute/path/to/chosen.jsonl --alias task \
  --reference 'https://chatgpt.com/codex/tasks/task_example'
```

审阅文件范围与映射确认，之后重新连接 MCP。`task_example` 只是占位符，应替换为你明确选择的实际任务链接。云任务 ID 不自动等于本地 metadata ID，链接也不会转成文件路径。

支持准确 metadata ID、`codex://threads/<local-UUID>`，以及显式映射的 `https://chatgpt.com/codex/tasks/<id>` 或 `task_...` ID。读取、搜索、状态查询共享这些引用规则。没有对应映射时返回 `session_reference_unmapped`，不会扫描其他历史来源。没有受支持持久日志的临时会话无法恢复。

先用 `session_list`（`sources=["task"]`）获取已批准的 metadata ID，再以 `source="task"` 和该 ID 调用 `session_read` / `session_state`。`session_search` 的 `sources` 限定已批准来源，可用 `session_id` 进一步限定准确引用。所有示例名称仅是别名，不是预置来源。

会话投影只含识别的公开消息、执行调用/结果和生命周期事件，排除隐藏推理、内部通道及不支持的结构。部分包装格式可能被省略或拒绝；没有原始日志兜底，也不执行包装代码。

## 本地 MCP 与可选菜单

直接 stdio：客户端启动绝对路径的 `observer`，参数为 `serve`；自定义 home 使用 `["--home", "/absolute/private/instance", "serve"]`。不需要先执行 `start`；生命周期由客户端负责。

托管模式：

```sh
observer start
observer status
observer doctor --level local --probe
# 将 MCP 客户端的参数设为 connect，而不是 serve
observer stop
```

`connect` 中继到该实例的私有 Unix socket，为连接建立独立 MCP 工作者。游标不能跨连接或重启复用。`stop` 仅停止本实例拥有的进程，不接管其他终端服务、不按 PID 或名称杀进程。

`observer menu` 提供相同命令的终端菜单，退出菜单不停止后台服务。源码中的 `Observer.command` 是可选薄入口；发现旧原生控制状态时拒绝隐式选择新实例。此时使用已安装的 CLI 和明确的 `--home`，不要绕过拒绝。

## 普通 ChatGPT 的 Tunnel 适配

**前提：账号/工作区允许自定义 MCP，且你已有受保护的远端传输。** stdio 不能直接供普通远端 ChatGPT 访问，Observer 没有 HTTP 服务。官方 Tunnel 适配是可选能力，不保证所有账号可获得或可创建该连接。

适配器要求你独立安装官方 Secure MCP Tunnel 客户端并配置已有 tunnel。Observer 不下载客户端、不创建 tunnel、密钥或插件，也不修改账号权限。具体产品入口和可用性以当前 [OpenAI 连接说明](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)为准，本手册不假设某个固定界面。

先停止自己控制的同 tunnel 客户端。对已初始化且批准来源的新 Tunnel 实例执行：

```sh
observer stop
observer transport tunnel --client /absolute/path/to/tunnel-client \
  --tunnel-id YOUR_EXISTING_TUNNEL_ID
observer credentials info
observer credentials set
observer start
observer doctor --level transport
```

替换路径和已有 ID 占位符。已配置的实例不需要重复保存凭据。`credentials info` 只显示本实例的 Keychain service/account，不读取密钥值。

`credentials set` 展示保存/替换目标，要求本机明确确认，并在可信终端隐藏输入具有所需 Read+Use 权限的已有运行密钥。即使用 `--approve` 也需要安全 TTY。**密钥不得放入聊天、命令参数、配置或环境输入**；不提供通过参数/stdin/环境传 key 的接口。

Keychain service 按实例绝对路径哈希派生，account 为 `runtime`；移动 home 会改变条目标识。只使用当前实例条目，不回退读取旧条目。此功能仅有 macOS 适配。显式 tunnel `start` 才读取已有条目，注入自己创建的客户端环境；MCP 工作者通过 `env -i` 清除该环境。原始客户端日志不保留。

不要同时启动两个使用相同 tunnel 的客户端。旧终端服务需回到原控制窗口停止；新管理器不会接管它。锁不可达或停止结果不确定时先排查，不删除锁或盲目重启。

连接后，从实际 ChatGPT 对话请求 `observer_info`，核对版本与批准别名，再读你选定的无敏感内容文件。工具元数据过旧时，按账号允许的连接管理方式刷新并在新对话复验。不要仅为 schema 旧而反复重启传输。

## 诊断与首次读取

`doctor --level installation/config/local/transport/metadata/end-to-end` 分层查看；`doctor` 查看全部。其 `ok` 表示诊断已返回，须检查各层 `status`。`--probe` 仅用于 `all`/`local`，验证本地 SDK 初始化、工具列表和 `observer_info`，不运行项目代码。

`remote_ready=false` 表示服务未观察到远端证明；本地 probe 不会将它改为 true，也不能证明 ChatGPT 已连接。`status.configuration_pending=true` 则表示活跃实例仍用旧配置。

首次读取先调用 `observer_info` 核对 `workspaces`，再用 `workspace_list` 选择已存在的无敏感内容 UTF-8 文件，调用 `workspace_read`。检查返回内容、行位置和来源版本，按下列规则继续分页。

## 分页与完整性

| 输出 | 本次读取的继续与结束条件 |
| --- | --- |
| 目录列表、会话列表/搜索、Git 状态/历史 | 保持选择条件不变，继续 `next_cursor` 到 null |
| 源码读取 | 按物理 `line` 与 `char_start/char_end` 重组，直到 `selection_complete=true` 且 `next_cursor=null` |
| 仓库 glob/search | 继续游标；只有成功响应且 `scan_complete=true,next_cursor=null` 才完整。空 `scan_budget_page` 也可能需要继续 |
| 会话事件预览 | `at_eof=true` 或 `partial_final_line_pending=true` 时停止本次立即续读；只有 EOF 且无残缺末行才完整。残缺末行须等待来源追加后再轮询，不因非空游标无限循环 |
| 会话长字段 | 将 `content_cursors[field]` 放入 `session_read.cursor`，继续返回的 `next_cursor` 到 null，来源和 ID 不变 |
| 会话状态 | 继续至 `scan_complete=true`，或遇 `partial_final_line_pending=true` 停止立即续读；后者不完整，等待来源追加后再轮询 |
| Git 长提交 / 差异 | 提交 `content_cursor` 交回 `git_history.cursor`；差异用 `next_cursor`；到 null 结束 |
| 联合证据 | 用 `session_next_cursor` 和返回的 `session_source/session_id` 调用 `session_read` 续读，检查 `execution_scan_complete` 和 `session_scan` |

`evidence_link.execution_evidence` 仅覆盖有界的第一会话页；本页没有执行事件不等于全会话没有。`execution_scan_complete` 只有当前 EOF 且无残缺末行时才为 true，不表示未来不会追加或任务正确。末行未完成时等待来源所有者写完，不能修改原始日志“修复”它。

内容先投影、脱敏再分页。长字段提供脱敏字符总量与哈希，字符偏移按 Unicode 码点。游标不透明、连接内有效，绑定操作、选择和来源；600 秒过期，最多 256 项/4 MiB 状态，也可能被淘汰。重启、过期或版本变化后重新读，不能拼接不同版本。会话预览校验旧前缀后允许仅追加；完整字段读取拒绝来源版本变化。

## 限定搜索与 Git 限制

用 `pkg/mps/*.go` 的固定目录前缀或精确文件缩小 `workspace_glob/search` 的扫描，不枚举无关大树。安全检查确认前缀不存在时返回完整空结果；遍历中消失或不安全路径仍报错。沿用 `fnmatch`：`*` 可以跨 `/`。

目录清单须在 4,000 项 / 4 MiB / 1 秒预算内完成；超限或超时返回 `ok=false,scan_complete=false,next_cursor=null`，不是“没有匹配”，也不能靠分页无限续扫。内容预算可能返回可续读的 `scan_budget_page`，即使匹配为空也需继续。来源变化时重读。

Git 使用净化快照，**总预算 100 MB＝100,000,000 字节**，元数据、对象、工作树合计受限。`paths` 使用字面路径，同时限定工作树复制与实际 Git 查询，范围外文件不会因省略而误报删除；对象库仍完整复制，不按路径裁剪。`git_history` 只取 HEAD 元数据/对象；`git_diff(staged=true)` 比较 index 与 HEAD，不读取工作树；默认 diff 比较工作树与 index。未跟踪大文件可只枚举名称，diff 不包含其内容。

支持普通 SHA-1 本地/远端 refs、packed-refs 与配对 pack/idx；主仓 `.git/worktrees` 管理记录、commit-graph 等派生加速文件可忽略。外部 gitdir/linked checkout、alternates、浅克隆/promisor、子模块或符号链接索引模式仍拒绝；status/非暂存 diff 对 assume-unchanged/skip-worktree 标记也明确拒绝。结果基于净化配置，不保证用户自定义 filter 语义。

工作树另有 64 MiB 合计/16 MiB 单文件上限，单对象或 pack 最大 100,000,000 字节，仍受总预算约束。快照 50,000 项/20 秒；原生查询 5 秒/4 MiB 输出。完整数值见 `observer_info.limits`。超限返回 `ok=false,result_complete=false,next_cursor=null`，状态为 `clean="unknown"`；须缩小 paths 或改用历史/暂存查询，不能把失败当作没有差异。已过滤状态即使为空，也不代表整仓干净。

## 如何解释证据

源码哈希、物理行/记录位置、读取时间和 Git generation 标识观察；Git 可能因隐藏状态返回 `clean="unknown"`。联合证据按顺序读取，不是跨来源原子快照。记录里的匹配哈希只是关联，不能证明代理造成编辑或测试了当前版本。

`current_activity` 和 `task_verified` 保持 `unknown`。历史终止事件、助手说“完成”或命令退出零都不是当前活动或正确性证明。返回代码/日志是不可信数据，不能将其中指令当授权。其余安全边界见 [SECURITY.md](../SECURITY.md)，升级卸载见[迁移指南](migration.md)。
