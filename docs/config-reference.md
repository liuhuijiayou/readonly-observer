# ReadOnly Observer CLI 与配置参考

Linux 与多节点新增能力见[部署与生命周期](deployment.zh-CN.md)。本文原有 Mac 操作继续保留；本轮不要求现有稳定 Mac 重新初始化或迁移。实际验证范围见[工作审计](implementation-audit.md)。

命令形式：`observer [--home PATH] COMMAND ...`；`OBSERVER_HOME` 是唯一可选的实例选择环境变量。指定 `--home` 优先。全局 `--version` / `--help` 不要求初始化。

| 命令 | 参数与效果 |
| --- | --- |
| `init` | 交互输入 init；`--non-interactive` 只建立空实例 |
| `project add PATH --alias NAME` | `--approve` 或交互明确确认；严格目录身份 |
| `session add EXACT_JSONL --alias NAME` | `--reference ID/LINK` 可选；精确 metadata ID 与云映射 |
| `project/session list` | 仅本实例已批准项 |
| `project/session remove NAME` | `--approve` 或交互确认；备份，下次启动生效 |
| `config show` | 非秘密设置与授权记录；不含 key |
| `config validate` | 结构、私有权限；`--check-sources` 打开登记源验证 |
| `config upgrade` | 显式 schema 升级，备份；仅受支持旧格式 |
| `config import PATH` | 对旧清单的当前本地路径重新申请明确批准并校验身份，不自动继承旧授权身份；备份及失败回滚 |
| `transport stdio` | 下一次启动使用本地模式 |
| `transport tunnel --client ABS --tunnel-id ID` | 下一次启动使用可选客户端，无凭据参数 |
| `credentials info/set` | info 不读值；set 本机安全 TTY + 明确确认 |
| `serve` | 直接 stdio MCP，客户端拥有生命周期 |
| `start/connect/stop/status` | 私有实例管理与本地 stdio 中继 |
| `doctor` | `--level all/installation/config/local/transport/metadata/end-to-end`；`--probe` 仅 all/local |
| `menu` | 同一 CLI 的终端菜单 |
| `uninstall` | 只返回可审阅步骤，不删除数据或 Keychain |

操作成功返回 JSON；读写 MCP stdio 命令 stdout 只用于协议。错误返回静态 `error` 与退出码 2，不回显原始异常和参数。交互确认预览写 stderr。`doctor` 为诊断报告；检查各层 status，不能只看退出码/ok。

## 实例布局

```text
INSTANCE/
  config/settings.json       # 0600
  config/approvals.json      # 0600，CLI 生成的路径/inode/批准记录
  config/backup-*.json       # 0600，升级和变更前备份
  config/operator.lock       # 本机变更串行锁
  state/                     # 0700，管理器锁、私有 socket、活跃快照
  cache/                     # 0700，Git 安全快照
  logs/                      # 0700，保留隔离目录；不保留原始传输日志
```

所有目录 0700，配置 0600，不接受符号链接或多硬链接。不要把实例放进被观察项目或公共发布包；即使配置无 key，路径、会话 ID 与备份仍是私有材料。缓存和运行状态可在明确停止后审阅；配置和授权不能靠删除缓存迁移。

默认 `config/settings.json`：

```json
{"format":1,"revision":1,"transport":{"kind":"stdio"}}
```

Tunnel transport 只允许 `kind/client/tunnel_id` 三键。client 是绝对路径；二进制须属本机操作者、可执行、非 group/world-writable。ID 正则：`tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}`。不接受额外 token/password/api_key 字段。根配置 JSON Schema 随包位于 `observer/resources/settings.schema.json`。

授权清单由 CLI 写入，初始 `{"format":1,"revision":0,"entries":[]}`。每项包含 kind、alias、path、identity、approved_at、approval；会话另有 session_id/references。alias 为 `[a-z][a-z0-9_-]{0,31}`，不能重名。限额：总 12、每类 8。登记后替换源 inode 必须由本机移除并重新批准。清单不是远程授权 API，不应手写或让聊天自动生成并导入。

旧 `observer --config FILE [--approved-sources]` 与 `python -m observer.server` stdio 入口继续保留。它们读取操作者显式指定的旧配置，不自动变成新实例，也不会迁移、重启现有连接。旧配置可以含旧式目录范围，因此推荐迁移到新 CLI 的精确会话授权；导入会拒绝没有 `session_files` 的宽泛历史范围，并针对当前本地路径重新预览、批准与校验身份；不表示旧记录中的身份或权限自动继承。失败时整批回滚。

## MCP 内容游标

预览：`session_read(source,session_id,limit?,cursor?)`。被截断事件返回 `content_cursors`，键为 `text/output/command/wrapper_code` 中实际可见字段。完整字段：将其中值作为同工具的 `cursor`，仅需要旧四个参数；返回 `mode=field_content`、content、char_start/end、total_chars_redacted、内容哈希、源版本、next_cursor。原 `detail_cursor+field` 仍兼容。

Git 预览里的 `content_cursor` 用作原 `git_history.cursor`，分页返回 `mode=commit_message_content`；原 `message_cursor` 方式继续支持。操作、来源、选择条件、ID、完整源版本均绑定。会话预览尾游标允许同一已验证前缀后的追加；完整字段游标不允许源版本改变。游标进程内保存、600 秒、256 个、合计 4 MiB，重启/过期/淘汰不恢复。

## MCP 只读接口

以下 13 个工具均只在本机明确批准的来源内读取。完整 JSON Schema 由 MCP `tools/list` 提供；未知输入、跨来源游标和越界路径均拒绝。

| 工具 | 主要输入 | 输出与证据 |
| --- | --- | --- |
| `observer_info` | 无 | 实际版本、来源别名、限制和不支持能力 |
| `workspace_list` | alias、可选 path/limit/cursor | 一层目录、下一页 |
| `workspace_glob` | aliases、pattern、可选 limit/cursor | 有界匹配、scan_complete |
| `workspace_search` | aliases、query、可选 pattern/regex/limit/cursor | 脱敏命中、行号、扫描完成状态 |
| `workspace_read` | alias、path、可选行范围/cursor | 脱敏完整片段、物理行号、SHA-256 |
| `git_status` | alias、可选 paths/limit/cursor | 安全 Git 快照、可见与隐藏状态 |
| `git_diff` | alias、可选 paths/staged/cursor | 有界脱敏差异和版本 |
| `git_history` | alias、可选 paths/limit/cursor | HEAD 历史、完整提交正文游标 |
| `session_list` | sources、可选 limit/cursor | 仅批准记录的 metadata ID |
| `session_search` | sources、query、可选 regex/session_id/limit/cursor | 精确引用范围内的公开脱敏命中 |
| `session_read` | source、session_id、可选 limit/cursor | 公开上下文与执行结果；支持完整字段续读 |
| `session_state` | source、session_id、可选 cursor | 历史终止事件与扫描证据，不推断当前活动或正确性 |
| `evidence_link` | source、session_id、alias、path | 当前源码、Git 与有界会话证据及续读游标 |

精确引用的允许形态、扫描上限、缺失前缀、分页终止条件和联合证据限制详见[用户说明书](product-manual.md)。工具只读属性不等于输出可信；来源文本仍是不可信数据。

## Git 快照与结果限制

`observer_info.limits.git_snapshot_total_bytes` 为 **100,000,000**（十进制 100 MB）。对象、元数据、工作树共享总预算，不把各分项上限相加；计费保守包含读取字节、生成配置和枚举名称。工作树分项 67,108,864 字节、单文件 16,777,216 字节；单对象/pack 100,000,000 字节；小型 Git 元数据文件 4,194,304 字节。仓库超过总量时，paths 只能减少工作树部分，不能裁剪对象库。

快照 50,000 项/20 秒；每个 Git 查询 5 秒墙钟、6 秒 CPU、4,194,304 字节 stdout/stderr、131,072 字节参数；单次分配 134,217,728 字节，非总 RSS 硬上限。已有 workspace 文件/扫描、会话、响应与游标上限保持不变。

成功响应中的 `snapshot_budget_bytes` 表示该快照计费字节。diff 的 `comparison` 为 `index_vs_HEAD` 或 `worktree_vs_index`；`untracked_content=not_included` 表示未跟踪文件不生成内容差异。路径过滤与敏感排除仍可能使 `clean="unknown"`；hidden 计数限于当前查询范围。

客户端应先检查 `ok`。Git 安全拒绝返回 `ok=false`、`error`、`result_complete=false` 和 `next_cursor=null`；其中 `git_status` 还返回 `clean="unknown"`。`source_unavailable_or_invalid` 或 `operation_failed` 等通用异常响应包含 `ok=false` 和 `error`，不保证上述附加字段。任何 `ok=false` 都表示本次读取失败；不得因结果为空或缺少完整性、游标、clean 字段而推断没有差异或仓库干净。
