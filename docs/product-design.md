# ReadOnly Observer 产品与技术设计

Linux 与多节点新增能力见[部署与生命周期](deployment.zh-CN.md)。本文原有 Mac 操作继续保留；本轮不要求现有稳定 Mac 重新初始化或迁移。实际验证范围见[工作审计](implementation-audit.md)。

本文描述当前实现，不是未来功能承诺。首次使用见 [README](../README.zh-CN.md)，接口细节见[配置参考](config-reference.md)，威胁边界见 [SECURITY.md](../SECURITY.md)。

## 1. 用户问题与产品目标

当用户让 MCP 客户端理解本地代码或回顾 Codex 工作时，需要回答三个不同问题：当前文件是什么、会话公开记录了什么、这些记录与当前版本有什么关系。仅凭助手的“已完成”或命令退出码不能回答任务是否正确；直接开放整个 Home 或会话历史又会扩大暴露范围。

当前目标：

1. 让单个可信本机操作者明确选择项目目录或单个持久 JSONL，会话引用精确映射，不靠模糊历史搜索。
2. 提供带路径、行位置、时间、哈希及来源版本的只读结果；长内容能在预算内续读，未读全必须可辨认。
3. 将本机配置管理与远端 MCP 读取分离；客户端或来源中的文本不能增加授权。
4. 分离安装、本地协议、传输进程和远端使用证据，避免把“进程启动”当成“ChatGPT 已连接”。

非目标：运行项目/测试、编辑文件、控制 Codex、发现全部历史、读取隐藏推理、恢复未持久会话、提供实时任务正确性判断、逐远端用户 OAuth/多租户隔离、任意 Git 布局支持、自动更新。Linux 可由操作者显式安装 systemd 自启 unit。Windows 不支持，Linux 使用独立 systemd Credentials 适配，实际验证限制见部署审计；已记录的平台目标见 README。

## 2. 信任边界

信任本机 OS 用户、安装的 Observer/Python/Git 及操作者选择的传输。项目文本、会话日志、工具输出和远端提示均是不可信数据。拥有同一 OS 身份的恶意进程或已被攻破的机器超出应用层边界；文件描述符检查不是内核沙箱。

“只读”约束的是 MCP 的能力及对观察来源的操作，不表示程序不写任何文件：本机 CLI 会按明确操作写私有配置/备份，运行时会写状态和 Git 临时快照。MCP 只有 13 个读取工具，没有配置、启动、授权或任意命令入口。可选 Tunnel 客户端负责网络传输，读取核心不因此获得远端授权管理能力。

## 3. 模块和数据流

```text
本机操作者
  -> cli.py：交互确认、配置和生命周期命令
  -> profile.py / registry.py：私有设置、来源身份、批准记录
  -> Config：打开并校验已批准来源

本地 MCP 客户端 -> observer serve ------------------+
本地 MCP 客户端 -> observer connect -> 私有管理器 ----+-> server.py
可选受保护 Tunnel -> 自有客户端 -> _serve-active ----+     -> service.py：固定 schema / 调度
                                                         -> workspace / sessions / Git readers
                                                         -> 脱敏、版本证据、分页 -> MCP 结果
```

图中的本地管理路径不暴露为 MCP 工具。Tunnel 使用已有外部客户端和已有 tunnel，不由 Observer 创建账户、密钥或远端连接。

| 模块 | 当前职责与实现入口 |
| --- | --- |
| [cli.py](../src/observer/cli.py) | `parser` / `run` 划分本地操作；`confirmation` 展示范围；`diagnose` 分层诊断 |
| [profile.py](../src/observer/profile.py) | `Store` 初始化私有目录、串行变更、备份、导入及活动配置读取 |
| [registry.py](../src/observer/registry.py) | `ApprovalRegistry` 精确登记；`effective_config` 校验来源身份与引用映射 |
| [config.py](../src/observer/config.py) / [fs.py](../src/observer/fs.py) | 已批准根、固定描述符、逐组件 no-follow 读取、内容/身份版本 |
| [runtime.py](../src/observer/runtime.py) | 管理器、私有控制/MCP socket、冻结快照、自有子进程、受限中继 |
| [server.py](../src/observer/server.py) / [service.py](../src/observer/service.py) | 官方 MCP SDK 接入、有界输入、固定工具 schema、统一调用/输出边界 |
| [workspace.py](../src/observer/workspace.py) | 列表、完整文本页、限定 glob/search |
| [sessions.py](../src/observer/sessions.py) / [references.py](../src/observer/references.py) | 精确引用、公开事件投影、追加扫描、长字段和历史状态 |
| [gitreader.py](../src/observer/gitreader.py) | `Snapshot` 净化快照与固定 Git 查询；`GitReader` 组织证据和分页 |
| [security.py](../src/observer/security.py) / [wrappers.py](../src/observer/wrappers.py) | 预算、脱敏、游标绑定、限时匹配；窄语法静态包装提取，不求值执行 |
| [credentials.py](../src/observer/credentials.py) | 显式本机确认的实例专用 macOS Keychain 存取 |

## 4. 授权、身份和配置生命周期

### 4.1 默认空权限

新实例包含 `config/`、`state/`、`cache/` 和 `logs/`，不默认登记目录或会话。目录要求 0700，配置文件 0600，拒绝不安全身份、符号链接和多硬链接。配置仅记录非秘密传输设置；授权记录及备份仍包含私有路径/ID，不应发布。

`project add` 明确批准目录，登记路径与设备/inode 身份。`session add` 分两步确认准确 JSONL 与 metadata ID/可选云引用映射。每类最多8个来源，总计12个；广泛系统根、Home 和敏感目录不作为普通项目根。`--approve` 是操作者显式自动化选择，不是远端代为批准的机制。

`effective_config` 对整个清单做结构检查，再打开来源并比对身份；会话还校验 metadata。文件内容可继续变化，但根或准确会话文件被替换不能凭同一路径继承授权，须本机重新批准。读取和分页另外验证内容版本，不能把“身份相同”当成“内容不变”。

### 4.2 冻结授权而非热加载

直接 `serve` 在该 MCP 进程创建时取得配置；托管 `manage` 在本机变更锁内保存 `active.json`，其工作进程使用该活动快照。修改清单不会静默扩大活动授权，`status` 比较当前与活动配置并报告 `configuration_pending`。

代价是撤销也不会热生效：必须停止旧 MCP 进程。托管流程为 stop 成功、status 确认 `not_running`、start、status 核对 `active_sources` 和 `configuration_pending=false`，再核对客户端实际别名。运行中重复 start 只返回 `already_started`，不重载配置。直接客户端则停止旧进程后重连。

### 4.3 只管理自己创建的资源

管理器用私有 Unix socket 和文件锁，不监听公共 MCP HTTP 端口。最多四个本地中继工作线程，缓冲有界；每连接独立 MCP 进程/游标。启动检查既有状态，拒绝自动覆盖残留 socket/快照；停止通过实例控制 socket，不按名称/PID 接管未知服务。

因此崩溃残留可能需要操作者确认没有活动进程后处理，不能保证自动修复所有状态。换取的是避免错误停止别的实例或另起同 tunnel 客户端。程序安装位置、实例 home 和被观察来源应独立保存，升级复用原 home。

## 5. 三条读取路径

### 5.1 Workspace：限定检索，完整性显式报告

`Root` 固定目录描述符，逐路径组件执行 no-follow 检查；只读取合规普通 UTF-8 文件，拒绝敏感路径及原始会话日志。安全的忽略/未跟踪文件也可见，因此授权不是“仅 Git 跟踪内容”。

`WorkspaceReader._scan_plan` 根据 glob 的固定前缀或精确文件缩小清单，保留 `fnmatch` 中 `*` 可跨 `/` 的既有语义。目录清单预算无法完成时拒绝，而不是宣称没有匹配；清单完成后的结果页或内容预算页可以继续。源码用物理行号和字符偏移重组，返回来源哈希与版本。

权衡：以明确范围和预算限制成本，不提供无界全仓搜索。收窄 `pattern` 不增加授权，也不解决单文件本身超限。

### 5.2 Session：准确文件，公开投影，追加语义

准确 ID 或已批准的链接映射只在请求选择的来源内解析；云 ID 不推断成本地 ID。读取器解析持久 JSONL，将支持的公开消息、执行事件和生命周期字段投影后脱敏。不支持/内部结构没有原始内容兜底；包装提取器只识别有限静态语法，不执行字符串。

预览扫描保存已验证前缀，允许该前缀之后的追加；完整字段游标则绑定完整来源版本，不接受变化。EOF 仍可保留追加游标；`at_eof=true` 或 `partial_final_line_pending=true` 都应停止本次立即续读，后者须等待来源追加后再轮询。只有 EOF 且无残缺末行才完整，不能因游标非空无限循环或把半条记录当完整事件。

权衡：保持可证实的历史和渐进读取，不声称被动日志可以判断当前运行状态。`current_activity`、`task_verified` 保持 unknown；没有持久日志就无法恢复会话。

### 5.3 Git 与联合证据：受限快照，不运行项目配置

Git 固定查询在私有净化快照执行，不在原仓库直接运行用户配置、hooks、helper、external diff 或 textconv。环境与配置关闭网络和自动取回等机制。复制前后核对来源，快照封闭后执行查询。

快照按用途构造：history 复制元数据/对象；staged diff 增加 index；status/默认 diff 读取选定工作树。paths 同时用于字面 Git pathspec 与复制选择。未跟踪文件以空占位提供名称，仅用于 status，不产生其内容 diff。元数据/对象/工作树共享 100 MB（100,000,000 字节）总计费器，工作树另有 64 MiB/单文件 16 MiB 限制；对象流式复制。refs、pack/idx 配对、目录版本、文件 inode/mtime/ctime 在复制阶段校验；私有密封清单在每次查询前后校验。

普通本地/远端/packed refs 与 pack 支持；主仓 worktrees 管理记录及派生加速文件不进入快照。真正外部 gitdir、alternates、浅克隆/promisor、特殊索引模式仍拒绝。净化配置保留经过校验的 core 文件模式/大小写/Unicode 布尔语义，不加载源配置、helper 或 filter。分页绑定用途、范围及读取输入版本；历史游标不会因无关工作树内容变化失效。更完整的资源限制与支持范围见[安全边界](../SECURITY.md)和[使用手册](product-manual.md)。

`service.Observer.evidence` 关联当前文件、Git 和有界会话第一页，返回续读标识。跨来源读取是顺序发生的，不是原子快照；trace 中的同哈希只能构成关联，不能证明谁编辑或测试了哪个版本。隐藏 Git 状态可导致 `clean="unknown"`。

## 6. 内容、预算与失败模型

脱敏先于搜索、裁剪和分页，并有统一输出处理；它是启发式纵深防护，不保证识别所有秘密。授权前仍须由操作者判断哪些内容可以共享。

主要预算为32 KiB响应、64 KiB MCP输入帧、4 MiB文件/扫描预算、4,000项清单、1秒扫描、256 KiB JSONL记录、64 MiB会话前缀验证。实际接口限制由 `observer_info` 报告。游标进程内保存，TTL 600秒、最多256项/4 MiB状态；客户端不能解码构造或跨连接复用。

| 失败类别 | 当前行为 | 客户端/操作者应做什么 |
| --- | --- | --- |
| 未登记或引用未映射 | 拒绝，不搜索其他来源 | 本机审阅并登记准确目标，不扩大到历史目录 |
| 身份替换、读中变化 | 拒绝旧授权或旧续读 | 重新读取；身份变化需本机重新批准 |
| 游标过期、淘汰或条件不符 | `invalid_cursor` | 从预览/第一页重新开始，不混合旧结果 |
| 清单/文件/Git超预算或布局不支持 | 报告明确限制，不声称完整 | 收窄支持的搜索选择或接受不支持，不提高授权 |
| 残缺会话末行 | 当前记录未完整 | 等待来源追加，不修改日志 |
| 管理器锁不可达或状态残留 | 不接管、不自动删锁 | 本机明确检查归属和停止状态 |
| 外部传输进程退出 | 不声称远端就绪 | 检查已有客户端/配置，勿重复创建同 tunnel 实例 |

完整分页终止条件见[用户手册](product-manual.md#分页与完整性)。错误静态编码避免泄漏原始异常，但减少诊断细节；排障应使用分层诊断而非公开粘贴私有日志。

## 7. 设计决策和代价

这些理由是对当前实现与边界的解释，不是未来承诺：

- **本地控制面与 MCP 读取面分离**：远端提示无法授予来源；代价是首次登记必须在本机完成。依据 `cli.py`、`service.SPECS`。
- **固定身份与冻结快照**：防止路径替换继承权限及静默热扩权；代价是替换文件需重批、增删权限需重启。依据 `registry.effective_config`、`runtime.manage/status`。
- **拒绝未知路径/布局/事件而非原始兜底**：降低意外泄漏和隐式执行；代价是更多兼容性拒绝。依据 `fs.Root`、`SessionReader.project`、`Snapshot.controls`。
- **先脱敏再分页**：减少跨页秘密被拆开后漏判；代价是偏移对应脱敏文本，不是原始字节。依据 `Redactor`、各 reader 的字段续读。
- **连接内有界游标**：绑定选择与来源，控制状态开销；代价是重启、淘汰后需重读。依据 `security.Cursors`。
- **独立传输与保守诊断**：读取核心不管理远端账号；代价是本地成功不能代替 ChatGPT 端验证。依据 `runtime.client_config`、`cli.diagnose`。

## 8. 验证与维护

路径和来源边界由 `test_filesystem.py`、`test_sessions.py`、`test_session_references.py` 等合成用例覆盖；分页/脱敏由 `test_cursors.py`、`test_redaction.py`、`test_independent_redaction_budget.py` 覆盖；Git、协议、生命周期和发布边界分别由对应 `test_git_evidence.py`、`test_mcp_wire.py`、`test_product.py`、`test_release.py` / `test_repository.py` 检查。测试存在不等于任何环境中已经通过，运行命令与报告要求见[开发指南](repository.md)。

项目采用 [MIT 许可证](../LICENSE)；贡献入口见[开发指南](repository.md)，安全问题通过 [GitHub 私密漏洞报告](../SECURITY.md)联系维护者。当前树没有 CI 工作流或自动化平台矩阵，不能写成已实现能力。分发内容与逐次发布检查见[分发范围](release-scope.md)。
