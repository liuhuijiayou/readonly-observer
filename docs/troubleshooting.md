# 故障排查

Linux 与多节点新增能力见[部署与生命周期](deployment.zh-CN.md)。本文原有 Mac 操作继续保留；本轮不要求现有稳定 Mac 重新初始化或迁移。实际验证范围见[工作审计](implementation-audit.md)。

先运行 `observer doctor`，再针对失败层操作。它不会检查真实 Keychain 值、自动登录、修改系统权限或启动真实 tunnel。原始异常和日志被抑制以避免秘密回显。

| 现象/错误 | 下一步 |
| --- | --- |
| 找不到 observer | 使用安装环境的 `.venv/bin/observer`；`--help` 确认实际命令 |
| not_initialized | 同一 `--home` 执行 `init`；不会自动授予任何来源 |
| no_sources_registered | 在本机登记你明确批准的项目或精确 JSONL |
| local_approval_required | 阅读本机预览，交互输入 approve；脚本仅在你已明确决定时加 --approve |
| private_* / unsafe_* | 不接受公开目录、symlink、多硬链接或不安全文件权限；选择你拥有的私有实际路径，不由工具自动 chmod 既有文件 |
| instance_path_too_long_for_unix_socket | 使用更短、无符号链接的 `--home`；其他实例不会自动迁移 |
| project_not_approved / session_not_found | 只接受已登记的精确目录或 metadata ID；远端提供路径不授权 |
| invalid_session_reference / session_reference_unmapped | 检查支持的精确 ID/link；cloud ID 需要本机明确映射；不扫描全部历史 |
| source_changed | 丢弃旧分页结果，从第一页重新读；需要换 inode 时先本机重新批准 |
| invalid_cursor | 句柄过期、重启、淘汰、跨连接或绑定不符；重新取得预览和新句柄 |
| configuration_pending=true | 活跃实例仍用旧授权快照；协调停止后再启动，撤销也是如此 |
| already_started / already_stopped | 幂等返回；不是远端可用证明 |
| unreachable_lock_held / manager_unreachable | 不接管或按 PID 杀进程；回到原操作者控制窗口确认进程状况 |
| stale_runtime_requires_explicit_local_review | 异常中止残留；先由你确认此实例无运行进程，再审阅 state 中残留。工具不自动删除或覆盖 |
| transport_process_exited | 检查你独立安装的官方客户端及非秘密设置；工具不保留原始客户端输出或自动修复授权 |
| Keychain 不可用/缺项 | Mac 用 info 识别条目，只有你亲自确认后 set；不从其他条目回退。Linux 不调用 Keychain，须检查 Credentials 上下文 |
| 本地 probe 成功但 ChatGPT 失败 | 分别检查传输、连接元数据和公开标记端到端；不要仅据进程反复重启 |
| 旧 session_read 没有 field/detail_cursor | 使用预览的 content_cursors.output 作为原 cursor，逐页 next_cursor；或操作者刷新自定义连接元数据 |
| glob/search: scan_limit / scan_timeout / scan_limit_narrow_selection | 本次选择未扫描完成；用固定目录前缀或精确文件收窄 pattern，保留原批准根；没有续扫游标时不能声称空结果或读全 |
| search: scan_budget_page=true 且 next_cursor 非空 | 内容字节预算产生可续读页；即使 matches 为空仍继续 cursor，直至 scan_complete=true |
| file_limit / unsupported_* | 已达文件/Git安全边界或布局不支持；保留限制，不宣称读全 |

Linux 尚未端到端验证，Windows 明确不支持；macOS Keychain、GUI 或本机 stdio 成功不表示其他平台同等可用。无法恢复未持久化的 ephemeral 会话；JSONL 不提供可靠的当前运行状态或任务正确性。


## 会话检索与证据

`session_reference_unmapped`：先由本机操作者为其选定的精确 JSONL 文件登记准确云链接；不要自动扫描历史。ID、链接和 sources/source 在分页中保持不变。

联合证据只含最初有界会话页：execution_scan_complete=false 时继续 session_next_cursor 到 session_read；不得把本页没有执行事件解释为整段会话没有执行。预览 EOF 仍有追加轮询游标，遇 at_eof=true 或 partial_final_line_pending=true 时停止本次立即续读；只有前者为 true 且后者为 false 才完整。末行尚未写完时等待来源所有者写完后再追加读取，不强行修复原始日志。

ChatGPT 接入条件与传输说明见[中文 README](../README.zh-CN.md#接入普通-chatgpt)与[英文 README](../README.md#connect-chatgpt)。本地 protocol verified 不等于远端连接、元数据或真实会话已验收。

## Git 快照拒绝

- `git_snapshot_byte_limit` / `git_snapshot_file_limit`：达到 100 MB 总量或分项上限。用 paths 收窄工作树，或仅请求 history / staged diff。对象库仍须完整容纳；不要改观察仓库来绕过限制。
- `git_snapshot_entry_limit` / `git_snapshot_timeout` / `git_timeout` / `git_output_limit` / `git_pathspec_limit`：达到枚举、创建、执行、输出或参数上限。收窄请求后重试；分页不延长一次 Git 执行的预算。
- `source_changed`：HEAD、refs、index、对象或所读取工作树版本改变；重新获取第一页，不能拼接旧游标。
- `git_pack_pair_incomplete`：pack/idx 不配对，可能正在 repack；待外部操作稳定后重试。
- `unsupported_git_index_flags`：选中索引含 assume-unchanged/skip-worktree，状态或工作区 diff 不受支持；history/staged diff 可独立尝试。

普通远端 refs 和主仓库的 `.git/worktrees` 管理目录受支持；linked checkout 的外部 gitdir、alternates、shallow/promisor 仍不受支持。`ok=false` 是读取失败，不能等同没有差异。
