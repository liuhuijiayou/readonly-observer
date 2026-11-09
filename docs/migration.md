# 升级、回退与卸载

Linux 与多节点新增能力见[部署与生命周期](deployment.zh-CN.md)。本文原有 Mac 操作继续保留；本轮不要求现有稳定 Mac 重新初始化或迁移。实际验证范围见[工作审计](implementation-audit.md)。

安装起点见 [English README](../README.md) / [中文 README](../README.zh-CN.md)。以下操作只针对自己拥有的安装与实例；源码变更不会自动更新已经安装的程序。

## 同实例切换程序版本

0.1.0 是公开版本号的起点，使用 format 1 配置。版本号调整不会自动替换已有安装。需要切换程序时，将新版本安装到**新程序目录**，保留旧安装和安装材料；在配置 schema 相同的前提下，沿用相同的实例 home、授权和凭据身份。不要重新 `init`、登记来源或运行 `credentials set`。

以下路径是占位符，替换为实际安装位置：

```sh
OLD_OBSERVER="/absolute/path/to/old-install/bin/observer"
NEW_OBSERVER="/absolute/path/to/new-install/bin/observer"
OBSERVER_INSTANCE="$HOME/Library/Application Support/ReadOnlyObserver"
"$NEW_OBSERVER" --version
"$NEW_OBSERVER" --home "$OBSERVER_INSTANCE" config validate
# 在你协调好的切换窗口执行：
"$OLD_OBSERVER" --home "$OBSERVER_INSTANCE" stop
"$OLD_OBSERVER" --home "$OBSERVER_INSTANCE" status
# 仅在 manager=not_running 后继续：
"$NEW_OBSERVER" --home "$OBSERVER_INSTANCE" start
"$NEW_OBSERVER" --home "$OBSERVER_INSTANCE" doctor --level local --probe
```

这组命令用于托管模式。直接使用 `serve` 的客户端，应先停止其旧 MCP 进程，更新绝对可执行路径，再重新连接；不必改成托管模式。所有客户端都须指向原 home。

停止结果不确定时先排查，不启动同 tunnel 的第二个客户端、不删除锁、不按进程名杀进程。新入口 `--version` 只证明磁盘版本，本机 probe 只证明本地协议。

从实际 MCP 客户端核对 `observer_info.version`、批准别名、文件读取与分页；如使用 ChatGPT，须从实际 ChatGPT 连接复验。旧游标不能跨重启使用。`remote_ready=false` 不会因本地 probe 成功变成远端成功。

## 回退

先用新入口停止并确认 `manager=not_running`，再用旧入口和**同一 home** 启动：

```sh
"$NEW_OBSERVER" --home "$OBSERVER_INSTANCE" stop
"$NEW_OBSERVER" --home "$OBSERVER_INSTANCE" status
# 确认已停止后：
"$OLD_OBSERVER" --home "$OBSERVER_INSTANCE" start
```

直接 stdio 客户端则停止新进程并改回旧可执行路径。重新核对客户端实际版本和读取结果。同 schema 的程序切换不需要恢复授权文件或迁移 Keychain；仅保留旧目录不会启动另一实例。

## 旧入口与格式迁移

公共入口为 `observer` CLI；`menu` 复用相同实现。`Observer.command` 是可选源码安装薄入口，发现旧原生控制状态时拒绝隐式切换。使用已安装 CLI 显式指定 `--home`；新管理器不能接管旧终端进程。

内部测试阶段的旧配置格式可迁移到新空实例，逐项明确批准项目和精确 JSONL，或显式导入已审阅配置：

```sh
observer config import /absolute/path/to/reviewed-legacy-config.json
```

导入有预览、确认、备份和整批失败回滚；没有精确 `session_files` 的宽泛历史来源拒绝导入。原始日志和旧 Keychain 项不自动迁移。相同 tunnel 的旧客户端应在原控制窗口停止后，才启动新实例；不要并行争用。

## 配置 schema 与备份

`config upgrade` 仅支持明确的 `{format:0,transport:{kind:stdio}}` 空权限设置升级为 format 1，备份设置和授权，不扩大权限；未知格式拒绝且文件不变。当前 format 1 是 no-op。来源/传输变更留存备份，在新 MCP 进程生效。

没有自动恢复授权命令。必要时由操作者确认所有旧进程已停止后审阅并恢复选定备份，保持 0600/0700 权限、校验原来源身份。不要从聊天、未知清单或日志生成授权。

## 卸载

先停止托管实例和直接 stdio 客户端，再查看卸载计划：

```sh
"$OBSERVER" stop
"$OBSERVER" uninstall
```

`uninstall` **只输出计划，不删除文件、来源或凭据**。源码虚拟环境中可执行：

```sh
.venv/bin/python -m pip uninstall local-readonly-observer
```

对于离线安装，使用该安装的 `runtime/bin/python -m pip uninstall local-readonly-observer`，而不是系统 Python。审阅剩余程序文件后再手动移除相应安装目录，不要误删实例 home。

实例、授权备份、项目和会话文件应分别决定保留。`credentials info` 只标识本实例 Keychain 项；若不再需要，由拥有者单独处理。删除本地条目不等于撤销远端权限，程序卸载也不自动撤销远端连接。
