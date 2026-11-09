# macOS / Linux 独立节点部署与生命周期

同一个仓库、Python **3.14+**、相同的 13 个只读 MCP 工具。每台机器只读取本机明确授权的数据；每个同时在线的实例使用独立 home、Tunnel ID 和独立签发的 Runtime Key。不存在中央 Observer、中央文件服务器或远程授权入口。同机多实例通过不同 `--home` 区分。

本轮重点是 Linux 适配。Mac 原有 `profile.py`、`credentials.py`、`runtime.py`、`server.py` 保持不变，默认目录、settings v1、授权记录、Keychain service/account 和现有 Tunnel 启动路径保留。**现有稳定 Mac 无需重新初始化、重新授权、迁移凭据或重新安装。** 没有连接或操作 Mac，没有发布。当前验证证据见[工作审计](implementation-audit.md)，完整英文说明见 [English deployment](deployment.md)。

systemd 219–246 使用受限 RuntimeDirectory 暂存后端，见[版本专用部署与安全差异](systemd219.md)。这取代原来的 247+ 最低要求；Manager 的 Provider 不回退读取源文件。

## 架构与配置

ChatGPT 分别连接 `codex-observer-mac`、`codex-observer-linux1`、`codex-observer-linux2`。每个连接指向对应 Platform Tunnel，由该机器上的 Client 连接本机 MCP。Linux 的客户端通过私有 manager 中继到共享读取核心；Mac 继续使用已有启动实现。

CLI 仅在 Linux 按需导入 `linux*` 模块。公共改动限于可选节点身份、Linux 专用 Git 配置和目录竞态复核，不改变 MCP 工具名或参数：

`observer_info`、`workspace_list`、`workspace_read`、`workspace_glob`、`workspace_search`、`session_list`、`session_read`、`session_search`、`session_state`、`git_status`、`git_diff`、`git_history`、`evidence_link`。

原有 `config/settings.json` 与 `config/approvals.json` 格式不变。Linux 增加：

| 路径 | 内容及边界 |
| --- | --- |
| `config/node.json` | 随机公开节点 ID、公开显示名、active/retired 状态 |
| `config/linux.json` | 可选 `{"format":1,"proxy":true}`；未配置时 proxy=false |
| `credentials/runtime`、`credentials/proxy` | 供 systemd 加载的私有凭据源，0600；不进入普通 JSON 配置或备份 |
| `state/node-active.json`、`state/linux-active.json` | 本次运行冻结的平台设置 |
| `state/manager.lock`、`state/*.sock` | 实例专用租约与私有 socket |
| `state/last-error.json` | 静态错误码，不记录原始异常、客户端输出或秘密 |

实例目录 0700，配置/状态文件 0600。home 应短、无符号链接祖先、位于被观察项目之外。`home/state/control.sock` 总长度不超过 100 字节。socket、进程、缓存和日志目录按 home 隔离。Linux 还使用按 UID 和 Tunnel ID 哈希命名的 abstract Unix socket 作为本机租约，阻止同一 UID 下不同 home 意外复用同一 Tunnel。它没有磁盘文件、凭据或通信协议，所有持有描述符关闭后由内核释放，systemd PrivateTmp 不影响这一检查；不是中央注册表。它无法阻止其他机器或 UID 复用身份，跨机器唯一性必须由操作者在 Platform 维护。

新 Linux 实例获得随机节点 ID；既有 v1 实例无需升级，缺少 sidecar 时从 home 派生不包含路径的兼容 ID。Mac 的 `node set` 是可选命令，不要求当前稳定实例使用。公开名称为 1–64 字符 ASCII 标签，不填写 IP、私有主机名、凭据或内部资产详情。`observer_info.node` 仅报告 ID、显示名、格式和状态，不返回主机地址、账户、Tunnel ID、凭据路径或 Key。

## 新 Linux 服务器：完整步骤

先准备：Python 3.14+（含 venv/pip）、Git 2.28+、systemd 219+、官方 Tunnel Client。Ubuntu 22.04/systemd 249 是部署目标；系统默认 Python 不满足基线，应通过你的受控方式安装 Python 3.14。无需修改核心源码。

```sh
python3.14 --version
git --version
systemctl --version
```

以下以 root、独立安装目录和 `linux1` 实例为例，不创建或修改用户。每台服务器或同机新增实例更换名称与 home：

```sh
git clone https://github.com/liuhuijiayou/readonly-observer.git /opt/readonly-observer
cd /opt/readonly-observer
# 选择已审核且包含 Linux 适配的版本/提交。
python3.14 -m venv /opt/readonly-observer/.venv314
/opt/readonly-observer/.venv314/bin/python -m pip install .
OBSERVER=/opt/readonly-observer/.venv314/bin/observer
INSTANCE=/var/lib/readonly-observer/linux1
"$OBSERVER" --home "$INSTANCE" init --non-interactive
"$OBSERVER" --home "$INSTANCE" node set --name codex-observer-linux1
"$OBSERVER" --home "$INSTANCE" project add /absolute/authorized/project --alias app
"$OBSERVER" --home "$INSTANCE" config validate --check-sources
"$OBSERVER" --home "$INSTANCE" doctor --level local --probe
```

阅读确认预览，仅为准确目标输入 `approve`。`--approve` 是本地操作者明确选择自动化时的替代方式，不是让远端自动授权。init 为空权限，不启动进程。普通源码读取不依赖 Git，Git/联合证据工具需要现代 Git。先使用无敏感内容的公开标记做本地探测。

精确会话授权：

```sh
"$OBSERVER" --home "$INSTANCE" session add /absolute/selected/rollout.jsonl --alias task
```

只能选择一个准确、持久化的 JSONL；登记 metadata ID、文件身份和可选 `--reference` 显式云链接映射。不得授权整段会话历史目录。不读取 auth.json，不恢复未持久化日志，不返回隐藏推理。对本轮指定的真实项目和会话，本次实现/测试没有执行这些授权操作。

### Platform Tunnel 与 Runtime Key

在 [Platform Tunnel 设置](https://platform.openai.com/settings/organization/tunnels)为此节点创建独立 Tunnel，关联实际使用的 Platform organization 和 ChatGPT workspace。为该节点独立签发 Restricted Runtime Key，仅给 Tunnels **Read + Use**，其所属 principal 也必须有对应权限。创建/修改 Tunnel 需要 **Read + Manage**；ChatGPT 工作区访问权限独立管理。依据：[官方 Tunnel 指南](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)、[官方客户端权限说明](https://github.com/openai/tunnel-client/blob/master/docs/permissions.md)。

从 Platform 或[官方最新发布页](https://github.com/openai/tunnel-client/releases/latest)安装客户端，按你的供应链流程核验。Observer 不自动下载/安装客户端。二进制必须属于运行服务的 OS 用户、可执行且不可被组/其他用户写入；root 服务使用 root 所有的安装。先查看当前安装版本的离线 help，核对配置接口。合成测试不对真实凭据运行客户端 doctor。

```sh
/absolute/installed/tunnel-client help quickstart
/absolute/installed/tunnel-client run --help
"$OBSERVER" --home "$INSTANCE" transport tunnel \
  --client /absolute/installed/tunnel-client --tunnel-id '<NODE_TUNNEL_ID>'
"$OBSERVER" --home "$INSTANCE" credentials info
"$OBSERVER" --home "$INSTANCE" credentials set
```

在隐藏终端提示中输入已签发的 Restricted Key。禁止作为参数、管道 stdin 或普通环境变量传入。Linux 命令只将值存为 0600 的 `LoadCredential` 源，不创建远端 Key，也不写入普通配置、命令行、备份或日志。该源文件是**受权限保护的明文，并非静态加密**。systemd 249 使用 `LoadCredential`，不假设较新版本的加密凭据功能可用。若用外部秘密管理器，可由操作者调整生成 unit 的 `LoadCredential=<准确ID>:<受控源路径>`，保留 `credentials info` 显示的 ID；不能把值写入 unit、EnvironmentFile、历史命令或 Git。

运行时仅从 `$CREDENTIALS_DIRECTORY/<本实例ID>` 读取。逐组件 no-follow，检查 owner、mode、link、大小、ASCII 和读取前后身份；缺失/不安全即失败。不会回退读取源文件、OPENAI_API_KEY、其他实例凭据或 Keychain。systemd 提供每个 unit 的目录；这些检查不能抵御同 UID 的恶意进程。

### 可选代理

```sh
"$OBSERVER" --home "$INSTANCE" credentials set --kind proxy
"$OBSERVER" --home "$INSTANCE" proxy enable
```

在隐藏提示中输入 HTTP(S) 代理 URL，需要认证时只在这里输入。代理使用独立安全槽位，普通配置只有 `proxy=true`；`proxy disable` 在下次重启停用。不会继承 HTTP_PROXY、HTTPS_PROXY、ALL_PROXY、NO_PROXY。

[官方客户端配置](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md)确认：`control_plane.http_proxy`、`--control-plane.http-proxy`、`CONTROL_PLANE_HTTP_PROXY`，并支持 `env:VAR`。Linux 复用现有 `client_config`，设置 `control_plane.http_proxy: env:OBSERVER_TUNNEL_PROXY`；仅向自有 transport supervisor/client 注入该变量。客户端 MCP 命令经过 `env -i ... connect`，manager 从固定最小环境启动 Worker，Worker 不继承 Key、代理或 Credentials 目录。这是应用和环境隔离，进程仍共享服务 UID。

### 安装 systemd unit

只为**新的唯一 unit 名称**生成、审核并安装；不得覆盖当前部署：

```sh
"$OBSERVER" --home "$INSTANCE" systemd-unit > /tmp/observer-linux1.service
cat /tmp/observer-linux1.service
test ! -e /etc/systemd/system/observer-linux1.service
install -m 0644 /tmp/observer-linux1.service /etc/systemd/system/observer-linux1.service
systemctl daemon-reload
systemctl enable --now observer-linux1.service
"$OBSERVER" --home "$INSTANCE" status
"$OBSERVER" --home "$INSTANCE" doctor --level local --probe
```

必须确认 `test` 成功再执行 install。unit 使用已安装的 Python 模块，venv 不可移动。包含前台 `run`、独立 `LoadCredential`、`KillMode=control-group`、0077 umask、禁止 core dump、实例 home 之外只读文件系统、抑制客户端原始日志。此示例以 root 运行；未来改用已有非 root 用户时，由操作者审阅来源可读权限、二进制 owner 和 home 权限，程序不调整用户体系。

systemd 部署用 `systemctl stop/start/restart observer-linux1.service` 管理生命周期。受 systemd 监督时仅调用 `observer stop` 可能在异常退出策略下被重新拉起。非 systemd 的本地实例仍可使用 `start/stop`，Tunnel 启动必须具备 systemd Credentials 上下文；直接 `serve` 和本地 stdio 不需要凭据。Tunnel 架构使用出站连接，无需开放入站端口；程序不改动防火墙或安全组。

在 ChatGPT 为 Linux1 新建名为 `codex-observer-linux1` 的独立 MCP 连接/plugin，选择 Tunnel 与该 ID，设置适当认证、工作区权限并审阅工具。Linux2 及以后节点重复相同步骤，使用不同 home、unit、Tunnel、Key 和连接名。保留当前 Mac 连接。**必须通过每个真实 ChatGPT 连接**检查 `observer_info.node`、13 个只读工具和一个无敏感内容的授权标记；本地 status/probe 不证明远端接通。

## 停止、异常恢复、迁移和撤销

| 场景 | 本地动作 | 远端仍需处理 |
| --- | --- | --- |
| 正常停止 | stop 对应 systemd unit，核对 status | 原有权限与连接保留 |
| 异常退出 | stop unit，`recover --approve`，再 start | 怀疑泄露时另行撤销凭据 |
| 删除单个授权 | 停止相关 managed/direct Worker，project/session remove，再显式启动 | Key、Platform、ChatGPT 不变 |
| 撤销全部本地来源 | stop unit，`revoke --approve` | 按需要单独撤销 Key 和远端访问 |
| 节点退役 | stop/disable unit，`node retire --approve` | 撤销 Key、Platform Use/关联或 Tunnel，以及 ChatGPT 连接 |
| Key 轮换 | 保存新签发 Key，restart unit 重载 | Platform 签发新 Restricted Key，明确 revoke 旧 Key |
| 替换机器并保留连接 | 停旧节点；新 home 初始化，重新批准本机来源；可选设置原 node ID/name；配置原 Tunnel ID 和新 Key | 签发新 Key、撤销旧 Key，验证保留的 ChatGPT 连接 |

停止 unit 后的本地命令示例：

```sh
"$OBSERVER" --home "$INSTANCE" recover --approve
"$OBSERVER" --home "$INSTANCE" revoke --approve
"$OBSERVER" --home "$INSTANCE" node retire --approve
# 明确远端撤销后，可独立移除本地凭据源：
"$OBSERVER" --home "$INSTANCE" credential-delete --kind runtime --approve
```

recover 必须取得 manager 独占租约；manager、Worker、supervisor 任一仍持有租约就拒绝。仅删除已知且安全的运行态文件，拒绝 symlink、异常类型/owner/mode，保留其他文件。不猜 PID、不杀其他实例、不删除锁强行接管。unit 的 ExecStartPre 在旧 control group 停止后运行相同受限恢复。manager SIGKILL 会关闭父进程 pipe，Worker 退出，supervisor 终止并回收真实客户端；Client 异常退出则 manager 退出，systemd 可重启。恢复不等于远端连接已验证。

revoke 停止本实例自有 manager，清空当前本地授权。retire 额外阻止新的 Linux Worker，直到本机明确 `node activate --approve`；activate 不恢复任何授权。备份可能保留旧授权但不会自动恢复。**独立启动的直接 `serve` 和 legacy 入口也必须由其拥有者停止**，它们不属于 manager 租约。退役状态不是阻止可信本机用户主动运行 legacy 命令的 OS 安全机制。

删除凭据源仅删除本地文件；运行中的 unit 仍可能持有已加载副本，必须停止才能释放。删除文件或停进程都不是撤销远端 Key。Mac 的不再需要的 Keychain 条目通过原有本地管理方式处理，本轮不修改该实现。

官方支持以既有 Tunnel ID 和单独 Runtime Key 启动 Client。**依据二者分离关系作出的推论**：新机器可保留 Tunnel ID，使用新签发且有权限的 Key，从而保留 ChatGPT 连接目标。没有假设存在自动机器迁移 API 或“为某 Tunnel 重签 Key”专用 API。具体步骤是：停旧机、为有权限的 principal 签发独立 Restricted Key、在新机器重新授权本机来源、保存新 Key、配置原 Tunnel ID、撤销旧 Key、启动新机、验证旧 ChatGPT 连接。若账户策略/关联不允许则使用新 Tunnel/连接。不得让新旧机器同时复用同一运行身份；不要复制 active state、socket、凭据源、缓存或包含旧 inode 的授权记录。

远端撤销至少区分四层：本地数据授权；旧 Runtime API Key；principal 的 Platform Tunnel Use 权限及 organization/workspace 关联（必要时删除 Tunnel）；ChatGPT 连接与工作区使用权。各层单独操作。不要撤销其他节点仍使用的共享 principal 角色或计划保留的 Tunnel。Observer 不持有管理 Key，明确报告远端撤销 **not performed**。

## root 安全边界与验证

root 具有读取其他用户数据、查看进程环境/内存、绕过普通权限和修改项目的 OS 能力。只读 MCP 不削弱这些权限。生成 unit 的只读挂载限制普通服务写入，但不构成抵御 root 主机被攻破的租户沙箱。不要授权整个 Home/系统根，不把凭据放入允许读取的项目。后续切换非 root 是操作者决策，不是本轮自动变更。

合成验证无需真实项目、会话或 Key：

```sh
python3.14 -m venv .venv-test
.venv-test/bin/python -m pip install .
.venv-test/bin/python -I scripts/test_suite.py
.venv-test/bin/python -I scripts/check_repository.py
```

系统 Git 过旧时，`scripts/test_suite.py --git /absolute/isolated/git` 仅为本次测试进程选择现代 Git，不改变生产固定 `/usr/bin/git`。生产使用 Git 工具之前必须由受控系统管理流程升级 Git。CI 配置 Ubuntu 22.04/macOS 14 + Python3.14；Linux 另以 root 运行 `scripts/systemd_smoke.py`，使用合成 LoadCredential 和伪客户端。该脚本只安装/清理唯一命名的临时测试 unit，不连接真实 Tunnel。当前环境的实际通过数、systemd/macOS 限制及待完成的真实远端验收见审计，不把未运行的 CI 写成通过。
