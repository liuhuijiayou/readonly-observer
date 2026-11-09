# systemd 219 安全兼容部署

同一套 Linux 代码按**正在运行的 systemd manager 版本**选择凭据后端，不根据发行版或 Python 版本猜测。Mac 的 Keychain、默认配置与进程路径不变。完整旧版/新版部署关系见 [English](systemd219.en.md)、[本轮实际验收](systemd219-audit.md)及[完整部署指南](deployment.zh-CN.md)。

| systemd 版本 | 凭据后端 | 文件系统规则 |
| --- | --- | --- |
| 219–230 | 受限 ExecStartPre 暂存至 RuntimeDirectory | ProtectSystem=full、ReadOnlyDirectories/ReadWriteDirectories |
| 231 | 同上 | ProtectSystem=full、ReadOnlyPaths/ReadWritePaths |
| 232–246 | 同上 | ProtectSystem=strict、ReadOnlyPaths/ReadWritePaths |
| 247+ | 原生 LoadCredential | ProtectSystem=strict、ReadOnlyPaths/ReadWritePaths |

低于 219、版本未知或 manager 不可达则拒绝生成。新版原生后端不执行旧版暂存命令，Manager 的 Provider 接口和 credential_id 均不改变。版本依据：[systemd 219 官方手册](https://github.com/systemd/systemd/blob/v219/man/systemd.exec.xml)、[231/232 变更记录](https://github.com/systemd/systemd/blob/v232/NEWS)、[LoadCredential 官方说明](https://www.freedesktop.org/software/systemd/man/247/systemd.exec.html)。

## 旧版启动顺序和安全边界

1. systemd 为该实例创建 `/run/readonly-observer-<实例 namespace>`，RuntimeDirectoryMode=0700。
2. ExecStartPre 执行现有 `recover --approve`，确认本实例没有仍持有租约的进程并受限清理旧状态。
3. ExecStartPre 执行内部 `_stage-credentials`：验证 CREDENTIALS_DIRECTORY 是本实例准确目录、root 所有、0700、逐组件 no-follow，使用 **fstatfs 检查已打开目录本身确为 tmpfs**。
4. 只打开当前实例 `credentials/runtime`，以及 proxy 启用时的 `credentials/proxy`。检查目录 0700、文件 root 所有/0600/单链接/普通文件/大小上限；校验内容，并核对读取前后 fd 与路径身份。
5. 在空目标目录以 O_EXCL 创建暂存锁和随机临时文件，写入后 fsync；通过 link/unlink 完成不覆盖的原子发布，最终名称仍是已有 credential_id，文件 0600、nlink=1。所有选定来源先验证，再发布。
6. 任一失败只按 inode 清理本次创建的文件；冲突文件不归本次启动，拒绝覆盖或删除。清理错误返回静态失败码，要求本地审阅。最终 fsync 目录后启动单个前台 `observer run` Manager。
7. 服务停止、启动失败或自动重启时，RuntimeDirectory 由 systemd 清理；下一次启动重新暂存。对应真实 219 流程已用合成凭据验证。

Manager 仍只从 CREDENTIALS_DIRECTORY 读取，不从源文件、JSON、OPENAI_API_KEY、普通环境变量或其他实例回退。暂存命令不属于 MCP 工具。不要手动对正式实例运行它；正式凭据只应由已审核服务的 ExecStartPre 加载。一份 home 只配置一个 systemd unit；同机新增实例使用不同 home，产生不同 RuntimeDirectory 与 credential_id。

219 unit 不包含 LoadCredential、ProtectSystem=strict 或 ReadWritePaths。WorkingDirectory 和路径列表使用严格白名单验证的无引号绝对路径；空格、引号、百分号、美元符、反斜线或其他无法安全编码的路径会拒绝生成。ExecStart 直接调用已安装 Python 模块，不经过 Shell、不后台化、不启动第二个 Manager。

`ReadOnlyDirectories=/ /tmp /var/tmp` 与准确的实例 home、RuntimeDirectory 写入允许列表组合。显式列出临时目录是必要的：PrivateTmp=true 自身会创建可写的私有临时目录。真实测试验证了允许列表之外的合成项目文件与私有 `/tmp` 均无法写入。NoNewPrivileges、KillMode=control-group、0077 umask、LimitCORE=0 和原始日志抑制保留。

代理仍是独立凭据；只有 proxy=true 在普通配置中。Client 只获得明确注入的 key/proxy，Worker 不获得 key、代理、CREDENTIALS_DIRECTORY 或 SSH Shell 的代理变量。系统配置不包含密钥值、EnvironmentFile 或包含秘密的 Environment/命令行参数。

## 当前服务器的正式部署流程

本轮已在真实 systemd 219 上完成合成集成验证，随后才生成当前真实实例的待审核 unit。**没有安装或启动正式服务、没有启动真实 Tunnel。** 本轮不要求重新输入任何密钥，不重建实例、不修改 Tunnel ID 或项目授权。

正式实例的 unit 和待安装 wheel 放在工作区的私有验证目录，不属于 Git 公开清单。按本轮报告给出的准确路径操作，不向公开仓库复制它们。安装前先检查是否已有同一 home 的服务；不得并行启动两个 unit 或覆盖现有 unit。已存在的部署须单独审阅，不能靠更换 unit 名绕过冲突。

以下命令是人工部署步骤，**本轮没有执行**。将变量替换为本轮已审核文件的实际绝对路径。先审核 wheel 与 unit，再更新当前 venv 的 Observer 包；不要移动 venv。安装不需要读取凭据源，也不改变实例配置。

```sh
# 采用系统中可用的 pip；目标 venv 即使没有 pip，也可用 pip --python。
BUILD_PY=/absolute/reviewed/build-venv/bin/python
TARGET_PY=/absolute/observer/venv/bin/python
WHEEL=/absolute/reviewed/local_readonly_observer-0.1.0-py3-none-any.whl
UNIT=/absolute/reviewed/observer-linux1.service
"$BUILD_PY" -I -m pip --python "$TARGET_PY" install \
  --no-index --no-deps --force-reinstall "$WHEEL"
systemd-analyze verify "$UNIT"
```

只为确认不存在的新 unit 路径安装。下列脚本使用 `noclobber` 拒绝覆盖；如果已有 unit，请停止并审阅现有部署，不要继续覆盖。

```sh
DEST=/etc/systemd/system/observer-linux1.service
if (umask 022; set -C; cat "$UNIT" > "$DEST"); then
  systemctl daemon-reload && systemctl enable --now observer-linux1.service
else
  printf '%s\n' '拒绝覆盖：请审阅已有 unit。' >&2
fi
```

启动真实服务会在 ExecStartPre 安全读取已有持久凭据；这是本地操作者实际部署时的动作。本轮合成验证没有读取它们。启动后核对本机 status、已授权公开标记、ChatGPT 中原 `tunnel_linux1` 连接的 `observer_info.node` 和 13 个只读工具；不会创建新 Tunnel。完整联通验收必须使用真实 ChatGPT 请求，本地进程状态不能替代。

停止与重启使用 systemctl，避免与监督器冲突。停止后确认生成 unit 所列的 `/run` 目录已不存在。若启动失败，先查看 status/静态错误码和该实例运行态，不打印密钥文件或客户端原始日志。不要手动清空异常凭据目录强行启动；应先确认服务完全停止、无其他实例占用。

```sh
systemctl stop observer-linux1.service
systemctl restart observer-linux1.service
```

## 安全差异与剩余风险

旧版持久凭据源是 **root-only 明文**，并非静态加密，不等价于 LoadCredentialEncrypted。临时副本位于已验证的 tmpfs；tmpfs 仍可能使用 swap，本方案不配置磁盘/swap 加密。旧版目录和副本可被 root 访问，也可被同一 root 服务身份修改；应用不以敌对同 UID 进程为隔离边界。停止服务会自动清理副本，持久源保留。

根文件系统只读挂载限制普通文件写入；root 仍具有 OS 权力，特别是被攻破的进程可能利用其保留的权限，旧版 systemd 对后来出现的子挂载也有已知限制。没有声称这是抵御主机 root 失陷的沙箱。13 个 MCP 工具仍没有写入、任意执行、授权扩展或会话控制入口。停止/清理不代表远端 Key、Platform 权限或 ChatGPT 连接已撤销。

## 可重复合成验证

```sh
python3.14 -I scripts/test_suite.py
# 仅为测试进程指定现代 Git（系统 Git 过旧时）：
python3.14 -I scripts/test_suite.py --git /absolute/isolated/git
# root，使用安装了当前包的独立测试 Python：
/path/to/test/python -I scripts/systemd_smoke.py
```

最后一个脚本使用唯一命名的临时 runtime unit 链接，所有 unit 源和合成数据位于工作区 `.local`。systemd 在 `/run` 创建的测试链接与目录会清理；不改现有 unit，不启动官方客户端，不读真实 Key/Proxy/会话。247+ 主机使用原生后端执行相应测试；219 来源权限/符号链接检查由旧版专属测试覆盖。CI 增加 root 暂存回归，原生 macOS 与 247+ 的本轮实际运行状态见审计。
