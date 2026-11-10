# ReadOnly Observer

[简体中文](README.zh-CN.md) · [Linux / multi-node deployment](docs/deployment.md) · [systemd 219](docs/systemd219.en.md)

Give an MCP client an evidence-based, read-only view of the local projects and individual Codex sessions you explicitly approve.

**0.1.0 · Alpha / experimental.** Public versioning starts at 0.1.0. The same code supports macOS and independent Linux nodes. Linux installation and upgrades use the interactive terminal wizard below; current verification is recorded in the [wizard audit](docs/linux-wizard-audit.md). Use a reviewed revision containing these scripts; this wizard change awaits human review and has not been published by the assistant.

## Features

- **Understand a codebase.** Browse and search approved source, follow implementations across files, and cite paths, lines and source hashes.
- **Review a Codex session.** Read public context and execution results from one registered JSONL file, including paginated long output. No history-wide discovery.
- **Compare evidence.** Relate session records to current source and bounded Git status, diffs and HEAD history, without treating “finished” as proof of correctness.

Example questions to ask after connecting (not recorded results):

- “In `app`, trace startup through registration across files. Cite paths and lines.”
- “In the approved `task` session, what execution results are recorded, and what remains unknown?”
- “Compare this session's evidence with the current source. Distinguish recorded claims from verified observations.”

**Read-only by design:** a new instance has no sources. Only the local operator can approve a project or exact session file. MCP cannot register sources, execute project commands or tests, control sessions, or read hidden reasoning. Mentioning a path in chat grants no access.

Approved UTF-8 source can include safe ignored/untracked files. Sensitive paths, symlinks and hardlinks are rejected; redaction cannot detect every secret. Git uses sealed snapshots with a **100 MB (100,000,000 bytes) combined budget** for metadata, objects and selected worktree content. Local/remote refs and ordinary packs are supported. Paths narrow worktree copying and Git queries; history and staged diffs need no worktree. Unsupported layouts or exhausted budgets return a failure, never a clean result. This is a single-operator service, not a per-user authorization system. See [security boundaries](SECURITY.md).

## Linux: recommended installation and upgrade

Prepare root/sudo, Bash, Python **3.14+** with venv/ensurepip, `/usr/bin/git` **2.28+**, active systemd **219+**, 1 GiB free space, and an already installed/verified official Tunnel Client. The wizard checks these prerequisites and does not upgrade the OS/systemd or download a Tunnel executable.

```bash
git clone https://github.com/liuhuijiayou/readonly-observer.git
cd readonly-observer
sudo bash scripts/install_linux_node.sh
```

The terminal collects Node Name, Installation Directory, independent Instance Home, project path/alias, optional exact JSONL/alias, Tunnel Display Name, an explicitly entered Tunnel ID, confirmed/detected Client path, hidden Runtime API Key, proxy choice/hidden URL, unit name and startup choice. No script, JSON or environment editing is required. Every source grant requires `approve`; keys are entered only through Observer's existing hidden-TTY CLI. No Platform resources or ChatGPT connections are created automatically.

```bash
sudo bash scripts/install_linux_node.sh --dry-run
sudo bash scripts/install_linux_node.sh --no-start
sudo bash scripts/upgrade_linux_node.sh --home /var/lib/readonly-observer/linux2 --ref REVIEWED_COMMIT_OR_TAG
```

Flags can prefill non-secret metadata; real installation still requires a human TTY. Existing homes/units are refused. Interrupted owned installs use `--resume --install-dir ...`; upgrades retain the old release/venv and provide explicit rollback. See the [installation, upgrade and recovery SOP](docs/deployment.md#terminal-wizard-sop). Manual steps below remain useful for macOS and Linux recovery.

## Manual quick start

### 1. Install from source

You need **macOS or Linux, Python 3.14+ with `venv`/`pip`, and a local MCP client that supports stdio**. Git 2.28+ is required for Git and joint evidence, optional for ordinary reads. Linux Tunnel deployment supports systemd 219+ (checked tmpfs staging before 247, native LoadCredential from 247); see the [complete deployment guide](docs/deployment.md). Existing macOS Keychain, v1 configuration and lifecycle behavior are retained; no action is required on an existing stable Mac. Windows is unsupported. Native Mac verification and actual remote acceptance for the current revision remain pending; see the audit.

Download and extract the source archive from [v0.1.0 Release](https://github.com/liuhuijiayou/readonly-observer/releases/tag/v0.1.0), or clone the [source repository](https://github.com/liuhuijiayou/readonly-observer). There is **no public PyPI installation**. In the source directory containing `pyproject.toml`, run:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install .
OBSERVER="$PWD/.venv/bin/observer"
"$OBSERVER" --version
```

Dependencies come from your configured package index, so this normally requires network access. Keep the environment at its installed path. This source installation does not bundle Python, Git or the optional Secure MCP Tunnel client.

### 2. Create an empty instance

```sh
"$OBSERVER" init --non-interactive
```

This creates private instance files, not a service or source grant. On macOS the default home is `~/Library/Application Support/ReadOnlyObserver`. For a custom home, place `--home /absolute/private/instance` before **every** subcommand, including the client's `serve` argument. Keep it outside your observed project and installation, at a short private path without symlink ancestors. See [instance configuration](docs/config-reference.md#实例布局).

### 3. Approve one project locally

Replace the path with a project you are authorized to expose:

```sh
"$OBSERVER" project add /absolute/path/to/project --alias app
"$OBSERVER" project list
"$OBSERVER" config validate --check-sources
"$OBSERVER" doctor --level local --probe
```

Review the displayed scope and type `approve` in your terminal. `project list` should show `app`; validation should report `service_can_start=true`. A successful probe reports `local_protocol_verified`, not remote ChatGPT readiness.

### 4. Connect your local MCP client

Configure a stdio server with the **absolute executable path** printed by `printf '%s\n' "$OBSERVER"` and the argument `serve`. For clients using an `mcpServers` configuration, the entry looks like:

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

Replace the example path; shell variables and `~` are not guaranteed to expand in client settings. Adapt the surrounding configuration to your client's documentation. The client starts and stops this process; **`observer start` is not needed for `serve`**. Managed `start`/`connect` is an alternative covered in the [manual](docs/product-manual.md#本地-mcp-与可选菜单).

### 5. Confirm your first read

In that client, request these MCP calls:

```text
observer_info({})
workspace_read({"alias":"app","path":"README.md"})
```

These are tool-call examples, not shell commands. If your project has no `README.md`, first call `workspace_list({"alias":"app"})` and select an existing, harmless UTF-8 file.

Check that `observer_info` returns `ok=true`, the installed `version`, and `app` in `workspaces`. The read should return that file's redacted content, physical line locations and source version. Follow any `next_cursor` until `selection_complete=true` and `next_cursor=null`; a preview is not a complete read. If a step fails, see [troubleshooting](docs/troubleshooting.md).

### Optional: approve a Codex session

Session reading is implemented, but requires a separately approved, persisted JSONL file selected by you:

```sh
"$OBSERVER" session add /absolute/path/to/chosen.jsonl --alias task
"$OBSERVER" session list
```

Review the file and metadata-ID scope locally, then reconnect the MCP client. Only this file is approved, not its directory or other sessions. Exact IDs and explicitly mapped links are supported; unmapped cloud links and non-persisted sessions cannot be recovered. See [session registration and references](docs/product-manual.md#会话登记与精确引用).

Any source-registration change (adding, removing or mapping a source) requires new MCP processes: reconnect direct `serve` clients, or stop/start the managed instance and reconnect its clients. Old processes retain their approved snapshot until stopped.

## Connect ChatGPT

**Ordinary remote ChatGPT needs both account/workspace support for a custom MCP connection and a separately protected transport.** The local stdio quick start does not supply either prerequisite, and Observer does not expose an HTTP server.

An optional adapter supports an independently installed official Secure MCP Tunnel client and an existing tunnel. It does not create tunnels, install the client, create credentials or grant account access. Adapter support does not imply availability for every ChatGPT account.

Follow the [Tunnel setup and verification guide](docs/product-manual.md#普通-chatgpt-的-tunnel-适配) and the current [OpenAI connection guide](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) for your account. Never put a key in chat, command arguments or configuration. Verify `observer_info` and a harmless file from the actual ChatGPT connection; `doctor` never establishes remote readiness.

## Documentation

- [User manual](docs/product-manual.md) — sessions, transports, evidence and pagination (Chinese).
- [CLI and configuration reference](docs/config-reference.md) — commands, instance layout and all 13 MCP tools (Chinese).
- [Troubleshooting](docs/troubleshooting.md) — refusals and incomplete reads (Chinese).
- [Upgrade, rollback and uninstall](docs/migration.md) — preserve the original instance and approvals (Chinese).
- [Architecture](docs/product-design.md) · [Security](SECURITY.md) · [Distribution scope](docs/release-scope.md).

## Development / contributing

Use the [development guide](docs/repository.md) for isolated synthetic tests, SDK checks, builds, clean exports and contribution requirements. Tests do not require your real sessions, credentials or ChatGPT connection. Submit ordinary bug reports through [Issues](https://github.com/liuhuijiayou/readonly-observer/issues) and proposed changes through pull requests. Keep private data out of patches and follow [SECURITY.md](SECURITY.md) for security reporting.

## License

ReadOnly Observer is licensed under the [MIT License](LICENSE), copyright 2026 liuhuijiayou. Dependencies retain their own terms; see [third-party notices](THIRD_PARTY_NOTICES.md) and the [distribution scope](docs/release-scope.md).
