"""Operator CLI. No lifecycle, configuration or approval action is an MCP tool."""
import argparse
import asyncio
import getpass
import json
import logging
import os
from pathlib import Path
import sys
import warnings

from . import __version__
from .security import Refusal, Redactor

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("invalid_cli_arguments; use_--help")

def parser():
    root = Parser(prog="observer", description="Read-only project and exact-session MCP. Configure locally; no default sources.")
    root.add_argument("--home", help="Private instance directory (or OBSERVER_HOME)")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True, metavar="COMMAND")
    init = commands.add_parser("init", help="Initialize an empty private instance; never starts a service")
    init.add_argument("--non-interactive", action="store_true")
    for kind in ("project", "session"):
        group = commands.add_parser(kind, help="Explicit local source approval")
        actions = group.add_subparsers(dest="action", required=True)
        add = actions.add_parser("add")
        add.add_argument("path", help="Project directory or exact JSONL file; never all session history")
        add.add_argument("--alias", required=True)
        add.add_argument("--approve", action="store_true", help="Local operator explicitly approves the displayed source scope")
        if kind == "session":
            add.add_argument("--reference", default="", help="Exact local metadata ID or explicitly mapped cloud link/ID")
        remove = actions.add_parser("remove")
        remove.add_argument("alias")
        remove.add_argument("--approve", action="store_true")
        actions.add_parser("list")
    group = commands.add_parser("config", help="Show, validate, explicitly upgrade or import local configuration")
    actions = group.add_subparsers(dest="action", required=True)
    actions.add_parser("show")
    validate = actions.add_parser("validate")
    validate.add_argument("--check-sources", action="store_true")
    actions.add_parser("upgrade")
    load = actions.add_parser("import", help="Explicitly import exact legacy source grants, with backup and rollback")
    load.add_argument("path")
    load.add_argument("--approve", action="store_true")
    transport = commands.add_parser("transport", help="Select stdio or an independently installed tunnel client")
    transport.add_argument("kind", choices=("stdio", "tunnel"))
    transport.add_argument("--client", help="Operator-installed official client; no automatic download")
    transport.add_argument("--tunnel-id", help="Existing non-secret tunnel ID; never an API key")
    credentials = commands.add_parser("credentials", help="Opt-in instance-specific macOS Keychain settings")
    credentials.add_argument("action", choices=("info", "set"))
    credentials.add_argument("--approve", action="store_true")
    credentials.add_argument("--kind", choices=("runtime", "proxy"), default="runtime", help="Linux credential slot")
    linux_credentials = commands.add_parser("credential-delete", help="Linux: remove a local staged credential; no remote revocation")
    linux_credentials.add_argument("--kind", choices=("runtime", "proxy"), default="runtime")
    linux_credentials.add_argument("--approve", action="store_true")
    node = commands.add_parser("node", help="Optional public identity; no source or credential migration")
    node.add_argument("action", choices=("info", "set", "retire", "activate"))
    node.add_argument("--name")
    node.add_argument("--id", dest="node_id")
    node.add_argument("--approve", action="store_true")
    proxy = commands.add_parser("proxy", help="Linux: use the separate secure proxy credential")
    proxy.add_argument("action", choices=("enable", "disable"))
    for name in ("recover", "revoke"):
        group = commands.add_parser(name, help="Linux: explicit local recovery or removal of all source grants")
        group.add_argument("--approve", action="store_true")
    commands.add_parser("run", help="Linux: foreground manager for systemd")
    commands.add_parser("systemd-unit", help="Linux: render instance unit to stdout; never install or start")
    commands.add_parser("_stage-credentials", help=argparse.SUPPRESS)
    descriptions = {"serve": "Serve read-only MCP directly over stdio", "connect": "Connect stdio to this instance's local manager",
                    "start": "Start this instance; remote readiness remains unverified", "stop": "Stop only this instance's owned processes",
                    "status": "Show local process state and pending configuration", "menu": "Interactive menu using these same commands",
                    "uninstall": "Show manual removal steps without deleting anything"}
    for name, description in descriptions.items():
        commands.add_parser(name, help=description)
    for name in ("_manager", "_serve-active"):
        internal = commands.add_parser(name)
        internal.add_argument("--parent-fd", type=int, default=None, help=argparse.SUPPRESS)
    internal = commands.add_parser("_tunnel")
    internal.add_argument("--parent-fd", type=int, required=True, help=argparse.SUPPRESS)
    doctor = commands.add_parser("doctor", help="Separate installation/configuration/local/transport/metadata/end-to-end evidence")
    doctor.add_argument("--level", choices=("all", "installation", "config", "local", "transport", "metadata", "end-to-end"), default="all")
    doctor.add_argument("--probe", action="store_true", help="Run a temporary local MCP initialize/tools-list/info probe; no observed project code executes")
    return root

def confirmation(args):
    def confirm(preview):
        print(json.dumps(Redactor().clean(preview), ensure_ascii=False, indent=2), file=sys.stderr)
        if getattr(args, "approve", False):
            return True
        if not sys.stdin.isatty():
            raise Refusal("local_approval_required; use_--approve_only_for_your_explicit_source")
        return input("Type approve to grant exactly this scope: ") == "approve"
    return confirm

async def probe(store, managed=False):
    from datetime import timedelta
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from .runtime import argv, environment
    arguments = argv(store, "connect" if managed else "serve")
    params = StdioServerParameters(command=arguments[0], args=arguments[1:], env=environment(), cwd=str(store.home))
    with open(os.devnull, "w") as errors:
        async with stdio_client(params, errlog=errors) as (read, output):
            async with ClientSession(read, output, read_timeout_seconds=timedelta(seconds=8)) as client:
                await client.initialize()
                tools = (await client.list_tools()).tools
                result = await client.call_tool("observer_info", {})
                body = json.loads(result.content[0].text)
                if not body.get("ok") or result.isError or len(tools) != 13 or not all(t.annotations.readOnlyHint for t in tools):
                    raise Refusal("local_mcp_probe_failed")
                return {"status": "local_protocol_verified", "version": body["version"], "readonly_tools": len(tools),
                        "session_read_parameters": list(next(t for t in tools if t.name == "session_read").inputSchema["properties"]),
                        "transport_scope": "instance_local_only", "remote_readiness": "not_observed"}

def diagnose(store, args):
    from . import runtime
    if sys.platform.startswith("linux"):
        from . import linux_runtime as runtime
    layers = {"installation": {"status": "available", "version": __version__, "python": sys.version.split()[0],
                               "platform": sys.platform, "tested_scope": "see_release_evidence; platform_presence_is_not_validation"},
              "config": {"status": "not_checked"}, "local": {"status": "not_observed"},
              "transport": {"status": "not_observed"},
              "metadata": {"status": "not_observed_in_ChatGPT", "action": "Refresh the custom MCP connection, then verify schema in a new conversation; cursor content mode also supports old schemas"},
              "end-to-end": {"status": "not_observed", "action": "Read an approved public marker through the actual ChatGPT plugin; local process/probe is insufficient"}}
    settings, state = None, None
    try:
        store.require()
        approvals = store.config.entries()
        settings = store.settings()
        layers["config"] = {"status": "valid", "sources": len(approvals["entries"]), "format": settings["format"],
                            "service_can_start": bool(approvals["entries"])}
    except Refusal as error:
        layers["config"] = {"status": "blocked", "code": error.code}
    except Exception:
        layers["config"] = {"status": "invalid; raw_errors_suppressed"}
    if settings is not None:
        try:
            state = runtime.status(store)
            layers["local"] = {"status": state["manager"], "configuration_pending": state.get("configuration_pending", False)}
        except Refusal as error:
            layers["local"] = {"status": "blocked", "code": error.code}
        except Exception:
            layers["local"] = {"status": "unreachable; raw_errors_suppressed"}
        layers["transport"] = {"kind": settings["transport"]["kind"],
                                "active_kind": (state or {}).get("active_transport"),
                                "status": (state or {}).get("transport", "not_observed"),
                                "connection": "not_observed", "credential_accessed": False}
        if settings["transport"]["kind"] == "tunnel":
            try:
                runtime.check_binary(settings["transport"]["client"])
                layers["transport"]["binary"] = "local_metadata_valid; not_executed"
            except Exception:
                layers["transport"]["binary"] = "missing_or_unsafe"
        if args.probe:
            try:
                if args.level not in {"all", "local"}:
                    raise Refusal("probe_only_applies_to_local_or_all")
                layers["local"] = asyncio.run(probe(store, bool(state and state["manager"] == "running")))
            except Refusal as error:
                layers["local"] = {"status": "probe_blocked", "code": error.code}
            except Exception:
                layers["local"] = {"status": "probe_failed; raw_errors_suppressed"}
    return {"ok": True, "overall": "diagnostic_only; no_remote_ready_claim", "remote_ready": False,
            "layers": layers if args.level == "all" else {args.level: layers[args.level]}, "credential_accessed": False}

def run(args):
    from .profile import Store
    from . import runtime
    if sys.platform.startswith("linux"):
        from .linux import LinuxStore as Store
        from . import linux_runtime as runtime
    store = Store(args.home)
    command = args.command
    if command == "menu":
        if not sys.stdin.isatty():
            raise Refusal("interactive_terminal_required")
        while True:
            print("Observer: 1 init, 2 project add, 3 session add, 4 start, 5 stop, 6 status, 7 doctor, 8 credentials set, 0 exit (exit does not stop background service)")
            choice = input("> ")
            if choice == "0":
                return {"menu_closed": True, "background_service": "unchanged"}
            items = {"1": ["init"], "4": ["start"], "5": ["stop"], "6": ["status"], "7": ["doctor"], "8": ["credentials", "set"]}
            if choice in {"2", "3"}:
                kind = "project" if choice == "2" else "session"
                path, alias = input("Exact local path: "), input("Alias: ")
                items[choice] = [kind, "add", path, "--alias", alias]
                if kind == "session":
                    items[choice] += ["--reference", input("Optional exact ID/link: ")]
            if choice in items:
                main(["--home", str(store.home), *items[choice]])
    if command == "init":
        if not args.non_interactive:
            if not sys.stdin.isatty():
                raise Refusal("use_init_--non-interactive_for_scripts")
            print("Initialize an empty instance. No sources, credentials or services are created/started.")
            if input("Type init to continue: ") != "init":
                raise Refusal("initialization_cancelled")
        initialized = store.initialize()
        if not args.non_interactive:
            print("Optional source: 1 project, 2 exact session, 0 configure later (default)")
            choice = input("> ").strip() or "0"
            if choice in {"1", "2"}:
                kind = "project" if choice == "1" else "session"
                path, alias = input("Exact local path: "), input("Alias: ")
                values = ["--home", str(store.home), kind, "add", path, "--alias", alias]
                if kind == "session":
                    values += ["--reference", input("Optional exact ID/link: ")]
                run(parser().parse_args(values))
            elif choice != "0":
                raise Refusal("invalid_wizard_choice; initialized_instance_preserved")
            print("Transport: 0 local stdio (default), 1 operator-installed tunnel client")
            choice = input("> ").strip() or "0"
            if choice == "1":
                client, identifier = input("Absolute installed client path: "), input("Existing tunnel ID (not a key): ")
                run(parser().parse_args(["--home", str(store.home), "transport", "tunnel", "--client", client, "--tunnel-id", identifier]))
                print("No credential accessed. Use observer credentials info/set separately if you choose.")
            elif choice != "0":
                raise Refusal("invalid_wizard_choice; current_config_preserved")
            initialized["sources"] = len(store.config.entries()["entries"])
        return {"ok": True, **initialized, "next": "observer project add PATH --alias NAME; or observer session add EXACT_JSONL --alias NAME"}
    if command == "doctor":
        return diagnose(store, args)
    if command == "config" and args.action == "upgrade":
        return {"ok": True, **store.upgrade()}
    store.require()
    if command == "node":
        from . import nodes
        if args.action == "info":
            return {"ok": True, "node": nodes.identity(store), "credential_accessed": False}
        if args.action == "set":
            if not args.name and not args.node_id:
                raise Refusal("node_set_requires_name_or_id")
            if confirmation(args)({"action": "set_public_node_identity", "name": args.name, "id": args.node_id}) is not True:
                raise Refusal("local_approval_required")
            return {"ok": True, **nodes.configure(store, args.name, args.node_id)}
        if not sys.platform.startswith("linux"):
            raise Refusal("linux_lifecycle_command; existing_macos_lifecycle_unchanged")
        if confirmation(args)({"action": args.action, "local_only": True, "remote_permissions": "unchanged"}) is not True:
            raise Refusal("local_approval_required")
        runtime.stop(store)
        if args.action == "retire":
            return {"ok": True, **store.revoke_all(retire=True)}
        return {"ok": True, **nodes.configure(store, status="active")}
    if command in {"run", "recover", "revoke", "systemd-unit", "proxy", "credential-delete", "_tunnel", "_stage-credentials"}:
        if not sys.platform.startswith("linux"):
            raise Refusal("linux_only_command; macos_unchanged")
        if command == "run":
            return runtime.manage(store)
        if command == "_tunnel":
            return runtime.supervise_tunnel(store, args.parent_fd)
        if command == "systemd-unit":
            from .linux_systemd import render
            print(render(store), end="")
            return None
        if command == "_stage-credentials":
            from .linux_legacy import prepare
            return {"ok": True, **prepare(store)}
        if command == "proxy":
            return {"ok": True, **store.set_proxy(args.action == "enable")}
        if confirmation(args)({"action": command, "local_only": True, "remote_permissions": "unchanged"}) is not True:
            raise Refusal("local_approval_required")
        if command == "recover":
            return {"ok": True, **runtime.recover(store)}
        if command == "revoke":
            runtime.stop(store)
            return {"ok": True, **store.revoke_all()}
        from .linux_credentials import delete_staged
        delete_staged(store, args.kind)
        return {"ok": True, "staged_credential_removed": True, "runtime_key": "not_revoked",
                "loaded_unit_credentials": "unchanged_until_unit_stops", "platform_permissions": "unchanged"}
    if command in {"project", "session"}:
        kind = "workspace" if command == "project" else "session"
        if args.action == "list":
            return {"ok": True, "sources": [e for e in store.config.entries()["entries"] if e["kind"] == kind]}
        confirm = confirmation(args)
        with store.mutation():
            if args.action == "remove":
                entries = store.config.entries()["entries"]
                if not any(e["alias"] == args.alias and e["kind"] == kind for e in entries):
                    raise Refusal("registration_not_found")
                store.backup("source_removal")
                store.config.remove(args.alias, confirm)
            else:
                path = str(Path(args.path).expanduser().absolute())
                store.backup("source_registration")
                if kind == "workspace":
                    store.config.register_workspace(args.alias, path, confirm)
                else:
                    store.config.register_session(args.alias, path, args.reference, confirm)
        return {"ok": True, "saved": True, "activation": "next_explicit_start; running_instance_unchanged"}
    if command == "config":
        if args.action == "show":
            return {"ok": True, **store.snapshot(), "credential_values": "never_stored_in_config"}
        if args.action == "import":
            return {"ok": True, **store.import_sources(args.path, confirmation(args))}
        entries = store.config.entries()["entries"]
        if args.check_sources:
            config = store.configuration()
            config.close()
        return {"ok": True, "format": 1, "registered_sources": len(entries),
                "sources_opened": args.check_sources, "service_can_start": bool(entries)}
    if command == "transport":
        if args.kind == "stdio":
            if args.client or args.tunnel_id:
                raise Refusal("stdio_has_no_tunnel_parameters")
            value = {"kind": "stdio"}
        else:
            if not args.client or not args.tunnel_id:
                raise Refusal("tunnel_requires_--client_and_--tunnel-id; no_credentials_in_arguments")
            value = {"kind": "tunnel", "client": str(Path(args.client).expanduser().absolute()), "tunnel_id": args.tunnel_id}
        return {"ok": True, **store.set_transport(value)}
    if command == "credentials":
        if sys.platform.startswith("linux"):
            from .linux_commands import credentials
            return credentials(store, args, confirmation(args))
        if args.kind != "runtime":
            raise Refusal("linux_only_credential_kind; macos_keychain_unchanged")
        keychain = store.keychain()
        meta = {"service": keychain.service.decode(), "account": keychain.account.decode(),
                "value_read": False, "old_legacy_item": "not_read_or_migrated"}
        if args.action == "info":
            return {"ok": True, **meta}
        if confirmation(args)({"action": "save_or_replace_this_instance_keychain_item", **meta}) is not True:
            raise Refusal("local_approval_required")
        if not sys.stdin.isatty():
            raise Refusal("secure_tty_required; no_stdin_or_environment_key_input")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Existing Read+Use tunnel runtime key (hidden, local only): ")
            keychain.save_from_local_settings(key, confirmed=True)
        except getpass.GetPassWarning:
            raise Refusal("secure_tty_required") from None
        finally:
            key = None
        return {"ok": True, "credential_saved_by_operator": True, "service_started": False}
    if command in {"serve", "_serve-active"}:
        from .server import serve
        from .service import Observer
        if sys.platform.startswith("linux") and getattr(args, "parent_fd", None) is not None:
            runtime.watch_parent(args.parent_fd)
        config = store.configuration(active=command == "_serve-active")
        if sys.platform == "darwin":
            from .nodes import identity
            config.node = identity(store)
        try:
            asyncio.run(serve(Observer(config)))
        finally:
            config.close()
        return None
    if command == "connect":
        runtime.connect(store)
        return None
    if command == "_manager":
        return runtime.manage(store)
    if command == "start":
        return {"ok": True, **runtime.start(store)}
    if command == "stop":
        return {"ok": True, **runtime.stop(store)}
    if command == "status":
        return {"ok": True, **runtime.status(store)}
    if command == "doctor":
        return diagnose(store, args)
    if command == "uninstall":
        return {"ok": True, "plan_only": True, "instance": str(store.home),
                "steps": ["Stop this instance explicitly", "python -m pip uninstall local-readonly-observer",
                          "Review and optionally remove only this instance directory", "Remove this instance Keychain item manually if desired"],
                "observed_sources_deleted": False, "credential_revocation": "not_performed; local_removal_does_not_revoke_remote_authorization"}
    raise Refusal("unknown_command")

def main(argv=None):
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] in {"--config", "--approved-sources"}:
        # Existing stdio invocation remains supported, with no automatic import.
        from .server import main as legacy
        previous = sys.argv
        try:
            sys.argv = [previous[0], *values]
            legacy()
        finally:
            sys.argv = previous
        return 0
    if os.name != "posix":
        print('{"ok":false,"error":"unsupported_platform; POSIX_required; Windows_not_validated"}')
        return 2
    try:
        result = run(parser().parse_args(values))
        if isinstance(result, int):
            return result
        if result is not None:
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Refusal as error:
        print(json.dumps({"ok": False, "error": error.code, "hint": "observer --help; observer doctor"}))
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        print('{"ok":false,"error":"local_operation_failed; raw_errors_suppressed","hint":"observer doctor"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
