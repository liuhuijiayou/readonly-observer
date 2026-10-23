"""Product CLI, source approval, lifecycle and old-schema compatibility tests."""
import asyncio
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from support import PROJECT, ObserverCase, Config, Observer, SECRET, event, jsonl, metadata, write, init_repo, git
from observer.cli import main, probe
from observer.profile import Store
from observer import runtime
from observer.security import Refusal, canonical

class ProductCLITests(ObserverCase):
    def setUp(self):
        super().setUp()
        self.home = self.extra / "instance"
        self.store = Store(self.home)
        self.store.initialize()

    def cli(self, *arguments, code=0):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = main(["--home", str(self.home), *arguments])
        self.assertEqual(result, code, output.getvalue())
        self.assertNotIn(SECRET, output.getvalue() + error.getvalue())
        return json.loads(output.getvalue())

    def test_init_is_empty_idempotent_and_never_accesses_credentials(self):
        with patch("observer.credentials.Keychain.get", side_effect=AssertionError("no key")):
            result = self.cli("init", "--non-interactive")
            self.assertFalse(result["service_started"])
            self.assertEqual(result["sources"], 0)
            self.assertEqual(self.store.config.entries()["entries"], [])
        self.assertEqual((self.home / "config").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.home / "config/settings.json").stat().st_mode & 0o777, 0o600)

    def test_project_registration_requires_explicit_operator_approval(self):
        with patch("sys.stdin.isatty", return_value=False):
            result = self.cli("project", "add", str(self.base / "workspace"), "--alias", "code", code=2)
        self.assertIn("local_approval_required", result["error"])
        self.assertEqual(self.store.config.entries()["entries"], [])
        self.cli("project", "add", str(self.base / "workspace"), "--alias", "code", "--approve")
        self.assertEqual(len(self.cli("project", "list")["sources"]), 1)
        self.assertTrue(self.cli("config", "validate", "--check-sources")["sources_opened"])
        self.cli("project", "remove", "code", "--approve")
        self.assertEqual(self.cli("project", "list")["sources"], [])

    def test_exact_session_add_link_mapping_and_removal(self):
        path = self.extra / "chosen.jsonl"
        jsonl(path, [metadata("chosen", self.extra)])
        result = self.cli("session", "add", str(path), "--alias", "chosen", "--reference", "task_explicit", "--approve")
        self.assertTrue(result["saved"])
        config = self.store.configuration()
        try:
            page = Observer(config).call("session_read", {"source": "chosen", "session_id": "task_explicit"})
            self.assertTrue(page["ok"])
        finally:
            config.close()
        self.cli("session", "remove", "chosen", "--approve")

    def test_import_backs_up_and_rolls_back_without_partial_permissions(self):
        source = self.extra / "import.json"
        source.write_text(json.dumps({"workspaces": {"one": str(self.base / "workspace"), "two": str(self.extra / "absent")}, "sessions": {}, "strict_hardlinks": True}))
        self.cli("config", "import", str(source), "--approve", code=2)
        self.assertEqual(self.store.config.entries()["entries"], [])
        self.assertTrue(list((self.home / "config").glob("backup-*.json")))

    def test_import_never_discovers_a_session_directory(self):
        source = self.extra / "broad.json"
        source.write_text(json.dumps({"workspaces": {}, "sessions": {"history": str(self.base / "sessions")}, "strict_hardlinks": True}))
        result = self.cli("config", "import", str(source), "--approve", code=2)
        self.assertIn("broad_session_import_denied", result["error"])

    def test_import_requires_approval_and_preserves_original_file(self):
        source = self.extra / "legacy.json"
        original = json.dumps({"workspaces": {"imported": str(self.base / "workspace")}, "sessions": {}, "strict_hardlinks": True})
        source.write_text(original)
        with patch("sys.stdin.isatty", return_value=False):
            self.cli("config", "import", str(source), code=2)
        self.cli("config", "import", str(source), "--approve")
        self.assertEqual(source.read_text(), original)
        self.assertEqual(len(self.store.config.entries()["entries"]), 1)

    def test_upgrade_is_explicit_backed_up_and_does_not_grant_sources(self):
        self.store.config.write_file("settings.json", {"format": 0, "transport": {"kind": "stdio"}})
        result = self.cli("config", "upgrade")
        self.assertTrue(result["upgraded"])
        self.assertFalse(result["permissions_changed"])
        self.assertTrue((self.home / result["backup"]).is_file())
        self.assertEqual(self.store.config.entries()["entries"], [])

    def test_unknown_config_and_literal_secret_fields_fail_closed(self):
        self.store.config.write_file("settings.json", {"format": 1, "revision": 1, "transport": {"kind": "stdio"}, "api_key": SECRET})
        result = self.cli("config", "validate", code=2)
        self.assertIn("unsupported_config_format", result["error"])

    def test_config_symlink_and_world_readable_file_are_rejected(self):
        filename = self.home / "config/settings.json"
        target = self.extra / "target.json"
        target.write_bytes(filename.read_bytes())
        filename.unlink()
        filename.symlink_to(target)
        self.cli("config", "validate", code=2)
        filename.unlink()
        filename.write_bytes(target.read_bytes())
        filename.chmod(0o644)
        self.cli("config", "validate", code=2)

    def test_keychain_namespace_is_instance_specific_and_info_never_reads_value(self):
        other = Store(self.extra / "another")
        self.assertNotEqual(self.store.keychain().service, other.keychain().service)
        with patch("observer.credentials.Keychain.get", side_effect=AssertionError("no value")):
            result = self.cli("credentials", "info")
        self.assertFalse(result["value_read"])

    def test_credential_set_cannot_take_stdin_or_arguments_as_secret(self):
        with patch("sys.stdin.isatty", return_value=False), patch("observer.credentials.Keychain.save_from_local_settings") as save:
            self.cli("credentials", "set", "--approve", code=2)
        save.assert_not_called()
        self.cli("credentials", "set", "--api-key", SECRET, code=2)

    def test_doctor_distinguishes_remote_metadata_and_end_to_end(self):
        result = self.cli("doctor")
        self.assertFalse(result["remote_ready"])
        self.assertEqual(result["layers"]["metadata"]["status"], "not_observed_in_ChatGPT")
        self.assertEqual(result["layers"]["end-to-end"]["status"], "not_observed")
        self.assertEqual(result["layers"]["local"]["status"], "not_running")

    def test_environment_to_child_and_config_do_not_inherit_keys(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": SECRET, "CONTROL_PLANE_API_KEY": SECRET, "PYTHONPATH": SECRET}):
            self.assertNotIn(SECRET, json.dumps(runtime.environment()))
        self.assertNotIn("CONTROL_PLANE_API_KEY", runtime.environment())

    def test_installation_doctor_before_init_does_not_create_an_instance(self):
        empty = self.extra / "not-initialized"
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--home", str(empty), "doctor", "--level", "installation"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["layers"]["installation"]["status"], "available")
        self.assertFalse(empty.exists())

    def test_initialization_wizard_uses_same_explicit_source_confirmation(self):
        inputs = ["init", "1", str(self.base / "workspace"), "wizard", "approve", "0"]
        output = io.StringIO()
        with (patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=inputs),
              patch("observer.credentials.Keychain.get", side_effect=AssertionError("no key")),
              redirect_stdout(output), redirect_stderr(io.StringIO())):
            self.assertEqual(main(["--home", str(self.home), "init"]), 0)
        self.assertEqual(self.store.config.entries()["entries"][0]["alias"], "wizard")
        self.assertIn('"service_started":false', output.getvalue())

    def test_local_probe_failure_does_not_relabel_valid_config_as_invalid(self):
        with patch("observer.cli.probe", side_effect=Refusal("synthetic_probe_failure")):
            result = self.cli("doctor", "--probe")
        self.assertEqual(result["layers"]["config"]["status"], "valid")
        self.assertEqual(result["layers"]["local"]["status"], "probe_blocked")
        self.assertFalse(result["remote_ready"])

    def test_empty_profile_cannot_start_reading_or_serving(self):
        self.cli("serve", code=2)
        self.assertFalse(self.cli("config", "validate")["service_can_start"])

    def test_uninstall_is_reviewable_plan_never_removes_sources_or_keychain(self):
        with patch("observer.credentials.Keychain.get", side_effect=AssertionError("no value")):
            result = self.cli("uninstall")
        self.assertTrue(result["plan_only"])
        self.assertFalse(result["observed_sources_deleted"])
        self.assertTrue(self.home.exists())

class LauncherCompatibilityTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.container = tempfile.TemporaryDirectory(prefix="launcher-", dir=Path("/tmp").resolve())
        self.addCleanup(self.container.cleanup)
        self.root = Path(self.container.name)
        shutil.copyfile(PROJECT/"Observer.command", self.root/"Observer.command")
        python = self.root/".venv/bin/python"
        python.parent.mkdir(parents=True)
        # Operator launcher shim prints argv only: no Python, GUI or source runs.
        python.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
        python.chmod(0o700)

    def launch(self):
        import subprocess
        return subprocess.run(["/bin/sh",str(self.root/"Observer.command")], env=runtime.environment(),
                              capture_output=True,text=True,timeout=5)

    def test_legacy_state_never_invokes_archived_native_controls_or_reads_settings(self):
        (self.root/".local/observer-control").mkdir(parents=True)
        (self.root/"scripts").mkdir()
        (self.root/"scripts/observer_local.py").write_text("not executed")
        (self.root/"observer.tunnel-test.json").write_text("not parsed by launcher")
        before = {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        result=self.launch()
        self.assertEqual(result.returncode,2)
        self.assertIn("Legacy operator state detected",result.stdout)
        self.assertNotIn(str(self.root/"scripts/observer_local.py"),result.stdout)
        self.assertNotIn("from observer.cli import main",result.stdout)
        self.assertFalse((self.root/".local/observer-control/approvals.json").exists())
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_legacy_state_with_missing_entry_refuses_new_empty_profile(self):
        (self.root/".local/observer-control").mkdir(parents=True)
        result=self.launch()
        self.assertEqual(result.returncode,2)
        self.assertIn("Refusing to open a new empty instance",result.stdout)
        self.assertNotIn("from observer.cli import main",result.stdout)

    def test_fresh_public_checkout_uses_the_same_cli_core(self):
        result=self.launch()
        self.assertEqual(result.returncode,0)
        self.assertIn("from observer.cli import main",result.stdout)
        self.assertIn("Opening the new CLI instance menu",result.stdout)

class LegacySchemaContentTests(ObserverCase):
    def setup_output(self):
        value = "公开输出 " * 4000 + "password=" + SECRET + "\nTAIL"
        path = self.extra / "legacy-schema.jsonl"
        jsonl(path, [metadata("legacy-schema", self.extra),
            event("response_item", {"type": "function_call", "name": "exec_command", "call_id": "compat", "arguments": json.dumps({"cmd": "synthetic"})}),
            event("response_item", {"type": "function_call_output", "call_id": "compat", "output": {"output": value, "exit_code": 0}})])
        preview = self.good("session_read", source="cases", session_id="legacy-schema")
        result = next(e for e in preview["events"] if e.get("phase") == "result")
        return path, result["content_cursors"]["output"], self.observer.redactor.text(value), preview

    def test_old_four_argument_schema_retrieves_complete_redacted_output(self):
        _, cursor, expected, _ = self.setup_output()
        pieces = []
        for _ in range(50):
            args = {"source": "cases", "session_id": "legacy-schema", "limit": 50, "cursor": cursor}
            self.assertLessEqual(set(args), {"source", "session_id", "cursor", "limit"})
            page = self.good("session_read", **args)
            self.assertEqual(page["mode"], "field_content")
            self.assertEqual(page["char_start"], sum(map(len, pieces)))
            pieces.append(page["content"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual("".join(pieces), expected)
        self.assertGreater(len(pieces), 1)

    def test_content_capability_cannot_cross_source_id_or_operation(self):
        _, cursor, _, _ = self.setup_output()
        self.denied("session_read", source="synthetic", session_id="synth-main", cursor=cursor)
        self.denied("session_read", source="cases", session_id="wrong-id", cursor=cursor)
        self.denied("workspace_read", alias="other", path="legacy-schema.jsonl", cursor=cursor)
        self.denied("session_state", source="cases", session_id="legacy-schema", cursor=cursor)
        self.denied("session_read", source="cases", session_id="legacy-schema", cursor=cursor[:-1] + "!")

    def test_content_capability_expires_and_rejects_changed_version(self):
        path, cursor, _, _ = self.setup_output()
        with patch("observer.security.time.monotonic", return_value=10**20):
            self.assertEqual(self.denied("session_read", source="cases", session_id="legacy-schema", cursor=cursor)["error"], "invalid_cursor")
        _, cursor, _, _ = self.setup_output()
        with path.open("ab") as stream:
            stream.write(b"\n")
        self.assertEqual(self.denied("session_read", source="cases", session_id="legacy-schema", cursor=cursor)["error"], "source_changed")

    def test_preview_cursor_still_polls_only_appended_events(self):
        path, _, _, preview = self.setup_output()
        with path.open("ab") as stream:
            stream.write(canonical(event("event_msg", {"type": "agent_message", "message": "only delta"})) + b"\n")
        page = self.good("session_read", source="cases", session_id="legacy-schema", cursor=preview["next_cursor"])
        self.assertEqual([e["text"] for e in page["events"]], ["only delta"])

    def test_git_commit_message_uses_only_legacy_cursor_argument(self):
        root = self.extra / "repo"
        init_repo(root, False)
        git(root, "commit", "--allow-empty", "-qm", "public message " * 2000)
        config = Config(PROJECT, {"workspaces": {"git": str(root)}, "sessions": {}, "strict_hardlinks": True})
        self.addCleanup(config.close)
        self.observer = Observer(config)
        first = self.good("git_history", alias="git", limit=1)["commits"][0]
        cursor, pieces = first["content_cursor"], []
        while cursor:
            page = self.good("git_history", alias="git", cursor=cursor)
            pieces.append(page["message"])
            cursor = page["next_cursor"]
        self.assertEqual("".join(pieces), ("public message " * 2000).strip())

class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        parent = Path("/tmp").resolve()
        self.container = tempfile.TemporaryDirectory(prefix="p-", dir=parent)
        self.addCleanup(self.container.cleanup)
        self.base = Path(self.container.name)
        self.store = Store(self.base / "i")
        self.store.initialize()
        source = self.base / "code"
        source.mkdir()
        (source / "public.py").write_text("public stable source\n")
        self.source = source
        self.store.config.register_workspace("code", str(source), lambda _: True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        try:
            runtime.stop(self.store)
        except Exception:
            pass

    def test_actual_start_connect_probe_repeat_stop_without_any_keychain(self):
        original = (self.source / "public.py").read_bytes()
        with patch("observer.credentials.Keychain.get", side_effect=AssertionError("stdio needs no key")):
            started = runtime.start(self.store)
            self.assertFalse(started["ready"])
            self.assertEqual(runtime.start(self.store)["action"], "already_started")
            result = asyncio.run(probe(self.store, managed=True))
            self.assertEqual(result["readonly_tools"], 13)
            self.assertEqual(result["remote_readiness"], "not_observed")
            self.assertEqual(runtime.stop(self.store)["action"], "owned_instance_stopped")
            self.assertEqual(runtime.stop(self.store)["action"], "already_stopped")
        self.assertEqual((self.source / "public.py").read_bytes(), original)

    def test_running_snapshot_does_not_silently_take_new_grants(self):
        runtime.start(self.store)
        before = self.store.state.read_file("active.json")
        other = self.base / "other"
        other.mkdir()
        self.store.config.register_workspace("other", str(other), lambda _: True)
        status = runtime.status(self.store)
        self.assertTrue(status["configuration_pending"])
        self.assertEqual(status["active_sources"], 1)
        self.assertEqual(self.store.state.read_file("active.json"), before)

    def test_unreachable_lock_holder_is_never_killed_or_taken_over(self):
        import fcntl
        with self.store.state.directory() as directory:
            fd = os.open("manager.lock", os.O_RDWR | os.O_CREAT, 0o600, dir_fd=directory)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("observer.runtime.subprocess.Popen") as spawn, patch("observer.runtime.os.killpg") as kill:
                with self.assertRaises(Refusal):
                    runtime.start(self.store)
                with self.assertRaises(Refusal):
                    runtime.stop(self.store)
            spawn.assert_not_called()
            kill.assert_not_called()
        finally:
            os.close(fd)

    def test_stale_socket_is_not_unlinked_automatically(self):
        import socket
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = runtime.socket_path(self.store, "control.sock")
        listener.bind(path)
        listener.close()
        os.chmod(path, 0o600)
        with self.assertRaises(Refusal):
            runtime.start(self.store)
        self.assertTrue(os.path.exists(path))

    def test_local_probe_without_daemon_is_ephemeral_and_remote_unknown(self):
        result = asyncio.run(probe(self.store, managed=False))
        self.assertEqual(result["version"], "0.1.0")
        self.assertEqual(runtime.status(self.store)["manager"], "not_running")

    def test_tunnel_adapter_uses_only_mocked_instance_key_and_clears_environment(self):
        import threading
        stopped = threading.Event()
        binary = self.base / "synthetic-client"
        binary.write_text("not executed")
        binary.chmod(0o700)
        tunnel = {"kind": "tunnel", "client": str(binary), "tunnel_id": "tunnel_" + "a"*32}
        self.store.set_transport(tunnel)
        keychain = Mock()
        keychain.get.return_value = "SYNTHETIC_RUNTIME_ONLY_CANARY"
        captured = {}
        child = Mock(pid=99999999)
        def launch(args, **kwargs):
            self.assertNotIn(keychain.get.return_value, str(args))
            self.assertEqual(kwargs["env"]["CONTROL_PLANE_API_KEY"], keychain.get.return_value)
            captured["environment"] = kwargs["env"]
            stopped.set()
            return child
        with (patch.object(self.store, "keychain", return_value=keychain),
              patch("observer.runtime.threading.Event", return_value=stopped),
              patch("observer.runtime.subprocess.Popen", side_effect=launch),
              patch("observer.runtime.kill_owned") as kill):
            self.assertEqual(runtime.manage(self.store), 0)
        kill.assert_called_once_with(child)
        self.assertEqual(captured["environment"], {})
        for path in self.store.home.rglob("*"):
            if path.is_file():
                self.assertNotIn(keychain.get.return_value.encode(), path.read_bytes())
        self.assertFalse((self.store.home/"state/active.json").exists())
        self.assertFalse((self.store.home/"state/transport.json").exists())
        config = runtime.client_config(self.store, tunnel)
        self.assertIn("env -i", config["mcp"]["commands"][0]["command"])
        self.assertFalse(config["admin_ui"]["open_browser"])
        self.assertFalse(config["cloudflared"]["managed"])

    def test_missing_mocked_key_leaves_no_active_config_or_socket(self):
        binary = self.base/"not-executed-client"
        binary.write_text("not executed")
        binary.chmod(0o700)
        self.store.set_transport({"kind":"tunnel", "client":str(binary), "tunnel_id":"tunnel_"+"a"*32})
        keychain = Mock()
        keychain.get.side_effect = Refusal("runtime_key_not_available")
        with patch.object(self.store,"keychain",return_value=keychain), patch("observer.runtime.subprocess.Popen") as launch:
            self.assertEqual(runtime.manage(self.store),2)
        launch.assert_not_called()
        self.assertFalse(runtime.locked(self.store))
        self.assertFalse((self.store.home/"state/active.json").exists())
        self.assertFalse((self.store.home/"state/transport.json").exists())
