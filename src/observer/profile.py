"""Private, instance-scoped operator configuration. Never exposed over MCP."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from .fs import DIR_FLAGS, Root, components
from .registry import ApprovalRegistry, APPROVALS, effective_config, unique
from .security import Refusal, canonical
from .credentials import Keychain

DEFAULTS = {"format": 1, "revision": 1, "transport": {"kind": "stdio"}}

def location(value=None):
    if value is None:
        value = os.environ.get("OBSERVER_HOME")
    if value is None:
        value = (Path.home() / "Library/Application Support/ReadOnlyObserver" if sys.platform == "darwin"
                 else Path.home() / ".local/share/readonly-observer")
    path = Path(value).expanduser().absolute()
    components(str(path)[1:])
    if str(path) == str(Path.home()) or len(path.parts) < 3:
        raise Refusal("unsafe_instance_home")
    return path

def private_directory(path):
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in components(str(path)[1:]):
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise Refusal("private_instance_directory_required")
    finally:
        os.close(fd)

class Store:
    def __init__(self, home=None):
        self.home = location(home)
        self.config = ApprovalRegistry(self.home, "config")
        self.state = ApprovalRegistry(self.home, "state")

    def initialize(self):
        private_directory(self.home)
        for folder in ("config", "state", "cache", "logs"):
            private_directory(self.home / folder)
        if self.config.read_file("settings.json") is None:
            self.config.write_file("settings.json", DEFAULTS)
        else:
            self.settings()
        if self.config.read_file(APPROVALS) is None:
            self.config.write_file(APPROVALS, {"format": 1, "revision": 0, "entries": []})
        self.config.entries()
        return {"initialized": True, "instance_home": str(self.home), "sources": len(self.config.entries()["entries"]),
                "credential_accessed": False, "service_started": False}

    def require(self):
        if self.config.read_file("settings.json") is None:
            raise Refusal("not_initialized; run_observer_init")
        self.settings()

    def settings(self):
        value = self.config.read_file("settings.json")
        self.validate_settings(value)
        return value

    @staticmethod
    def validate_settings(value):
        if (not isinstance(value, dict) or set(value) != {"format", "revision", "transport"}
                or type(value["format"]) is not int or value["format"] != 1
                or type(value["revision"]) is not int or value["revision"] < 1):
            raise Refusal("unsupported_config_format; explicit_upgrade_required")
        transport = value["transport"]
        if not isinstance(transport, dict) or transport.get("kind") not in {"stdio", "tunnel"}:
            raise Refusal("invalid_transport")
        if transport["kind"] == "stdio":
            if set(transport) != {"kind"}:
                raise Refusal("invalid_transport")
        elif (set(transport) != {"kind", "client", "tunnel_id"}
              or not isinstance(transport["client"], str) or not transport["client"].startswith("/")
              or not isinstance(transport["tunnel_id"], str)
              or not re.fullmatch(r"tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}", transport["tunnel_id"])):
            raise Refusal("invalid_tunnel_settings; credentials_are_not_config_values")

    @contextmanager
    def mutation(self):
        self.require()
        with self.config.directory() as directory:
            fd = os.open("operator.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                self.config.regular(fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Refusal("configuration_busy") from None
                yield
            finally:
                os.close(fd)

    def backup(self, reason):
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
        name = "backup-" + tag + ".json"
        self.config.write_file(name, {"reason": reason, "settings": self.config.read_file("settings.json"),
                                      "approvals": self.config.read_file(APPROVALS)})
        return "config/" + name

    def set_transport(self, transport):
        with self.mutation():
            value = self.settings()
            value = {**value, "revision": value["revision"] + 1, "transport": transport}
            self.validate_settings(value)
            backup = self.backup("transport_change")
            self.config.write_file("settings.json", value)
            return {"saved": True, "backup": backup, "activation": "next_explicit_start; current_service_unchanged"}

    def upgrade(self):
        # Only the narrowly specified empty-permission settings v0 is accepted.
        # Approval records are never inferred, broadened or imported by upgrade.
        old = self.config.read_file("settings.json")
        if isinstance(old, dict) and old.get("format") == 1:
            self.settings()
            return {"upgraded": False, "format": 1}
        if old != {"format": 0, "transport": {"kind": "stdio"}}:
            raise Refusal("unsupported_upgrade; existing_files_unchanged")
        with self.config.directory() as directory:
            fd = os.open("operator.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                self.config.regular(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                backup = self.backup("v0_to_v1_no_permission_change")
                self.config.write_file("settings.json", DEFAULTS)
            finally:
                os.close(fd)
        return {"upgraded": True, "backup": backup, "permissions_changed": False}

    def snapshot(self):
        return {"settings": self.settings(), "approvals": self.config.entries()}

    def configuration(self, active=False):
        data = self.state.read_file("active.json") if active else self.snapshot()
        if not isinstance(data, dict) or set(data) != {"settings", "approvals"}:
            raise Refusal("active_configuration_unavailable")
        self.validate_settings(data["settings"])
        if not isinstance(data["approvals"], dict):
            raise Refusal("invalid_registry")
        if not data["approvals"].get("entries"):
            raise Refusal("no_sources_registered; add_a_project_or_exact_session")
        class Frozen:
            def entries(self):
                return data["approvals"]
        # Validate the frozen schema by an existing registry validator, without
        # opening unapproved locations or loading arbitrary remote paths.
        validator = ApprovalRegistry(self.home, "state")
        original = validator.read_file
        validator.read_file = lambda *a, **k: data["approvals"]
        validator.entries()
        validator.read_file = original
        config = effective_config(self.home, {"workspaces": {}, "sessions": {}, "strict_hardlinks": True}, Frozen())
        config.project = self.home / "cache"  # private Git scratch never lives in observed repositories
        return config

    def keychain(self):
        service = ("readonly-observer." + hashlib.sha256(str(self.home).encode()).hexdigest()[:24] + ".tunnel-runtime").encode()
        return Keychain(service=service)

    def read_import(self, filename):
        path = Path(filename).expanduser().absolute()
        root = Root("import", str(path.parent), workspace=False)
        try:
            raw = root.read(path.name).raw
            if len(raw) > 65536:
                raise Refusal("import_limit")
            value = json.loads(raw, object_pairs_hook=unique)
        finally:
            root.close()
        if not isinstance(value, dict):
            raise Refusal("invalid_import")
        if set(value) == {"format", "revision", "entries"}:
            candidates = value.get("entries", [])
            if not isinstance(candidates, list) or len(candidates) > 12:
                raise Refusal("invalid_import")
            rows = []
            for item in candidates:
                if not isinstance(item, dict) or item.get("kind") not in {"workspace", "session"}:
                    raise Refusal("invalid_import")
                rows.append({"kind": item["kind"], "alias": item.get("alias"), "path": item.get("path"),
                             "reference": (item.get("references") or [item.get("session_id", "")])[0]})
            return rows
        required = {"workspaces", "sessions", "strict_hardlinks"}
        if set(value) not in (required, required | {"session_files"}) or value.get("strict_hardlinks") is not True:
            raise Refusal("invalid_or_unsafe_legacy_import")
        if not isinstance(value["workspaces"], dict) or not isinstance(value["sessions"], dict):
            raise Refusal("invalid_import")
        scopes = value.get("session_files", {})
        if set(scopes) != set(value["sessions"]):
            raise Refusal("broad_session_import_denied; select_exact_JSONL_files")
        rows = []
        for alias, source in value["workspaces"].items():
            location = Path(source) if isinstance(source, str) else None
            if location is None:
                raise Refusal("invalid_import")
            path_value = location if location.is_absolute() else path.parent / location
            # Dot is valid for the local operator's legacy project root.
            path_value = Path(os.path.abspath(path_value))
            rows.append({"kind": "workspace", "alias": alias, "path": str(path_value), "reference": ""})
        for alias, source in value["sessions"].items():
            scope = scopes[alias]
            if not isinstance(source, str) or not isinstance(scope, dict) or set(scope) != {"path", "session_id"}:
                raise Refusal("invalid_import")
            components(scope["path"])
            parent = Path(source) if source.startswith("/") else path.parent / source
            rows.append({"kind": "session", "alias": alias, "path": str(parent / scope["path"]), "reference": scope["session_id"]})
        return rows

    def import_sources(self, filename, confirm):
        rows = self.read_import(filename)
        if confirm({"import_sources": rows, "scope": "explicit new local grants; current runtime remains unchanged"}) is not True:
            raise Refusal("local_approval_required")
        with self.mutation():
            old = self.config.entries()
            backup = self.backup("explicit_source_import")
            try:
                for row in rows:
                    if row["kind"] == "workspace":
                        self.config.register_workspace(row["alias"], row["path"], confirm)
                    else:
                        self.config.register_session(row["alias"], row["path"], row["reference"], confirm)
            except BaseException:
                self.config.write_file(APPROVALS, old)
                raise
        return {"imported_sources": len(rows), "backup": backup, "service_restarted": False}
