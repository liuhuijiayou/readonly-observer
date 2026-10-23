"""Local operator approval store. This module is never exposed as an MCP tool."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import pwd
import re
import secrets
import stat
from types import MappingProxyType

from .fs import Root, DIR_FLAGS, FILE_FLAGS, components, identity, sensitive, signature
from .references import parse_reference
from .security import Budget, Refusal, canonical

CONTROL = ".local/observer-control"
APPROVALS = "approvals.json"

def alias_valid(alias):
    if not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", alias):
        raise Refusal("invalid_registration_alias")

def absolute_path(path, workspace=False):
    if not isinstance(path, str) or not path.startswith("/"):
        raise Refusal("absolute_local_path_required")
    components(path[1:])
    if workspace and ".codex" in path.split("/"):
        raise Refusal("codex_directory_requires_exact_session_registration")
    home = pwd.getpwuid(os.getuid()).pw_dir
    if path in {home, "/", "/Users", "/Users/Shared", "/tmp", "/var", "/private", "/Volumes"}:
        raise Refusal("broad_root_denied")
    # Do not allow credential directories to become new public roots.
    if any(part in {".ssh", ".aws", ".azure", ".gnupg", ".kube", "auth", "credentials", "secrets"}
           for part in path.split("/")) or (workspace and sensitive(path.rsplit("/", 1)[-1])):
        raise Refusal("sensitive_registration_path")
    return path

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate_registry_key")
        result[key] = value
    return result

class ApprovalRegistry:
    def __init__(self, project, control=CONTROL):
        components(control)
        self.project, self.control = project, control

    @contextmanager
    def directory(self, create=False):
        root = Root("local", str(self.project), workspace=False)
        fd = os.dup(root.fd)
        try:
            for part in self.control.split("/"):
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise Refusal("private_control_directory_required")
            yield fd
        finally:
            os.close(fd)
            root.close()

    @staticmethod
    def regular(fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise Refusal("private_control_file_required")

    def read_file(self, name, default=None):
        components(name)
        if "/" in name:
            raise Refusal("invalid_control_name")
        try:
            with self.directory() as directory:
                fd = os.open(name, FILE_FLAGS, dir_fd=directory)
                try:
                    self.regular(fd)
                    before = signature(os.fstat(fd))
                    raw = os.read(fd, 65537)
                    if len(raw) > 65536 or signature(os.fstat(fd)) != before:
                        raise Refusal("invalid_control_file")
                    return json.loads(raw, object_pairs_hook=unique)
                finally:
                    os.close(fd)
        except FileNotFoundError:
            return default

    def write_file(self, name, value):
        components(name)
        if "/" in name:
            raise Refusal("invalid_control_name")
        raw = canonical(value)
        if len(raw) > 65536:
            raise Refusal("registry_limit")
        with self.directory(create=True) as directory:
            try:
                fd = os.open(name, FILE_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                try:
                    self.regular(fd)
                finally:
                    os.close(fd)
            temporary = ".pending-" + secrets.token_hex(12)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def entries(self):
        data = self.read_file(APPROVALS, {"format": 1, "revision": 0, "entries": []})
        if (not isinstance(data, dict) or set(data) != {"format", "revision", "entries"}
                or data["format"] != 1 or type(data["revision"]) is not int
                or not isinstance(data["entries"], list) or len(data["entries"]) > 12):
            raise Refusal("invalid_approval_registry")
        for entry in data["entries"]:
            common = {"kind", "alias", "path", "identity", "approved_at", "approval"}
            if not isinstance(entry, dict) or entry.get("kind") not in {"workspace", "session"}:
                raise Refusal("invalid_approval_registry")
            expected = common if entry["kind"] == "workspace" else common | {"session_id", "references"}
            if set(entry) != expected or entry["approval"] != "local_operator":
                raise Refusal("invalid_approval_registry")
            alias_valid(entry["alias"])
            absolute_path(entry["path"], entry["kind"] == "workspace")
            if (not isinstance(entry["identity"], list) or len(entry["identity"]) != 2
                    or any(type(i) is not int for i in entry["identity"])):
                raise Refusal("invalid_approval_registry")
            if entry["kind"] == "session":
                if (not entry["path"].endswith(".jsonl") or not isinstance(entry["references"], list)
                        or len(entry["references"]) > 2 or parse_reference(entry["session_id"])[0] != "local"):
                    raise Refusal("invalid_approval_registry")
                for reference in entry["references"]:
                    if parse_reference(reference)[0] != "cloud":
                        raise Refusal("invalid_approval_registry")
        return data

    def _save(self, entry):
        data = self.entries()
        if any(e["alias"] == entry["alias"] or (e["kind"], e["path"]) == (entry["kind"], entry["path"])
               for e in data["entries"]):
            raise Refusal("registration_exists; remove_locally_before_reapproval")
        if len(data["entries"]) >= 12 or sum(e["kind"] == entry["kind"] for e in data["entries"]) >= 8:
            raise Refusal("registration_limit")
        data["entries"].append(entry)
        data["revision"] += 1
        self.write_file(APPROVALS, data)

    def register_workspace(self, alias, path, confirm):
        alias_valid(alias)
        path = absolute_path(path, True)
        preview = {"kind": "workspace", "alias": alias, "path": path,
                   "scope": "safe code/docs, uncommitted changes and fixed Git history; excludes credentials; readonly"}
        if confirm(preview) is not True:
            raise Refusal("local_approval_required")
        root = Root(alias, path)
        try:
            entry = {"kind": "workspace", "alias": alias, "path": path, "identity": root.pinned,
                     "approval": "local_operator", "approved_at": datetime.now(timezone.utc).isoformat()}
            self._save(entry)
        finally:
            root.close()
        return entry

    def register_session(self, alias, path, reference, confirm):
        alias_valid(alias)
        path = absolute_path(path)
        if not path.endswith(".jsonl"):
            raise Refusal("exact_jsonl_file_required; ephemeral_sessions_have_no_recoverable_log")
        parsed = parse_reference(reference) if reference else None
        if confirm({"kind": "session_file", "alias": alias, "path": path,
                    "reference": reference, "scope": "this exact JSONL only; public messages/tools, no internal reasoning"}) is not True:
            raise Refusal("local_approval_required")
        parent, filename = path.rsplit("/", 1)
        root = Root(alias, parent, workspace=False)
        try:
            fd = root.file(filename)
            try:
                version = os.fstat(fd)
                with os.fdopen(os.dup(fd), "rb") as stream:
                    raw = stream.readline(262145)
                if len(raw) > 262144 or not raw.endswith(b"\n"):
                    raise Refusal("invalid_session_metadata")
                event = json.loads(raw)
                payload = event.get("payload")
                from .sessions import public_channel
                if (event.get("type") != "session_meta" or not isinstance(payload, dict)
                        or not public_channel(event) or not public_channel(payload)):
                    raise Refusal("invalid_session_metadata")
                sid = payload.get("id")
                if parse_reference(sid)[0] != "local" or signature(os.fstat(fd)) != signature(version):
                    raise Refusal("invalid_session_metadata")
            finally:
                os.close(fd)
            if parsed and parsed[0] == "local" and parsed[1] != sid:
                raise Refusal("session_reference_metadata_mismatch")
            references = [] if not parsed or parsed[0] == "local" else [parsed[1]]
            if references and references[0].startswith("https://chatgpt.com/codex/tasks/task_"):
                references.append(references[0].rsplit("/", 1)[1])
            entry = {"kind": "session", "alias": alias, "path": path, "identity": identity(version),
                     "session_id": sid, "references": references, "approval": "local_operator",
                     "approved_at": datetime.now(timezone.utc).isoformat()}
            if confirm({**entry, "scope": "confirm explicit link-to-metadata mapping; cloud IDs are not assumed local IDs"}) is not True:
                raise Refusal("local_mapping_approval_required")
            self._save(entry)
            return entry
        finally:
            root.close()

    def remove(self, alias, confirm):
        alias_valid(alias)
        data = self.entries()
        matches = [e for e in data["entries"] if e["alias"] == alias]
        if len(matches) != 1:
            raise Refusal("registration_not_found")
        if confirm(matches[0]) is not True:
            raise Refusal("local_approval_required")
        data["entries"] = [e for e in data["entries"] if e["alias"] != alias]
        data["revision"] += 1
        self.write_file(APPROVALS, data)

def effective_config(project, base_values, registry=None):
    """Validate the entire local manifest before opening any registered source."""
    from .config import Config
    values = json.loads(json.dumps(base_values))
    values.setdefault("session_files", {})
    entries = (registry or ApprovalRegistry(project)).entries()["entries"]
    references = {}
    for entry in entries:
        alias = entry["alias"]
        if alias in values["workspaces"] or alias in values["sessions"]:
            raise Refusal("registration_alias_conflict")
        if entry["kind"] == "workspace":
            values["workspaces"][alias] = entry["path"]
        else:
            parent, filename = entry["path"].rsplit("/", 1)
            values["sessions"][alias] = parent
            values["session_files"][alias] = {"path": filename, "session_id": entry["session_id"]}
            for reference in entry["references"]:
                references[(alias, reference)] = entry["session_id"]
    config = Config(project, values)
    try:
        for entry in entries:
            if entry["kind"] == "workspace":
                current = config.workspaces[entry["alias"]].pinned
            else:
                root = config.sessions[entry["alias"]]
                fd = root.file(entry["path"].rsplit("/", 1)[1])
                try:
                    current = identity(os.fstat(fd))
                finally:
                    os.close(fd)
                from .sessions import SessionReader
                from .security import Cursors, Redactor
                SessionReader(config, Redactor(), Cursors()).metadata(entry["alias"], entry["path"].rsplit("/", 1)[1], Budget())
            if current != entry["identity"]:
                raise Refusal("approved_source_replaced; reapprove_locally")
        config.session_references = MappingProxyType(references)
        return config
    except BaseException:
        config.close()
        raise
