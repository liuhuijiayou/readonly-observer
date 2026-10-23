"""Fixed public API with non-echoing validation and common final redaction."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from .fs import components, sensitive
from . import __version__
from .gitreader import (GitReader, GIT_SNAPSHOT_BYTES, GIT_WORKTREE_BYTES,
                        GIT_OBJECT_FILE_BYTES, GIT_FILE_BYTES, GIT_ENTRIES,
                        GIT_SNAPSHOT_SECONDS, GIT_QUERY_SECONDS, GIT_ALLOC_BYTES)
from .security import CURSOR_TTL, MAX_CURSORS, MAX_CURSOR_BYTES, MAX_INPUT_FRAME, Cursors, Redactor, Refusal, canonical, envelope
from .sessions import SessionReader
from .workspace import WorkspaceReader

STRING = {"type": "string", "maxLength": 2048}
ALIAS = {"type": "string", "maxLength": 2048}
CURSOR = {"type": "string", "maxLength": 64}
LIMIT = {"type": "integer", "minimum": 1, "maximum": 50}
BOOL = {"type": "boolean"}
ALIASES = {"type": "array", "items": ALIAS, "minItems": 1, "maxItems": 8, "uniqueItems": True}
LINE = {"type": "integer", "minimum": 1, "maximum": 10000000}
PATHS = {"type": "array", "items": STRING, "maxItems": 20, "uniqueItems": True}


def spec(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


SPECS = {
    "observer_info": ("Approved aliases, actual limits and unavailable capabilities.", spec({})),
    "workspace_list": ("List a safe directory independently of Git.", spec({"alias": ALIAS, "path": STRING, "limit": LIMIT, "cursor": CURSOR}, ["alias"])),
    "workspace_read": ("Read complete redacted UTF-8 source with line/character pages and source version. Alias accepts an exact locally approved project path.", spec({"alias": ALIAS, "path": STRING, "start_line": LINE, "end_line": LINE, "cursor": CURSOR}, ["alias", "path"])),
    "workspace_glob": ("Find safe files in explicitly selected roots. Literal directory prefixes/exact files bound the scan; broad selections can hit unchanged safety limits.", spec({"aliases": ALIASES, "pattern": STRING, "limit": LIMIT, "cursor": CURSOR}, ["aliases", "pattern"])),
    "workspace_search": ("Literal or timed regex search on redacted safe sources; use pattern with a literal directory prefix or exact file to bound inventory.", spec({"aliases": ALIASES, "query": STRING, "regex": BOOL, "pattern": STRING, "limit": LIMIT, "cursor": CURSOR}, ["aliases", "query"])),
    "session_list": ("List only operator-approved session sources; no name search or global history discovery.", spec({"sources": ALIASES, "limit": LIMIT, "cursor": CURSOR}, ["sources"])),
    "session_read": ("Read approved events by exact ID or mapped link. Long fields expose content_cursors[field]: pass one as the existing cursor to read complete content; detail_cursor+field also supported. No raw reasoning.", spec({"source": ALIAS, "session_id": STRING, "limit": LIMIT, "cursor": CURSOR, "detail_cursor": CURSOR, "field": STRING}, ["source", "session_id"])),
    "session_search": ("Search projected, redacted events in selected sources; optional exact ID or explicitly mapped link, never history discovery.", spec({"sources": ALIASES, "query": STRING, "regex": BOOL, "session_id": STRING, "limit": LIMIT, "cursor": CURSOR}, ["sources", "query"])),
    "session_state": ("Historical lifecycle and recency; current activity and task verification remain unknown.", spec({"source": ALIAS, "session_id": STRING, "cursor": CURSOR}, ["source", "session_id"])),
    "git_status": ("NUL-parsed status from a sealed safe snapshot, including hidden-state counts.", spec({"alias": ALIAS, "paths": PATHS, "limit": LIMIT, "cursor": CURSOR}, ["alias"])),
    "git_diff": ("Bounded redacted patch; fixed arguments, safe selected paths.", spec({"alias": ALIAS, "paths": PATHS, "staged": BOOL, "cursor": CURSOR}, ["alias"])),
    "git_history": ("Redacted HEAD history. For a complete long commit message pass content_cursor as the existing cursor; message_cursor also supported.", spec({"alias": ALIAS, "paths": PATHS, "limit": LIMIT, "cursor": CURSOR, "message_cursor": CURSOR}, ["alias"])),
    "evidence_link": ("Associate exact session cwd, source hash, Git and a bounded first event page; session_next_cursor continues with session_read. No causal or correctness claims.", spec({"source": ALIAS, "session_id": STRING, "alias": ALIAS, "path": STRING}, ["source", "session_id", "alias", "path"])),
}


def validate(arguments, schema):
    if not isinstance(arguments, dict) or set(arguments) - set(schema["properties"]) or not set(schema["required"]) <= set(arguments):
        raise Refusal("invalid_arguments")
    for name, value in arguments.items():
        rule = schema["properties"][name]
        kind = rule["type"]
        if kind == "string":
            if not isinstance(value, str) or len(value) > rule.get("maxLength", 2048) or "\x00" in value:
                raise Refusal("invalid_arguments")
            if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
                raise Refusal("invalid_arguments")
        elif kind == "integer":
            if not isinstance(value, int) or isinstance(value, bool) or not rule["minimum"] <= value <= rule["maximum"]:
                raise Refusal("invalid_arguments")
        elif kind == "boolean":
            if not isinstance(value, bool):
                raise Refusal("invalid_arguments")
        elif kind == "array":
            if not isinstance(value, list) or not rule.get("minItems", 0) <= len(value) <= rule["maxItems"]:
                raise Refusal("invalid_arguments")
            if not all(isinstance(v, str) and len(v) <= 2048 for v in value) or len(set(value)) != len(value):
                raise Refusal("invalid_arguments")
            if "pattern" in rule["items"] and any(not re.fullmatch(rule["items"]["pattern"], v) for v in value):
                raise Refusal("invalid_arguments")
        if name in {"query", "keyword", "pattern"} and len(value.encode()) > 512:
            raise Refusal("input_limit")
        if name == "path":
            components(value, allow_empty=True)
        if name == "paths":
            for path in value:
                components(path)
                if sensitive(path):
                    raise Refusal("sensitive_path")
        if name == "pattern":
            components(value)
        if name == "session_id":
            from .references import parse_reference
            parse_reference(value)
    if len(canonical(arguments)) > 16384:
        raise Refusal("input_limit")


class Observer:
    def __init__(self, config):
        self.config = config
        roots = {r.absolute: r.alias for r in (*config.workspaces.values(), *config.sessions.values())}
        self.redactor, self.cursors = Redactor(roots), Cursors()
        self.workspace = WorkspaceReader(config, self.redactor, self.cursors)
        self.sessions = SessionReader(config, self.redactor, self.cursors)
        self.git = GitReader(config, self.redactor, self.cursors)

    def info(self):
        return {"ok": True, "version": __version__, "transport": "stdio",
                "workspaces": list(self.config.workspaces), "session_sources": list(self.config.sessions),
                "authorization": "local_operator_approval_only; frozen_per_MCP_process; restart_after_registration",
                "registration": "Use observer project add or observer session add locally; remote arguments and observed content cannot grant access.",
                "content_paging": "workspace_read continues to EOF; session_read cursor=content_cursors[field] and git_history cursor=content_cursor work with older connector schemas; continue next_cursor",
                "session_reference_formats": ["exact metadata ID", "codex://threads/<local UUID>", "https://chatgpt.com/codex/tasks/<id> only with explicit local mapping"],
                "limits": {"response_json_bytes": 32768, "results": 50, "read_lines": 200,
                           "scan_bytes": 4194304, "scan_seconds": 1, "jsonl_record_bytes": 262144,
                           "directory_entries_per_scan": 4000, "regex_search_timeout_seconds": 0.015,
                           "workspace_file_bytes": 4194304, "session_verified_prefix_bytes": 67108864,
                           "git_snapshot_total_bytes": GIT_SNAPSHOT_BYTES,
                           "git_worktree_bytes": GIT_WORKTREE_BYTES, "git_object_file_bytes": GIT_OBJECT_FILE_BYTES,
                           "git_worktree_file_bytes": GIT_FILE_BYTES, "git_small_metadata_file_bytes": 4194304,
                           "git_snapshot_entries": GIT_ENTRIES, "git_snapshot_seconds": GIT_SNAPSHOT_SECONDS,
                           "git_query_seconds": GIT_QUERY_SECONDS, "git_query_output_bytes": 4194304,
                           "git_allocation_bytes": GIT_ALLOC_BYTES, "git_query_argv_bytes": 131072},
                "git_semantics": "sanitized config; custom filters ignored; untracked names only, no untracked patches; paths bound worktree copy and literal Git pathspec; history/staged omit worktree; allocation cap is per allocation, not total RSS",
                "cursor_storage": {"kind": "opaque_process_local", "ttl_seconds": CURSOR_TTL,
                                   "max_entries": MAX_CURSORS, "max_state_bytes_total": MAX_CURSOR_BYTES,
                                   "restart_or_eviction": "invalid_cursor"},
                "workspace_selection": "glob/search scan only a literal directory prefix or exact file when available; fnmatch matching semantics unchanged; broad budget refusal has scan_complete=false and requires a narrower pattern",
                "input_frame_bytes": MAX_INPUT_FRAME,
                "coverage": {"workspace": "safe ignored/untracked included; UTF-8 regular files",
                             "sessions": "explicitly registered passive JSONL, projected events only",
                             "git": "fixed status/diff/HEAD history; sealed SHA-1 snapshots, local/remote/packed refs, paired pack+idx; main-repository worktrees metadata ignored; external gitdir/alternates/shallow/promisor refused",
                             "evidence": "association only; no proof of causation or task correctness"},
                "unavailable": ["SQLite/live DB", "authoritative current session activity", "AppServer",
                                "HTTP server", "network access from MCP tools", "root expansion via MCP", "writes", "session control"],
                "redaction": "defense_in_depth; cannot detect every secret",
                "strict_hardlinks": all(r.strict for r in (*self.config.workspaces.values(), *self.config.sessions.values()))}

    def evidence(self, source, session_id, alias, path):
        from .security import Budget

        file = self.workspace.read(alias, path)
        _, meta = self.sessions.resolve(source, session_id, Budget())
        session = self.sessions.read(source, session_id, limit=50)
        executions = [e for e in session["events"] if e["kind"] == "execution"]
        status = self.git.status(alias, paths=[path], limit=10)
        after = self.workspace.read(alias, path)
        if file["source_sha256"] != after["source_sha256"]:
            raise Refusal("source_changed")
        matches = [e["call_id"] for e in executions if e.get("reported_source_sha256") == file["source_sha256"]]
        association = "exact_registered_cwd" if meta["cwd"] == self.workspace.root(alias).absolute else "cwd_mismatch_or_unknown"
        return {"ok": True, "observed_at": datetime.now(timezone.utc).isoformat(),
                "association": association, "workspace_alias": alias, "session_id": session_id,
                "source": {"path": path, "sha256": file["source_sha256"], "line_count": file["source_line_count"]},
                "git": {k: status[k] for k in ("git_version", "source_generation", "clean", "filtered", "hidden_conflicts")},
                "execution_evidence": executions,
                "execution_scan_complete": session["at_eof"] and not session["partial_final_line_pending"],
                "execution_evidence_scope": "bounded_first_session_page; continue_session_read",
                "session_source": source, "session_next_cursor": session["next_cursor"],
                "session_scan": {k: session[k] for k in ("at_eof", "partial_final_line_pending",
                                 "source_version", "scanned_through_byte", "scanned_through_line")},
                "execution_source_link": "trace_reports_matching_source_hash" if matches else "not_established",
                "matching_hash_call_ids": matches, "agent_caused_edits": "not_established",
                "task_verified": "unknown", "exit_zero_alone_verifies_task": False,
                "consistency": "sequential_observations; source hash rechecked; not an atomic cross-source snapshot"}

    def call(self, name, arguments):
        try:
            if name not in SPECS:
                raise Refusal("unknown_tool")
            validate(arguments, SPECS[name][1])
            arguments = dict(arguments)
            # Resolve only by equality against already-open, approved roots.
            # Never open or normalize an arbitrary remote absolute path.
            for key in ("alias", "aliases"):
                if key not in arguments:
                    continue
                values = arguments[key] if isinstance(arguments[key], list) else [arguments[key]]
                resolved = []
                for value in values:
                    if value.startswith("/"):
                        matches = [a for a, r in self.config.workspaces.items() if r.absolute == value]
                        if len(matches) != 1:
                            raise Refusal("project_not_approved")
                        value = matches[0]
                    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value):
                        raise Refusal("invalid_arguments")
                    resolved.append(value)
                arguments[key] = resolved if isinstance(arguments[key], list) else resolved[0]
            functions = {
                "observer_info": self.info,
                "workspace_list": self.workspace.listing, "workspace_read": self.workspace.read,
                "workspace_glob": self.workspace.glob, "workspace_search": self.workspace.search,
                "session_list": self.sessions.listing, "session_read": self.sessions.read,
                "session_search": self.sessions.search, "session_state": self.sessions.state,
                "git_status": self.git.status, "git_diff": self.git.diff, "git_history": self.git.history,
                "evidence_link": self.evidence,
            }
            data = functions[name](**arguments)
        except Refusal as exc:
            data = {"ok": False, "error": exc.code}
            if name in {"git_status", "git_diff", "git_history"}:
                data.update({"result_complete": False, "next_cursor": None})
                if name == "git_status":
                    data["clean"] = "unknown"
            if name in {"workspace_glob", "workspace_search"} and exc.code in {"scan_limit", "scan_timeout", "scan_limit_narrow_selection"}:
                data.update({"scan_complete": False, "next_cursor": None,
                             "hint": "Selection scan reached a safety budget; no complete result. Narrow pattern to a literal directory prefix or exact file. Broad inventory cannot resume after this refusal."})
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            data = {"ok": False, "error": "source_unavailable_or_invalid"}
        except Exception:
            # No traceback, request, content, query, or OS error string is logged.
            data = {"ok": False, "error": "operation_failed"}
        data["read_at"] = datetime.now(timezone.utc).isoformat()
        return envelope(self.redactor, data)
