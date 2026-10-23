"""Passive JSONL adapter. No session database, control, or raw event API."""

from __future__ import annotations

import json
import hashlib
import os
import re
import time
from datetime import datetime, timezone

from .fs import identity, signature
from .references import parse_reference
from .wrappers import visible_wrapper
from .security import Budget, MAX_RECORD, Matcher, Refusal, binding, clip, digest, item_size, text_window, RedactedFragment

LIFECYCLE = {
    "task_started": "turn_started", "turn_started": "turn_started",
    "task_complete": "turn_completed", "turn_complete": "turn_completed",
    "turn_completed": "turn_completed", "turn_aborted": "aborted",
    "task_aborted": "aborted", "turn_failed": "aborted",
    "turn_blocked": "blocked", "task_blocked": "blocked",
}
EXEC_TOOLS = {"exec_command", "shell_command", "functions.exec_command", "functions.shell_command"}
CUSTOM_EXEC_WRAPPER = "exec"
PUBLIC_CHANNELS = {None, "final", "commentary"}
ARCHIVE_DIRECTORIES = {"archived", "archived_sessions"}


def public_channel(value):
    channel = value.get("channel")
    return isinstance(channel, (str, type(None))) and channel in PUBLIC_CHANNELS


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def json_record(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refusal("malformed_jsonl") from None


class SessionReader:
    def __init__(self, config, redactor, cursors):
        self.config, self.redactor, self.cursors = config, redactor, cursors

    def root(self, source):
        try:
            return self.config.sessions[source]
        except KeyError:
            raise Refusal("unknown_alias") from None

    def inventory(self, sources, budget):
        result = []
        for source in sorted(set(sources)):
            root = self.root(source)
            exact_file = self.config.session_files.get(source)
            if exact_file is not None:
                path, _ = exact_file
                fd = root.file(path)
                try:
                    info = os.fstat(fd)
                    budget.check(len(os.fsencode(path)), 1)
                    result.append((source, path, signature(info)))
                finally:
                    os.close(fd)
                continue
            for path, version in root.walk(budget):
                if path.endswith(".jsonl"):
                    result.append((source, path, version))
        return sorted(result)

    def metadata(self, source, path, budget):
        root = self.root(source)
        fd = root.file(path)
        try:
            before = signature(os.fstat(fd))
            with os.fdopen(os.dup(fd), "rb") as stream:
                raw = stream.readline(MAX_RECORD + 1)
            budget.check(len(raw))
            if len(raw) > MAX_RECORD:
                raise Refusal("oversized_jsonl_record")
            if not raw.endswith(b"\n"):
                raise Refusal("metadata_pending")
            event = json_record(raw)
            payload = event.get("payload", {})
            if event.get("type") != "session_meta" or not isinstance(payload, dict):
                raise Refusal("metadata_missing")
            if not public_channel(event) or not public_channel(payload):
                raise Refusal("invalid_session_metadata")
            sid, cwd = payload.get("id"), payload.get("cwd")
            if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sid):
                raise Refusal("invalid_session_metadata")
            exact_file = self.config.session_files.get(source)
            if exact_file is not None and (path, sid) != exact_file:
                raise Refusal("session_scope_mismatch")
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
            # Infer storage only from directories at or below the registered root.
            directories = (os.path.basename(root.absolute), *path.split("/")[:-1])
            return {
                "session_id": sid, "cwd": cwd if isinstance(cwd, str) else None,
                "title": payload.get("title", "") if isinstance(payload.get("title", ""), str) else "",
                "timestamp": timestamp(event.get("timestamp") or payload.get("timestamp")),
                "head": digest(raw), "inode": identity(os.fstat(fd)),
                "storage": "archived" if any(part in ARCHIVE_DIRECTORIES for part in directories) else "active_directory",
            }
        finally:
            os.close(fd)

    def public_metadata(self, meta, source, path):
        title, truncated = clip(self.redactor.text(meta["title"]), 1000)
        return self.redactor.clean({
            "source": source, "path": path, "session_id": meta["session_id"],
            "title": title, "title_truncated": truncated, "timestamp": meta["timestamp"],
            "storage": meta["storage"], "activity_authority": "unavailable_passive_jsonl",
        })

    def resolve(self, source, session_id, budget):
        kind, reference = parse_reference(session_id)
        if kind == "cloud":
            mapped = getattr(self.config, "session_references", {}).get((source, reference))
            if mapped is None:
                raise Refusal("session_reference_unmapped")
            session_id = mapped
        else:
            session_id = reference
        found = []
        for _, path, _ in self.inventory([source], budget):
            meta = self.metadata(source, path, budget)
            if meta["session_id"] == session_id:  # Exact metadata ID only.
                found.append((path, meta))
        if not found:
            raise Refusal("session_not_found")
        if len(found) != 1:
            raise Refusal("ambiguous_session_id")
        return found[0]

    def listing(self, sources, keyword="", limit=25, cursor=None):
        budget = Budget()
        filters = [sorted(set(sources)), self.redactor.text(keyword)]
        state = self.cursors.read(cursor, "session_list", filters)
        inventory = self.inventory(sources, budget)
        generation = binding(inventory)
        if state and state["generation"] != generation:
            raise Refusal("source_changed")
        index = state["offset"] if state else 0
        result, used = [], 0
        page_start = index
        while index < len(inventory):
            if budget.remaining < MAX_RECORD + 1:
                if index == page_start:
                    raise Refusal("scan_limit_narrow_selection")
                break
            source, path, _ = inventory[index]
            meta = self.metadata(source, path, budget)
            item = self.public_metadata(meta, source, path)
            if not keyword or self.redactor.text(keyword) in json.dumps(item):
                if len(result) == limit or used + item_size(item) > 18000:
                    break
                result.append(item)
                used += item_size(item)
            index += 1
        token = self.cursors.issue("session_list", filters, {"offset": index, "generation": generation}) if index < len(inventory) else None
        return {"ok": True, "sessions": result, "next_cursor": token}

    def project(self, event, calls, custom_calls):
        """Explicit shape and field allowlist; no fallback to raw objects."""
        kind = event.get("type")
        payload = event.get("payload")
        # Fail closed on all other channels, including unknown future internal
        # channels. Omit before matching, call pairing or lifecycle accumulation.
        if not public_channel(event) or (isinstance(payload, dict) and not public_channel(payload)):
            return None
        if kind == "session_meta":
            return None
        stamp = timestamp(event.get("timestamp"))
        if kind == "event_msg" and isinstance(payload, dict):
            tag = payload.get("type")
            if tag in LIFECYCLE:
                return {"kind": "lifecycle", "event": LIFECYCLE[tag], "timestamp": stamp}
            if tag in {"user_message", "agent_message", "assistant_message"}:
                message = payload.get("message")
                if isinstance(message, str):
                    return {"kind": "message", "role": "user" if tag == "user_message" else "assistant",
                            "text": message, "timestamp": stamp}
            if tag in {"exec_command_begin", "exec_command_end"}:
                return self._execution(payload, stamp, calls, tag == "exec_command_end")
            return None
        if kind == "execution" and isinstance(payload, dict):
            return self._execution(payload, stamp, calls, True)
        if kind != "response_item" or not isinstance(payload, dict):
            return None
        tag = payload.get("type")
        if tag == "message" and payload.get("role") in {"user", "assistant"}:
            parts = payload.get("content")
            if not isinstance(parts, list):
                return None
            texts = [p["text"] for p in parts if isinstance(p, dict)
                     and public_channel(p) and p.get("type") in {"input_text", "output_text", "text"} and isinstance(p.get("text"), str)]
            return {"kind": "message", "role": payload["role"], "text": "\n".join(texts), "timestamp": stamp} if texts else None
        if tag == "function_call" and payload.get("name") in EXEC_TOOLS:
            args = payload.get("arguments")
            try:
                args = json.loads(args) if isinstance(args, str) else args
            except (ValueError, RecursionError):
                return None
            if not isinstance(args, dict):
                return None
            data = {"call_id": payload.get("call_id"), "command": args.get("cmd", args.get("command"))}
            return self._execution(data, stamp, calls, False)
        if tag == "custom_tool_call" and payload.get("name") == CUSTOM_EXEC_WRAPPER:
            wrapper_input, call_id = payload.get("input"), payload.get("call_id")
            if payload.get("status") != "completed" or not isinstance(wrapper_input, str):
                return None
            try:
                if len(wrapper_input.encode("utf-8")) > 32768:
                    return None
            except UnicodeEncodeError:
                return None
            projected = self._execution(
                {"call_id": call_id, "command": "functions.exec wrapper"}, stamp, calls, False)
            if projected is not None:
                visible = visible_wrapper(wrapper_input, self.redactor)
                projected["wrapper_code_visibility"] = "static_literal_exec_command" if visible else "unavailable_unknown_shape"
                if visible is not None:
                    projected["wrapper_code"] = visible
                    projected["wrapper_code_representation"] = "normalized_static_literal_arguments"
                custom_calls[binding(call_id)] = True
                if len(custom_calls) > 4:
                    del custom_calls[next(iter(custom_calls))]
            return projected
        if tag == "custom_tool_call_output":
            call_id = payload.get("call_id")
            if not isinstance(call_id, str) or binding(call_id) not in custom_calls:
                return None
            blocks = payload.get("output")
            if not isinstance(blocks, list) or not 1 <= len(blocks) <= 16:
                return None
            texts = []
            for block in blocks:
                if (not isinstance(block, dict) or set(block) != {"type", "text"}
                        or block.get("type") != "input_text" or not isinstance(block.get("text"), str)):
                    return None
                texts.append(block["text"])
            projected = self._execution({
                "call_id": call_id, "command": "functions.exec wrapper", "output": "\n".join(texts)
            }, stamp, calls, True)
            if projected is not None:
                custom_calls.pop(binding(call_id), None)
            return projected
        if tag == "function_call_output" and isinstance(payload.get("call_id"), str):
            call_id = payload["call_id"]
            if binding(call_id) not in calls:
                return None
            output = payload.get("output")
            data = {"call_id": call_id, "command": calls[binding(call_id)], "_command_preview_only": True}
            if isinstance(output, dict):
                data.update({k: output.get(k) for k in ("exit_code", "output")})
            elif isinstance(output, str):
                data["output"] = output
                match = re.search(r"(?m)^Process exited with code (-?\d{1,5})\s*$", output)
                if match:
                    data["exit_code"] = int(match[1])
            return self._execution(data, stamp, calls, True)
        return None

    def _execution(self, payload, stamp, calls, ended):
        call_id, command = payload.get("call_id"), payload.get("command")
        preview_only = payload.get("_command_preview_only") is True or command is None
        if not isinstance(call_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", call_id):
            return None
        if isinstance(command, list) and all(isinstance(v, str) for v in command):
            command = " ".join(command)
        if not isinstance(command, str):
            command = calls.get(binding(call_id))
        if isinstance(command, str):
            calls[binding(call_id)] = clip(self.redactor.text(command), 300)[0]
            if len(calls) > 4:
                del calls[next(iter(calls))]
        result = {"kind": "execution", "phase": "result" if ended else "call", "call_id": call_id,
                  "command": self.redactor.text(command) if isinstance(command, str) else calls.get(binding(call_id)), "timestamp": stamp, "exit_status": None}
        result["command_representation"] = "paired_call_preview" if preview_only else "source_command_or_fixed_wrapper_label"
        result["command_may_be_incomplete"] = preview_only
        code = payload.get("exit_code")
        if isinstance(code, int) and not isinstance(code, bool) and -65536 <= code <= 65536 and ended:
            result["exit_status"] = code
        output = payload.get("output", payload.get("aggregated_output"))
        if isinstance(output, str) and ended:
            result["output"] = output
        sha = payload.get("source_sha256")
        if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha):
            result["reported_source_sha256"] = sha
        return result

    @staticmethod
    def anchor(fd, offset):
        return digest(os.pread(fd, min(offset, 256), max(0, offset - 256)))

    @staticmethod
    def prefix_hash(fd, size):
        # Full checked prefix defeats rewrite+append, which a tail anchor misses.
        # This separate verification budget is explicit; never silently weaken it.
        if size > 64 * 1024 * 1024:
            raise Refusal("session_prefix_verification_limit")
        budget, hasher, offset = Budget(remaining=64 * 1024 * 1024), hashlib.sha256(), 0
        while offset < size:
            raw = os.pread(fd, min(65536, size - offset), offset)
            budget.check(len(raw))
            if not raw:
                raise Refusal("source_changed")
            hasher.update(raw)
            offset += len(raw)
        return hasher.hexdigest()

    def scan(self, source, path, meta, budget, state=None, limit=25, matcher=None, state_only=False, max_bytes=18000):
        fd = self.root(source).file(path)
        try:
            before = signature(os.fstat(fd))
            if identity(os.fstat(fd)) != meta["inode"]:
                raise Refusal("source_rotated")
            offset, line = (state["offset"], state["line"]) if state else (0, 1)
            if state:
                if state["path_hash"] != binding(path) or state["inode"] != identity(os.fstat(fd)) or state["head"] != meta["head"]:
                    raise Refusal("source_rotated")
                if before[2] < state["seen_size"] or before[2] < offset:
                    raise Refusal("source_truncated")
                if self.prefix_hash(fd, offset) != state["prefix_sha256"]:
                    raise Refusal("source_changed")
                if self.anchor(fd, offset) != state["anchor"]:
                    raise Refusal("source_changed")
                if before[2] == state["seen_size"] and before[3:] != state["times"]:
                    raise Refusal("source_changed")
            calls = dict(state.get("calls", {})) if state else {}
            custom_calls = dict(state.get("custom_calls", {})) if state else {}
            acc = dict(state.get("acc", {})) if state else {}
            result, used, scanned, omitted, pending = [], 0, 0, 0, False
            with os.fdopen(os.dup(fd), "rb") as stream:
                stream.seek(offset)
                while offset < before[2]:
                    # Pause at a complete-record boundary; no dropped or skipped record.
                    if len(result) >= limit or scanned >= 1000 or budget.remaining < MAX_RECORD + 1:
                        if scanned == 0 and budget.remaining < MAX_RECORD + 1:
                            raise Refusal("scan_limit_narrow_selection")
                        break
                    budget.check()
                    raw = stream.readline(min(MAX_RECORD + 1, before[2] - offset))
                    budget.check(len(raw))
                    if len(raw) > MAX_RECORD:
                        raise Refusal("oversized_jsonl_record")
                    if not raw.endswith(b"\n"):
                        pending = True
                        break
                    event = json_record(raw)
                    next_calls, next_custom_calls, next_acc = dict(calls), dict(custom_calls), dict(acc)
                    projected = self.project(event, next_calls, next_custom_calls)
                    if projected is not None:
                        projected = self.redactor.clean(projected)
                        projected["evidence"] = {"source": source, "path": self.redactor.text(path),
                                                 "line": line, "byte_start": offset,
                                                 "byte_end": offset + len(raw), "record_sha256": digest(raw)}
                        stamp = projected.get("timestamp")
                        if stamp is not None:
                            next_acc["last_event_time"] = stamp
                        if projected["kind"] == "lifecycle":
                            next_acc["lifecycle"] = projected["event"]
                            next_acc["lifecycle_time"] = stamp
                            next_acc["lifecycle_is_latest"] = True
                        else:
                            next_acc["lifecycle_is_latest"] = False
                        next_acc["last_evidence"] = projected["evidence"]
                        if projected["kind"] == "message":
                            next_acc["last_public_message"] = {"role": projected["role"],
                                "preview": clip(projected["text"], 800)[0], "timestamp": stamp,
                                "evidence": projected["evidence"]}
                        if projected["kind"] == "execution":
                            next_acc["last_execution"] = {k: projected.get(k) for k in
                                ("phase", "call_id", "exit_status", "timestamp", "evidence")}
                        if not state_only and (matcher is None or matcher.matches(json.dumps(projected, ensure_ascii=False))):
                            # Search full redacted projection, then clip individual fields.
                            projected["field_totals_redacted"] = {k: len(projected[k]) for k in
                                ("text", "command", "output", "wrapper_code") if isinstance(projected.get(k), str)}
                            for key in ("text", "command", "output", "wrapper_code"):
                                if isinstance(projected.get(key), str):
                                    part, truncated = clip(projected[key], 300 if key == "command" else 1500)
                                    projected[key], projected[key + "_truncated"] = RedactedFragment(part), truncated
                            projected["evidence"] = {"source": source, "path": self.redactor.text(path),
                                                     "line": line, "byte_start": offset,
                                                     "byte_end": offset + len(raw), "record_sha256": digest(raw)}
                            if used + item_size(projected) > max_bytes:
                                break
                            if any(projected.get(k + "_truncated") for k in projected["field_totals_redacted"]):
                                projected["detail_cursor"] = self.cursors.issue("session_detail_ref", [source, meta["session_id"]], {
                                    "path": path, "offset": offset, "line": line, "size": len(raw),
                                    "version": before, "record_sha256": digest(raw),
                                    "calls": calls, "custom_calls": custom_calls})
                                projected["content_cursors"] = {key: self.cursors.issue("session_content", [source, meta["session_id"]], {
                                    "reference": projected["detail_cursor"], "field": key, "page": None})
                                    for key in projected["field_totals_redacted"] if projected.get(key + "_truncated")}
                                projected["detail_usage"] = "For complete content use session_read(source, session_id, cursor=content_cursors[field]); continue next_cursor. No extra input fields required."
                            if used + item_size(projected) > max_bytes:
                                break
                            result.append(projected)
                            used += item_size(projected)
                    else:
                        omitted += 1
                    calls, custom_calls, acc = next_calls, next_custom_calls, next_acc
                    offset += len(raw)
                    line += 1
                    scanned += 1
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
            prefix = self.prefix_hash(fd, offset)
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
            checkpoint = {"prefix_sha256": prefix, "path_hash": binding(path), "inode": identity(os.fstat(fd)), "head": meta["head"],
                          "offset": offset, "line": line, "seen_size": before[2], "times": before[3:],
                          "anchor": self.anchor(fd, offset), "calls": calls,
                          "custom_calls": custom_calls, "acc": acc}
            return {"events": result, "checkpoint": checkpoint, "at_eof": offset == before[2],
                    "partial_final_line_pending": pending, "records_scanned": scanned,
                    "omitted_nonprojected_records": omitted,
                    "source_version": before, "source_size_observed": before[2],
                    "scanned_through_byte": offset, "scanned_through_line": line - 1,
                    "verified_prefix_sha256": prefix}
        finally:
            os.close(fd)

    def detail(self, source, session_id, detail_cursor, field, cursor=None):
        if field not in {"text", "command", "output", "wrapper_code"}:
            raise Refusal("invalid_detail_field")
        budget = Budget()
        path, meta = self.resolve(source, session_id, budget)
        filters = [source, meta["session_id"]]
        ref = self.cursors.read(detail_cursor, "session_detail_ref", filters)
        page_filters = [*filters, detail_cursor, field]
        state = self.cursors.read(cursor, "session_detail", page_filters)
        if ref is None or ref["path"] != path:
            raise Refusal("invalid_cursor")
        fd = self.root(source).file(path)
        try:
            before = signature(os.fstat(fd))
            if before != ref["version"] or identity(os.fstat(fd)) != meta["inode"]:
                raise Refusal("source_changed")
            raw = os.pread(fd, ref["size"], ref["offset"])
            budget.check(len(raw))
            if digest(raw) != ref["record_sha256"]:
                raise Refusal("source_changed")
            value = self.project(json_record(raw), dict(ref["calls"]), dict(ref["custom_calls"]))
            value = self.redactor.clean(value) if value else {}
            if not isinstance(value.get(field), str):
                raise Refusal("detail_field_unavailable")
            if field == "command" and value.get("command_may_be_incomplete"):
                raise Refusal("paired_command_preview_only; read_call_event")
            full = value[field]
            start = state["offset"] if state else 0
            part, end = text_window(full, start, 12000)
            if before != signature(os.fstat(fd)):
                raise Refusal("source_changed")
            token = self.cursors.issue("session_detail", page_filters, {"offset": end}) if end < len(full) else None
            return {"ok": True, "session_id": meta["session_id"], "field": field,
                    "content": part, "char_start": start, "char_end": end,
                    "total_chars_redacted": len(full), "total_bytes_redacted": len(full.encode()),
                    "content_sha256_redacted": digest(full.encode()), "content_truncated": token is not None,
                    "next_cursor": token, "source_version": before,
                    "evidence": {"source": source, "path": path, "line": ref["line"],
                                 "record_sha256": ref["record_sha256"]},
                    "offset_unit": "redacted_unicode_codepoints", "consistency": "record_version_rechecked"}
        finally:
            os.close(fd)

    def content(self, source, session_id, cursor):
        _, meta = self.resolve(source, session_id, Budget())
        filters = [source, meta["session_id"]]
        state = self.cursors.read(cursor, "session_content", filters)
        result = self.detail(source, session_id, state["reference"], state["field"], state["page"])
        inner = result["next_cursor"]
        result["mode"] = "field_content"
        result["next_cursor"] = self.cursors.issue("session_content", filters, {
            **state, "page": inner}) if inner else None
        return result

    def read(self, source, session_id, limit=25, cursor=None, detail_cursor=None, field=None):
        if cursor is not None and detail_cursor is None and field is None and self.cursors.kind(cursor) == "session_content":
            return self.content(source, session_id, cursor)
        if detail_cursor is not None or field is not None:
            if detail_cursor is None or field is None:
                raise Refusal("detail_cursor_and_field_required")
            return self.detail(source, session_id, detail_cursor, field, cursor)
        filters = [source, session_id]
        state = self.cursors.read(cursor, "session_read", filters)
        budget = Budget()
        path, meta = self.resolve(source, session_id, budget)
        page = self.scan(source, path, meta, budget, state, limit)
        checkpoint = page.pop("checkpoint")
        return {"ok": True, "metadata": self.public_metadata(meta, source, path), **page,
                "next_cursor": self.cursors.issue("session_read", filters, checkpoint),
                "cursor_supports_append_polling": True}

    def search(self, sources, query, regex=False, session_id=None, limit=25, cursor=None):
        filters = [sorted(set(sources)), self.redactor.text(query), regex, session_id]
        state = self.cursors.read(cursor, "session_search", filters)
        budget, matcher = Budget(), Matcher(query, regex, self.redactor)
        selected = sorted(set(sources))
        # Validate every explicitly requested alias before narrowing by a local
        # mapping. A link never expands the approved source set or discovers files.
        for source in selected:
            self.root(source)
        selected_ids = None
        if session_id is not None:
            kind, reference = parse_reference(session_id)
            if kind == "cloud":
                mappings = getattr(self.config, "session_references", {})
                selected_ids = {source: mappings[(source, reference)]
                                for source in selected if (source, reference) in mappings}
                if not selected_ids:
                    raise Refusal("session_reference_unmapped")
                selected = list(selected_ids)
            else:
                selected_ids = {source: reference for source in selected}
        inventory = self.inventory(selected, budget)
        # Names/inodes bind inventory; appending to existing sources remains pollable.
        generation = binding([(a, p, v[:2]) for a, p, v in inventory])
        if state and generation != state["generation"]:
            raise Refusal("source_rotated")
        index = state["index"] if state else 0
        checkpoint = state["reader"] if state else None
        result, used = [], 0
        while index < len(inventory):
            if budget.remaining < 2 * (MAX_RECORD + 1):
                if index == (state["index"] if state else 0) and not result:
                    raise Refusal("scan_limit_narrow_selection")
                break
            source, path, _ = inventory[index]
            meta = self.metadata(source, path, budget)
            if selected_ids is not None and meta["session_id"] != selected_ids[source]:
                index, checkpoint = index + 1, None
                continue
            page = self.scan(source, path, meta, budget, checkpoint, limit - len(result), matcher, max_bytes=18000 - used)
            result.extend(page["events"])
            used += sum(item_size(item) for item in page["events"])
            if page["partial_final_line_pending"]:
                # Search is a finite snapshot pass, not an append poll. An
                # incomplete final record is not searchable; move on so it
                # cannot pin this cursor to the same byte offset forever.
                index, checkpoint = index + 1, None
                continue
            if not page["at_eof"]:
                checkpoint = page["checkpoint"]
                break
            index, checkpoint = index + 1, None
            if len(result) >= limit or budget.remaining < MAX_RECORD + 1:
                break
        token = self.cursors.issue("session_search", filters, {"generation": generation, "index": index, "reader": checkpoint}) if index < len(inventory) else None
        return {"ok": True, "matches": result, "next_cursor": token}

    def state(self, source, session_id, cursor=None):
        filters = [source, session_id]
        state = self.cursors.read(cursor, "session_state", filters)
        budget = Budget()
        path, meta = self.resolve(source, session_id, budget)
        page = self.scan(source, path, meta, budget, state, state_only=True)
        checkpoint = page["checkpoint"]
        acc = checkpoint["acc"]
        complete = page["at_eof"] and not page["partial_final_line_pending"]
        life = acc.get("lifecycle")
        status = "unknown"
        if complete:
            if life == "turn_completed" and acc.get("lifecycle_is_latest"):
                status = "explicit_terminal_turn"
            elif life in {"blocked", "aborted"} and acc.get("lifecycle_is_latest"):
                status = "explicit_" + life
            else:
                last = acc.get("last_event_time")
                if last:
                    age = time.time() - datetime.fromisoformat(last).timestamp()
                    if 0 <= age <= 60:
                        status = "recently_observed_event"
        return {"ok": True, "historical_state": status, "current_activity": "unknown",
                "last_evidence": acc.get("last_evidence"),
                "last_public_message": acc.get("last_public_message"),
                "last_execution": acc.get("last_execution"),
                "source_version": page["source_version"], "source_size_observed": page["source_size_observed"],
                "state": status, "last_observed_event_time": acc.get("last_event_time"),
                "last_explicit_lifecycle": life, "lifecycle_timestamp": acc.get("lifecycle_time"),
                "scan_complete": complete, "partial_final_line_pending": page["partial_final_line_pending"],
                "task_verified": "unknown", "authoritative_current_activity": "unavailable_passive_jsonl",
                "next_cursor": self.cursors.issue("session_state", filters, checkpoint)}
