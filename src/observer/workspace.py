"""Independent filesystem reader: Git tracking does not affect visibility."""

from __future__ import annotations

import fnmatch
import os

from .fs import Root, components, public_workspace_text, signature, source_lines
from .security import Budget, Matcher, Refusal, binding, clip, item_size, text_window


class WorkspaceReader:
    def __init__(self, config, redactor, cursors):
        self.config, self.redactor, self.cursors = config, redactor, cursors

    def root(self, alias):
        try:
            return self.config.workspaces[alias]
        except KeyError:
            raise Refusal("unknown_alias") from None

    def listing(self, alias, path="", limit=25, cursor=None):
        entries, version = self.root(alias).entries(path, Budget())
        filters = [alias, path]
        state = self.cursors.read(cursor, "workspace_list", filters)
        if state and state["version"] != version:
            raise Refusal("source_changed")
        start = state["offset"] if state else 0
        result = []
        used = 0
        for name, kind, st in entries[start:]:
            item = self.redactor.clean({"path": name, "kind": kind, "size": st[2] if kind == "file" else None})
            if len(result) == limit or used + item_size(item) > 18000:
                break
            result.append(item)
            used += item_size(item)
        end = start + len(result)
        token = self.cursors.issue("workspace_list", filters, {"offset": end, "version": version}) if end < len(entries) else None
        return {"ok": True, "entries": result, "next_cursor": token, "sensitive_entries_omitted": True}

    def read(self, alias, path, start_line=1, end_line=None, cursor=None):
        if end_line is not None and (end_line < start_line or end_line - start_line + 1 > 200):
            raise Refusal("line_limit")
        filters = [alias, path, start_line, end_line]
        state = self.cursors.read(cursor, "workspace_read", filters)
        file = self.root(alias).read(path)
        if state and (state["version"] != file.version or state["hash"] != file.sha256):
            raise Refusal("source_changed")
        lines = source_lines(self.redactor.text(public_workspace_text(file, path)))
        last = min(end_line if end_line is not None else len(lines), len(lines))
        number = state["line"] if state else start_line
        character = state.get("character", 0) if state else 0
        results, used = [], 0
        while number <= last and len(results) < 200:
            value = lines[number - 1]
            # A long logical line may span multiple entries with the same line
            # number. Bound both UTF-8 and escaped JSON; never drop its suffix.
            from .security import RedactedFragment
            prefix, _ = clip(value[character:], 1800)
            part, _ = text_window(prefix, 0)
            after = character + len(part)
            item = {"line": number, "text": part, "text_truncated": after < len(value),
                    "char_start": character, "char_end": after, "line_chars_redacted": len(value)}
            if used + item_size(item) > 18000:
                break
            results.append(item)
            used += item_size(item)
            if after < len(value):
                character = after
            else:
                number, character = number + 1, 0
        token = self.cursors.issue("workspace_read", filters, {
            "version": file.version, "hash": file.sha256, "line": number,
            "character": character}) if number <= last else None
        return {
            "ok": True, "alias": alias, "path": path, "source_sha256": file.sha256,
            "source_version": file.version, "source_bytes": len(file.raw),
            "source_line_count": len(lines), "lines": results, "next_cursor": token,
            "more_source_lines": last < len(lines), "selection_complete": token is None,
            "worktree_status": "not_observed; use git_status for the same registered alias",
            "offset_unit": "redacted_unicode_codepoints_per_line",
            "consistency": "descriptor_stable_during_read",
        }

    @staticmethod
    def _scan_plan(pattern):
        # Stop at the first metacharacter-containing component. This is a
        # conservative optimization; matching still uses the existing fnmatch
        # semantics on redacted root-relative paths (including '*' over '/').
        parts = components(pattern)
        literal = []
        for part in parts:
            if any(character in part for character in "*?["):
                return "subtree", "/".join(literal)
            literal.append(part)
        return "file", pattern

    def _inventory(self, aliases, budget, pattern):
        result, scopes = [], []
        kind, selection = self._scan_plan(pattern)
        for alias in sorted(set(aliases)):
            budget.check()
            root = self.root(alias)
            if kind == "file":
                try:
                    fd = root.file(selection)
                except FileNotFoundError:
                    scopes.append((alias, kind, selection, None))
                    continue
                except Refusal as error:
                    if error.code != "not_regular_file":
                        raise
                    # A literal directory is not a file match. Re-open it with
                    # the same no-follow policy; FIFO/devices remain refused.
                    fd = root.directory(selection)
                    try:
                        scopes.append((alias, "directory_only", selection, signature(os.fstat(fd))))
                    finally:
                        os.close(fd)
                    continue
                try:
                    budget.check(len(selection.encode()), 1)
                    version = signature(os.fstat(fd))
                    result.append((alias, selection, version))
                    scopes.append((alias, kind, selection, version))
                finally:
                    os.close(fd)
                continue
            try:
                # Only opening this explicit directory may report "missing".
                # ENOENT during a later walk is a changed/unavailable source,
                # never a successful partial inventory.
                fd = root.directory(selection)
            except FileNotFoundError:
                scopes.append((alias, kind, selection, None))
                continue
            try:
                scoped = Root.from_fd(alias, fd)
            finally:
                os.close(fd)
            # This is a descriptor below the existing approved root, with
            # exactly its workspace exclusions and hardlink policy preserved.
            scoped.workspace, scoped.strict = root.workspace, root.strict
            try:
                before = signature(os.fstat(scoped.fd))
                for relative, version in scoped.walk(budget):
                    path = selection + "/" + relative if selection else relative
                    components(path)
                    result.append((alias, path, version))
                if before != signature(os.fstat(scoped.fd)):
                    raise Refusal("source_changed")
                scopes.append((alias, kind, selection, before))
            finally:
                scoped.close()
        result.sort()
        return result, binding([scopes, result])

    @staticmethod
    def _glob(path, pattern):
        return fnmatch.fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]))

    def glob(self, aliases, pattern, limit=25, cursor=None):
        budget = Budget()
        filters = [sorted(set(aliases)), pattern]
        state = self.cursors.read(cursor, "workspace_glob", filters)
        inventory, generation = self._inventory(aliases, budget, pattern)
        if state and state["generation"] != generation:
            raise Refusal("source_changed")
        index = state["offset"] if state else 0
        results, used = [], 0
        while index < len(inventory):
            budget.check()
            alias, path, version = inventory[index]
            safe = self.redactor.text(path)
            if self._glob(safe, pattern):
                item = {"alias": alias, "path": safe, "size": version[2]}
                if len(results) == limit or used + item_size(item) > 18000:
                    break
                results.append(item)
                used += item_size(item)
            index += 1
        token = self.cursors.issue("workspace_glob", filters, {"generation": generation, "offset": index}) if index < len(inventory) else None
        return {"ok": True, "files": results, "next_cursor": token, "includes_safe_ignored_and_untracked": True, "scan_complete": token is None}

    def search(self, aliases, query, regex=False, pattern="**/*", limit=25, cursor=None):
        budget = Budget()
        matcher = Matcher(query, regex, self.redactor)
        filters = [sorted(set(aliases)), self.redactor.text(query), regex, pattern]
        state = self.cursors.read(cursor, "workspace_search", filters)
        inventory, generation = self._inventory(aliases, budget, pattern)
        if state and state["generation"] != generation:
            raise Refusal("source_changed")
        index, line = (state["offset"], state["line"]) if state else (0, 1)
        page_start = index
        result, used = [], 0
        while index < len(inventory):
            budget.check()
            alias, path, version = inventory[index]
            safe_path = self.redactor.text(path)
            if not self._glob(safe_path, pattern):
                index, line = index + 1, 1
                continue
            if version[2] > budget.remaining:
                if index == page_start:
                    raise Refusal("scan_limit_narrow_selection")
                token = self.cursors.issue("workspace_search", filters, {"generation": generation, "offset": index, "line": line})
                return {"ok": True, "matches": result, "next_cursor": token, "scan_budget_page": True, "scan_complete": False}
            file = self.root(alias).read(path, budget)
            if file.version != version:
                raise Refusal("source_changed")
            lines = source_lines(self.redactor.text(public_workspace_text(file, path)))
            while line <= len(lines):
                budget.check()
                if matcher.matches(lines[line - 1]):
                    text, truncated = clip(lines[line - 1])
                    item = {"alias": alias, "path": safe_path, "line": line, "text": text,
                            "text_truncated": truncated, "source_sha256": file.sha256}
                    if len(result) == limit or used + item_size(item) > 18000:
                        token = self.cursors.issue("workspace_search", filters, {"generation": generation, "offset": index, "line": line})
                        return {"ok": True, "matches": result, "next_cursor": token, "scan_complete": False}
                    result.append(item)
                    used += item_size(item)
                line += 1
            index, line = index + 1, 1
        return {"ok": True, "matches": result, "next_cursor": None, "scan_complete": True}
