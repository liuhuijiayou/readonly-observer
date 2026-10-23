"""Operator-only startup configuration; immutable authorization maps."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import MappingProxyType

from .fs import Root, components
from .security import Refusal


class Config:
    def __init__(self, project: Path, values: dict):
        base_keys = {"workspaces", "sessions", "strict_hardlinks"}
        if (not isinstance(values, dict)
                or set(values) not in (base_keys, base_keys | {"session_files"})):
            raise Refusal("invalid_config")
        if not isinstance(values["strict_hardlinks"], bool):
            raise Refusal("invalid_config")
        if any(not isinstance(values[kind], dict) or len(values[kind]) > 8
               for kind in ("workspaces", "sessions")) or not (values["workspaces"] or values["sessions"]):
            raise Refusal("invalid_config")
        session_files = values.get("session_files", {})
        if (not isinstance(session_files, dict) or len(session_files) > 8
                or not set(session_files).issubset(values["sessions"])):
            raise Refusal("invalid_config")
        exact_files = {}
        for alias, spec in session_files.items():
            if (not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", alias)
                    or not isinstance(spec, dict) or set(spec) != {"path", "session_id"}):
                raise Refusal("invalid_config")
            path, session_id = spec["path"], spec["session_id"]
            if (not isinstance(path, str) or not path.endswith(".jsonl")
                    or not isinstance(session_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id)):
                raise Refusal("invalid_config")
            components(path)
            exact_files[alias] = (path, session_id)
        self.project = project.absolute()
        self.session_files = MappingProxyType(exact_files)
        opened = []
        try:
            for kind in ("workspaces", "sessions"):
                mapping = values[kind]
                roots = {}
                for alias, location in mapping.items():
                    if not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", alias) or not isinstance(location, str):
                        raise Refusal("invalid_config")
                    if location == ".":
                        absolute = str(self.project)
                    elif location.startswith("/"):
                        components(location[1:])
                        absolute = location
                    else:
                        components(location)
                        absolute = str(self.project / location)
                    root = Root(alias, absolute, values["strict_hardlinks"], kind == "workspaces")
                    opened.append(root)
                    roots[alias] = root
                setattr(self, kind, MappingProxyType(roots))
        except BaseException:
            for root in opened:
                root.close()
            raise

    @classmethod
    def load(cls, project: Path, path: str = "observer.example.json", approved_sources: bool = False) -> Config:
        components(path)
        # Config itself is not a workspace API: startup, no-follow, bounded.
        root = Root("config", str(project.absolute()), workspace=False)
        try:
            data = root.read(path).raw
            if len(data) > 16384:
                raise Refusal("invalid_config")
            values = json.loads(data)
            if approved_sources:
                from .registry import effective_config
                return effective_config(project, values)
            return cls(project, values)
        finally:
            root.close()

    def close(self) -> None:
        for root in (*self.workspaces.values(), *self.sessions.values()):
            root.close()
