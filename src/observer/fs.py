"""Descriptor-based authorization. No realpath-prefix authorization."""

from __future__ import annotations

import os
import json
import stat
from dataclasses import dataclass

from .security import Budget, MAX_SCAN, Refusal, digest

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DENIED = frozenset({
    ".git", ".codex", ".venv", ".ssh", ".aws", ".azure", ".config", ".cache",
    "__pycache__", "node_modules", "auth", "auth.json", "authentication.json",
    "credentials", "credentials.json", "credentials.yml", "credentials.yaml",
    "tokens", "tokens.json", "token.json", "secrets", "secrets.json", "secrets.yaml", "secrets.toml",
    "password", "passwords", "passwords.txt", "id_rsa", "id_ed25519", "id_ecdsa",
    "private_key", "private-key", "keychain", ".npmrc", ".netrc", ".pypirc",
    "keys", "certs", "certificates", "secret", "secret.txt", "secrets.txt",
    "password.txt", "token", "token.txt", "api_key", "api_key.txt", "api-key",
    "auth.yaml", "auth.yml", "auth.toml", "credentials.toml", ".git-credentials",
    ".docker", ".kube", ".gnupg", "kubeconfig", "observer.local.json",
})
SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".jks", ".keystore", ".der")


def components(path: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(path, str) or len(path.encode("utf-8")) > 2048:
        raise Refusal("invalid_path")
    if path == "" and allow_empty:
        return ()
    parts = path.split("/")
    if (
        not path or path.startswith("/") or "\\" in path
        or any(ord(c) < 32 or ord(c) == 127 for c in path)
        or any(p in ("", ".", "..") or len(p.encode()) > 255 for p in parts)
    ):
        raise Refusal("invalid_path")
    return tuple(parts)


def sensitive(path: str) -> bool:
    return any(
        p.lower() in DENIED or p.lower().startswith(".env") or p.lower().endswith(SUFFIXES)
        for p in path.split("/")
    )


def source_lines(text):
    # Match physical LF source lines, including CRLF files. Unicode separators
    # inside source literals are characters, not extra code citation lines.
    if not text:
        return []
    lines = text.split("\n")
    return lines[:-1] if text.endswith("\n") else lines


def is_session_record(text):
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return False
    return (isinstance(value, dict) and value.get("type") in
            {"session_meta", "response_item", "event_msg", "turn_context"}
            and isinstance(value.get("payload"), dict))


def public_workspace_text(file, path):
    text = file.text()
    budget = Budget()
    for line in source_lines(text):
        budget.check(len(line.encode()))
        if line.lstrip().startswith("{") and is_session_record(line):
            raise Refusal("session_log_requires_exact_session_registration")
    return text


def signature(st: os.stat_result) -> list[int]:
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def identity(st: os.stat_result) -> list[int]:
    return [st.st_dev, st.st_ino]


@dataclass(frozen=True)
class FileData:
    raw: bytes
    sha256: str
    version: list[int]

    def text(self) -> str:
        try:
            value = self.raw.decode("utf-8")
            if "\x00" in value:
                raise ValueError
            return value
        except (UnicodeDecodeError, ValueError):
            raise Refusal("unsupported_binary") from None


class Root:
    @classmethod
    def from_fd(cls, alias: str, fd: int):
        """Private runtime copy boundary, never an MCP root expansion API."""
        root = cls.__new__(cls)
        root.alias, root.absolute = alias, ""
        root.strict, root.workspace = True, False
        root.fd = os.dup(fd)
        root.pinned = identity(os.fstat(root.fd))
        return root

    def __init__(self, alias: str, absolute: str, strict: bool = True, workspace: bool = True):
        if not absolute.startswith("/"):
            raise Refusal("invalid_config")
        self.alias, self.absolute, self.strict, self.workspace = alias, absolute, strict, workspace
        fd = os.open("/", DIR_FLAGS)
        try:
            for part in components(absolute[1:]):
                new = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = new
            self.fd = fd
            self.pinned = identity(os.fstat(fd))
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        os.close(self.fd)

    def _parts(self, path: str, internal: bool = False, empty: bool = False) -> tuple[str, ...]:
        parts = components(path, empty)
        if self.workspace and not internal and sensitive(path):
            raise Refusal("sensitive_path")
        return parts

    def directory(self, path: str = "", *, internal: bool = False) -> int:
        fd = os.dup(self.fd)
        try:
            for part in self._parts(path, internal, True):
                new = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = new
            return fd
        except BaseException:
            os.close(fd)
            raise

    def file(self, path: str, *, internal: bool = False) -> int:
        parts = self._parts(path, internal)
        parent = self.directory("/".join(parts[:-1]), internal=internal)
        try:
            fd = os.open(parts[-1], FILE_FLAGS, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Refusal("not_regular_file")
            if self.strict and st.st_nlink != 1:
                raise Refusal("hardlink_denied")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path: str, budget: Budget | None = None, *, internal: bool = False) -> FileData:
        budget = budget or Budget()
        fd = self.file(path, internal=internal)
        try:
            before = signature(os.fstat(fd))
            if before[2] > MAX_SCAN:
                raise Refusal("file_too_large")
            chunks = []
            while True:
                chunk = os.read(fd, min(65536, budget.remaining + 1))
                budget.check(len(chunk))
                if not chunk:
                    break
                chunks.append(chunk)
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
            raw = b"".join(chunks)
            return FileData(raw, digest(raw), before)
        finally:
            os.close(fd)

    def entries(self, path: str, budget: Budget, *, internal: bool = False) -> tuple[list, list[int]]:
        fd = self.directory(path, internal=internal)
        try:
            before = signature(os.fstat(fd))
            result = []
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    budget.check(len(os.fsencode(entry.name)), 1)
                    child = f"{path}/{entry.name}" if path else entry.name
                    components(child)
                    if self.workspace and not internal and sensitive(child):
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                        raise Refusal("unsafe_entry")
                    if stat.S_ISREG(st.st_mode) and self.strict and st.st_nlink != 1:
                        raise Refusal("hardlink_denied")
                    result.append((child, "directory" if stat.S_ISDIR(st.st_mode) else "file", signature(st)))
            if before != signature(os.fstat(fd)):
                raise Refusal("source_changed")
            return sorted(result), before
        finally:
            os.close(fd)

    def walk(self, budget: Budget, path: str = "", *, internal: bool = False):
        entries, _ = self.entries(path, budget, internal=internal)
        for child, kind, version in entries:
            if kind == "directory":
                yield from self.walk(budget, child, internal=internal)
            else:
                yield child, version
