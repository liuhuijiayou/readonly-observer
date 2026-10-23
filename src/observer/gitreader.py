"""Fixed Git queries against sealed, sanitized, private snapshots only.

Git never receives an observed path, config, environment, linked gitdir, or FD.
No shell is used. A snapshot contains regular byte copies, not hardlinks.
"""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
import re
import resource
import selectors
import secrets
import shutil
import stat
import subprocess
import threading
import time

from .fs import DIR_FLAGS, FILE_FLAGS, Root, components, sensitive, signature, is_session_record
from .security import Budget, MAX_SCAN, Refusal, binding, clip, digest, item_size, text_window, RedactedFragment

GIT = "/usr/bin/git"
CWD_LOCK = threading.Lock()
GIT_SNAPSHOT_BYTES = 100_000_000
GIT_WORKTREE_BYTES = 64 * 1024 * 1024
GIT_OBJECT_FILE_BYTES = 100_000_000
GIT_FILE_BYTES = 16 * 1024 * 1024
GIT_ENTRIES = 50000
GIT_SNAPSHOT_SECONDS = 20.0
GIT_QUERY_SECONDS = 5.0
GIT_ALLOC_BYTES = 128 * 1024 * 1024
SAFE_CONFIG = b"""[core]
repositoryformatversion = 0
bare = false
filemode = true
symlinks = false
hooksPath = /dev/null
fsmonitor = false
untrackedCache = false
preloadIndex = false
commitGraph = false
multiPackIndex = false
attributesFile = /dev/null
excludesFile = /dev/null
[protocol]
allow = never
[credential]
helper =
[gc]
auto = 0
[maintenance]
auto = false
"""
FIXED_ARGS = [
    GIT, "--no-pager", "--no-optional-locks", "--no-replace-objects",
    "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false", "-c", "core.preloadIndex=false",
    "-c", "protocol.allow=never", "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never", "-c", "credential.helper=",
    "-c", "core.commitGraph=false", "-c", "core.multiPackIndex=false",
    "-c", "core.packedGitWindowSize=16m", "-c", "core.packedGitLimit=64m",
    "-c", "core.deltaBaseCacheLimit=16m", "-c", "core.bigFileThreshold=16m",
    "-c", "gc.auto=0", "-c", "maintenance.auto=false",
]


class GitBudget:
    """Git storage is separate from workspace text scans and tool output."""
    def __init__(self, remaining=None, deadline=None, parent=None):
        self.remaining = GIT_SNAPSHOT_BYTES if remaining is None else remaining
        self.parent = parent
        self.deadline = deadline or time.monotonic() + GIT_SNAPSHOT_SECONDS
        self.entries = 0

    def check(self, size=0, entries=0):
        if self.parent is not None:
            self.parent.check(size, entries)
        self.remaining -= size
        self.entries += entries
        if self.remaining < 0:
            raise Refusal("git_snapshot_byte_limit")
        if self.entries > GIT_ENTRIES:
            raise Refusal("git_snapshot_entry_limit")
        if time.monotonic() > self.deadline:
            raise Refusal("git_snapshot_timeout")


def child_limits():
    # Set in the child before exec; no source code or inherited config runs.
    # CPU and output-file limits complement wall/output/allocation caps.
    # macOS does not provide an enforceable RLIMIT_AS; do not claim a RSS cap.
    for kind, value in ((resource.RLIMIT_CPU, int(GIT_QUERY_SECONDS) + 1),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        _, hard = resource.getrlimit(kind)
        bounded = min(value, hard) if hard != resource.RLIM_INFINITY else value
        resource.setrlimit(kind, (bounded, bounded))


def safe_env(home: Path) -> dict[str, str]:
    # Construct from nothing: ignore ALL inherited GIT_*, shell, loader, locale,
    # XDG, pager, SSH, credential and executable-path injection variables.
    return {
        "PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ALLOW_PROTOCOL": "", "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_LITERAL_PATHSPECS": "1", "GIT_PAGER": "", "PAGER": "",
        "GIT_ALLOC_LIMIT": str(GIT_ALLOC_BYTES),
    }


def private_entries(fd, path, budget):
    """Inspect a pinned private directory without repeatedly reopening ancestors."""
    result = []
    with os.scandir(fd) as entries:
        for item in entries:
            if budget is not None:
                budget.check(len(os.fsencode(item.name)), 1)
            child = f"{path}/{item.name}" if path else item.name
            components(child)
            st = item.stat(follow_symlinks=False)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise Refusal("unsafe_snapshot_entry")
            if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
                raise Refusal("unsafe_snapshot_entry")
            result.append((item.name, child, st))
    return result


def inventory(root: Root) -> dict:
    """Metadata inventory of sealed private bytes, never source links or FDs."""
    result, budget = {}, GitBudget()

    def visit(fd, path=""):
        st = os.fstat(fd)
        result[path] = [st.st_mode, st.st_mtime_ns]
        for name, child, st in private_entries(fd, path, budget):
            if stat.S_ISDIR(st.st_mode):
                sub = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    visit(sub, child)
                finally:
                    os.close(sub)
            else:
                # Sealed bytes have no surviving writable descriptors. Byte or
                # mode replacement changes inode/mtime/ctime even after restore.
                result[child] = [st.st_mode, signature(st)]

    visit(root.fd)
    return result


def seal(root: Root, executables: set[str], thaw=False, path="") -> None:
    # Cleanup must still work after the creation budget has been exhausted.
    budget = None if thaw else GitBudget()

    def visit(fd, relative):
        if thaw:
            os.fchmod(fd, 0o700)
        for name, child, st in private_entries(fd, relative, budget):
            if stat.S_ISDIR(st.st_mode):
                sub = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    visit(sub, child)
                finally:
                    os.close(sub)
            elif not thaw:
                mode = 0o500 if child in executables else 0o400
                if stat.S_IMODE(st.st_mode) == mode:
                    continue
                leaf = os.open(name, FILE_FLAGS, dir_fd=fd)
                try:
                    if signature(os.fstat(leaf)) != signature(st):
                        raise Refusal("snapshot_modified")
                    os.fchmod(leaf, mode)
                finally:
                    os.close(leaf)
        if not thaw:
            os.fchmod(fd, 0o500)

    fd = root.directory(path, internal=True)
    try:
        visit(fd, path)
    finally:
        os.close(fd)


class Snapshot:
    def __init__(self, root, scratch: Path, purpose="status", paths=()):
        self.root, self.scratch = root, scratch
        if purpose not in ("status", "diff", "staged", "history"):
            raise Refusal("invalid_git_purpose")
        for path in paths:
            components(path)
            if sensitive(path):
                raise Refusal("sensitive_path")
        self.purpose, self.paths = purpose, tuple(paths)
        self.hidden_paths = set()
        self.origin = []
        self.executables = set()
        self.directory_versions = {}
        self.tracked = set()
        self.index_conflicts = set()

    def watch_directory(self, path):
        fd = self.root.directory(path, internal=True)
        try:
            version = signature(os.fstat(fd))
            if path in self.directory_versions and self.directory_versions[path] != version:
                raise Refusal("source_changed")
            self.directory_versions[path] = version
        finally:
            os.close(fd)

    def metadata_entries(self, path, budget):
        self.watch_directory(path)
        entries, version = self.root.entries(path, budget, internal=True)
        if version != self.directory_versions[path]:
            raise Refusal("source_changed")
        return entries

    def optional(self, path, budget):
        parent = path.rsplit("/", 1)[0]
        try:
            self.watch_directory(parent)
        except FileNotFoundError:
            return None
        try:
            return self.root.read(path, budget, internal=True)
        except FileNotFoundError:
            return None

    def copy(self, source, destination, budget):
        fd = self.root.file(source, internal=True)
        try:
            st = os.fstat(fd)
            before = signature(st)
            maximum = GIT_OBJECT_FILE_BYTES if source.startswith(".git/objects/") else GIT_FILE_BYTES
            if st.st_size > maximum:
                raise Refusal("git_snapshot_file_limit")
            hasher = hashlib.sha256()
            # Copy large packs incrementally; never hand Git source descriptors.
            out = self.create(destination)
            try:
                while True:
                    raw = os.read(fd, min(65536, max(1, budget.remaining + 1)))
                    budget.check(len(raw))
                    if not raw:
                        break
                    hasher.update(raw)
                    out.write(raw)
            finally:
                out.close()
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
            if st.st_mode & 0o111 and not destination.startswith(".git/"):
                self.executables.add(destination)
        finally:
            os.close(fd)
        self.origin.append([source, before, hasher.hexdigest()])

    def create(self, relative):
        components(relative)
        parts = components(relative)
        fd = os.dup(self.private.fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            return os.fdopen(leaf, "wb")
        finally:
            os.close(fd)

    def write(self, relative, raw):
        with self.create(relative) as stream:
            stream.write(raw)

    @staticmethod
    def refname(name):
        if (not re.fullmatch(r"refs/[A-Za-z0-9_./-]+", name)
                or ".." in name or any(p in ("", ".", "..") or p.endswith(".lock") for p in name.split("/"))
                or name.startswith("refs/replace/")):
            raise Refusal("unsupported_git_refs")
        components(name)
        return name

    def validate_ref(self, raw, packed=False):
        if packed:
            for line in raw.splitlines():
                if not line or line.startswith(b"#"):
                    continue
                if re.fullmatch(rb"\^[0-9a-f]{40}", line):
                    continue
                match = re.fullmatch(rb"[0-9a-f]{40} (refs/[A-Za-z0-9_./-]+)", line)
                if not match:
                    raise Refusal("unsupported_git_refs")
                self.refname(match[1].decode("ascii"))
        elif raw.startswith(b"ref: "):
            try:
                self.refname(raw[5:].decode("ascii").rstrip("\n"))
            except UnicodeDecodeError:
                raise Refusal("unsupported_git_refs") from None
        elif not re.fullmatch(rb"[0-9a-f]{40}\n?", raw):
            raise Refusal("unsupported_git_refs")

    def controls(self, budget):
        # A .git file (including a linked worktree) cannot pass directory().
        self.watch_directory(".git")
        forbidden = (
            ".git/commondir", ".git/gitdir", ".git/config.worktree",
            ".git/objects/info/alternates", ".git/objects/info/http-alternates",
            ".git/info/grafts", ".git/shallow", ".git/refs/replace",
        )
        for path in forbidden:
            parent, name = path.rsplit("/", 1)
            try:
                self.watch_directory(parent)
                fd = self.root.directory(parent, internal=True)
            except FileNotFoundError:
                continue
            try:
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Refusal("unsupported_git_layout")
            finally:
                os.close(fd)
        config = self.optional(".git/config", budget)
        safe_core = []
        if config:
            text = config.text()
            # Includes are rejected, never expanded. No source config is copied.
            if re.search(r"(?im)^\s*\[\s*(?:include|includeif|extensions)\b", text):
                raise Refusal("unsupported_git_config")
            if re.search(r"(?im)^\s*(?:worktree|commondir|gitdir)\s*=", text):
                raise Refusal("unsupported_git_layout")
            if re.search(r"(?im)^\s*repositoryformatversion\s*=\s*[^0\s]", text):
                raise Refusal("unsupported_git_layout")
            section = ""
            for line in text.splitlines():
                if line.lstrip().startswith("["):
                    section = line.strip().lower()
                elif section == "[core]" and "=" in line:
                    key, value = (s.strip().lower() for s in line.split("=", 1))
                    if key == "bare" and value not in ("false", "no", "off", "0"):
                        raise Refusal("unsupported_git_layout")
                    if key in ("filemode", "ignorecase", "precomposeunicode"):
                        if value not in ("true", "yes", "on", "1", "false", "no", "off", "0"):
                            raise Refusal("unsupported_git_config")
                        safe_core.append(key + " = " + ("true" if value in ("true", "yes", "on", "1") else "false"))
            self.origin.append([".git/config", config.version, config.sha256])
        generated_config = SAFE_CONFIG + ("\n[core]\n" + "\n".join(safe_core) + "\n").encode()
        budget.check(len(generated_config))
        self.write(".git/config", generated_config)
        head = self.root.read(".git/HEAD", budget, internal=True)
        if not re.fullmatch(rb"(?:ref: refs/heads/[A-Za-z0-9_./-]+|[0-9a-f]{40})\n?", head.raw):
            raise Refusal("unsupported_git_head")
        if b".." in head.raw:
            raise Refusal("unsupported_git_head")
        self.write(".git/HEAD", head.raw)
        self.origin.append([".git/HEAD", head.version, head.sha256])
        metadata = ["packed-refs"]
        if self.purpose != "history":
            metadata.append("index")
        if self.purpose in ("status", "diff"):
            metadata.append("info/exclude")
        for name in metadata:
            data = self.optional(".git/" + name, budget)
            if data is not None:
                if name == "packed-refs":
                    self.validate_ref(data.raw, packed=True)
                self.write(".git/" + name, data.raw)
                self.origin.append([".git/" + name, data.version, data.sha256])
        if self.purpose != "history":
            fd = self.root.directory(".git", internal=True)
            try:
                with os.scandir(fd) as entries:
                    for item in entries:
                        budget.check(len(os.fsencode(item.name)), 1)
                        if re.fullmatch(r"sharedindex\.[0-9a-f]{40}", item.name):
                            self.copy(".git/" + item.name, ".git/" + item.name, budget)
            finally:
                os.close(fd)
        def refs(path):
            for name, kind, _ in self.metadata_entries(path, budget):
                if kind == "directory":
                    refs(name)
                else:
                    self.refname(name.removeprefix(".git/"))
                    data = self.root.read(name, budget, internal=True)
                    self.validate_ref(data.raw)
                    self.write(name, data.raw)
                    self.origin.append([name, data.version, data.sha256])

        try:
            self.watch_directory(".git/refs")
        except FileNotFoundError:
            pass
        else:
            refs(".git/refs")
        # Require an actual local object database. Copy only semantic inputs;
        # acceleration files are not necessary and are disabled in safe config.
        for child, kind, _ in self.metadata_entries(".git/objects", budget):
            leaf = child.rsplit("/", 1)[-1]
            if leaf == "info":
                continue  # alternates were rejected above; commit-graphs omitted
            if kind != "directory" or not (leaf == "pack" or re.fullmatch(r"[0-9a-f]{2}", leaf)):
                raise Refusal("unsupported_git_objects")
            packs, indexes = set(), set()
            for name, item_kind, _ in self.metadata_entries(child, budget):
                filename = name.rsplit("/", 1)[-1]
                if leaf == "pack":
                    match = re.fullmatch(r"pack-([0-9a-f]{40})\.(pack|idx)", filename)
                    if match:
                        (packs if match[2] == "pack" else indexes).add(match[1])
                    elif (re.fullmatch(r"pack-[0-9a-f]{40}\.(bitmap|rev|keep|mtimes)", filename)
                          or filename in ("multi-pack-index", "multi-pack-index.d")):
                        continue
                    else:
                        raise Refusal("unsupported_git_objects")
                elif not re.fullmatch(r"[0-9a-f]{38}", filename):
                    raise Refusal("unsupported_git_objects")
                if item_kind != "file":
                    raise Refusal("unsupported_git_objects")
                self.copy(name, name, budget)
            if leaf == "pack" and packs != indexes:
                raise Refusal("git_pack_pair_incomplete")
        fd = self.private.directory(".git", internal=True)
        try:
            for name in ("objects", "refs"):
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
        finally:
            os.close(fd)

    def selected(self, path, directory=False):
        return not self.paths or any(path == p or path.startswith(p + "/")
                                     or (directory and p.startswith(path + "/")) for p in self.paths)

    def worktree(self, budget, path=""):
        fd = self.root.directory(path, internal=True)
        try:
            before = signature(os.fstat(fd))
            entries = []
            with os.scandir(fd) as items:
                for item in items:
                    budget.check(len(os.fsencode(item.name)), 1)
                    child = f"{path}/{item.name}" if path else item.name
                    if child == ".git":
                        continue
                    policy = item.name in (".gitignore", ".gitattributes")
                    if not self.selected(child, True) and not policy:
                        continue
                    components(child)
                    st = item.stat(follow_symlinks=False)
                    if sensitive(child):
                        self.hidden_paths.add(child)
                        self.origin.append([child, signature(st), "withheld"])
                        continue
                    if (not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode))
                            or (stat.S_ISREG(st.st_mode) and self.root.strict and st.st_nlink != 1)):
                        raise Refusal("unsafe_entry")
                    entries.append((child, "directory" if stat.S_ISDIR(st.st_mode) else "file", signature(st)))
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
        finally:
            os.close(fd)
        self.directory_versions[path] = before
        for child, kind, version in entries:
            if kind == "directory":
                self.worktree(budget, child)
            elif child in self.tracked or child.rsplit("/", 1)[-1] in (".gitignore", ".gitattributes"):
                self.copy(child, child, budget)
            else:
                # Git status needs untracked names/modes, never their content.
                self.write(child, b"")
                self.origin.append([child, version, "untracked_metadata"])
        fd = self.root.directory(path, internal=True)
        try:
            if signature(os.fstat(fd)) != before:
                raise Refusal("source_changed")
        finally:
            os.close(fd)

    def __enter__(self):
        # Pin every runtime component too. Native Git chdirs via this private
        # snapshot FD, so renaming an ancestor cannot redirect its cwd/config.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise Refusal("snapshot_cleanup_unavailable")
        project = Root("runtime", str(self.scratch.parents[1]), workspace=False)
        parent = os.dup(project.fd)
        project.close()
        self.parent_fd = None
        self.private = None
        try:
            for part in (".local", "tmp"):
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(part, DIR_FLAGS, dir_fd=parent)
                os.close(parent)
                parent = child
            self.parent_fd = parent
            self.name = "git-snapshot-" + secrets.token_hex(12)
            os.mkdir(self.name, 0o700, dir_fd=parent)
            fd = os.open(self.name, DIR_FLAGS, dir_fd=parent)
            try:
                self.private = Root.from_fd("snapshot", fd)
            finally:
                os.close(fd)
            self.path = self.scratch / self.name  # Diagnostics/tests only.
        except BaseException:
            os.close(parent)
            raise
        try:
            deadline = time.monotonic() + GIT_SNAPSHOT_SECONDS
            budget = GitBudget(deadline=deadline)
            self.controls(budget)
            if self.purpose != "history":
                seal(self.private, self.executables)
                self.sealed = inventory(self.private)
                code, raw, _ = self._execute(["ls-files", "--stage", "-z", "--", *self.paths])
                if code:
                    raise Refusal("git_index_query_failed")
                for record in raw.split(b"\0"):
                    if not record:
                        continue
                    try:
                        header, name = record.split(b"\t", 1)
                        mode, sha, stage = header.split()
                        path = name.decode("utf-8")
                        components(path)
                    except (ValueError, UnicodeDecodeError):
                        raise Refusal("unsupported_git_index") from None
                    if mode not in (b"100644", b"100755"):
                        raise Refusal("unsupported_git_index_mode")
                    self.tracked.add(path)
                    if stage != b"0":
                        self.index_conflicts.add(path)
                if self.purpose in ("status", "diff"):
                    code, flags, _ = self._execute(["ls-files", "-v", "-z", "--", *self.paths])
                    if code:
                        raise Refusal("git_index_query_failed")
                    if any(r[:1] not in (b"H", b"M") for r in flags.split(b"\0") if r):
                        raise Refusal("unsupported_git_index_flags")
                seal(self.private, self.executables, thaw=True)
            if self.purpose in ("status", "diff"):
                self.worktree(GitBudget(GIT_WORKTREE_BYTES, deadline, parent=budget))
            self.budget_bytes = GIT_SNAPSHOT_BYTES - budget.remaining
            budget.check()
            self.generation = binding([sorted(self.origin), sorted(self.directory_versions.items()), self.purpose, self.paths])
            # Reopen every copied source by descriptors, checking original version.
            # A race cannot redirect a later Git read back to the observed tree.
            by_directory = {}
            for name, version, sha in self.origin:
                if sha != "withheld":
                    parent, _, leaf = name.rpartition("/")
                    by_directory.setdefault(parent, []).append((leaf, version))
            for parent, leaves in by_directory.items():
                fd = self.root.directory(parent, internal=True)
                try:
                    for leaf, version in leaves:
                        if signature(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) != version:
                            raise Refusal("source_changed")
                finally:
                    os.close(fd)
            for name, version in self.directory_versions.items():
                fd = self.root.directory(name, internal=True)
                try:
                    if signature(os.fstat(fd)) != version:
                        raise Refusal("source_changed")
                finally:
                    os.close(fd)
            seal(self.private, self.executables)
            self.sealed = inventory(self.private)
            budget.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        try:
            if self.private is not None:
                seal(self.private, self.executables, thaw=True)
                # stdlib fd-based rmtree refuses symlink replacement attacks.
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise Refusal("snapshot_cleanup_unavailable")
                shutil.rmtree(self.name, dir_fd=self.parent_fd)
        finally:
            if self.private is not None:
                self.private.close()
            if self.parent_fd is not None:
                os.close(self.parent_fd)

    def run(self, args):
        return self._execute(args)

    def _execute(self, args):
        if sum(len(os.fsencode(a)) + 1 for a in args) > 128 * 1024:
            raise Refusal("git_pathspec_limit")
        if inventory(self.private) != self.sealed:
            raise Refusal("snapshot_modified")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        # No observed absolute path or source FD is passed to the executable.
        # Darwin fdescfs cannot chdir through /dev/fd. Hand off the pinned cwd
        # directly, under a process-wide lock, then immediately restore it.
        # The standalone stdio server runs tool handlers synchronously; do not
        # embed this module in an app with other cwd-dependent worker threads.
        with CWD_LOCK:
            previous = os.open(".", DIR_FLAGS)
            try:
                os.fchdir(self.private.fd)
                process = subprocess.Popen(FIXED_ARGS + args, env=safe_env(self.path),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, close_fds=True, shell=False,
                                           preexec_fn=child_limits)
            finally:
                os.fchdir(previous)
                os.close(previous)
        deadline = time.monotonic() + GIT_QUERY_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    if time.monotonic() > deadline:
                        raise Refusal("git_timeout")
                    for key, _ in selector.select(0.02):
                        raw = os.read(key.fd, 65536)
                        if not raw:
                            selector.unregister(key.fileobj)
                            continue
                        output[key.data].extend(raw)
                        if sum(map(len, output.values())) > MAX_SCAN:
                            raise Refusal("git_output_limit")
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
            process.stderr.close()
        if inventory(self.private) != self.sealed:
            raise Refusal("snapshot_modified")
        return code, bytes(output["stdout"]), bytes(output["stderr"])


def parse_status(raw: bytes):
    parts = raw.split(b"\0")
    if parts[-1] != b"":
        raise Refusal("invalid_git_output")
    results, index = [], 0
    while index < len(parts) - 1:
        record = parts[index]
        if len(record) < 4 or record[2:3] != b" ":
            raise Refusal("invalid_git_output")
        try:
            status_code, path = record[:2].decode("ascii"), record[3:].decode("utf-8")
            components(path.rstrip("/"))
        except (UnicodeDecodeError, Refusal):
            raise Refusal("invalid_git_output") from None
        origin = None
        if "R" in status_code or "C" in status_code:
            index += 1
            if index >= len(parts) - 1:
                raise Refusal("invalid_git_output")
            try:
                origin = parts[index].decode("utf-8")
                components(origin)
            except (UnicodeDecodeError, Refusal):
                raise Refusal("invalid_git_output") from None
        results.append({"status": status_code, "path": path, "origin": origin})
        index += 1
    return results


class GitReader:
    def __init__(self, config, redactor, cursors):
        self.config, self.redactor, self.cursors = config, redactor, cursors
        self.scratch = config.project / ".local/tmp"

    def snapshot(self, alias, purpose="status", paths=()):
        try:
            root = self.config.workspaces[alias]
        except KeyError:
            raise Refusal("unknown_alias") from None
        return Snapshot(root, self.scratch, purpose, paths)

    def checked(self, snapshot, args):
        code, raw, errors = snapshot.run(args)
        # Errors also cross the common redactor, never exception interpolation.
        safe_error = self.redactor.text(errors.decode("utf-8", "replace"))
        if code != 0:
            raise Refusal("git_query_failed")
        return raw

    def version(self, snapshot):
        return self.redactor.text(self.checked(snapshot, ["--version"]).decode().strip())

    def head_commit(self, snapshot):
        code, raw, _ = snapshot.run(["rev-parse", "--verify", "--quiet", "HEAD"])
        value = raw.decode("ascii", "replace").strip()
        if code == 0 and re.fullmatch(r"[0-9a-f]{40}", value):
            return value
        if code == 1 and not raw:
            return None  # unborn HEAD
        raise Refusal("git_query_failed")

    def status_data(self, snapshot, paths):
        raw = self.checked(snapshot, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all", "--no-renames", "--", *paths])
        parsed = parse_status(raw)
        visible, hidden, conflicts = [], 0, 0
        safe_paths = []
        for item in parsed:
            if sensitive(item["path"]) or (item["origin"] and sensitive(item["origin"])):
                hidden += 1
                if item["status"] in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}:
                    conflicts += 1
                continue
            safe_paths.append(item["path"])
            if not paths or any(item["path"] == p or item["path"].startswith(p + "/") for p in paths):
                visible.append(self.redactor.clean(item))
        withheld = hidden + len(snapshot.hidden_paths)
        return {"entries": visible, "hidden_status_entries": hidden, "hidden_conflicts": conflicts,
                "withheld_inventory_entries": len(snapshot.hidden_paths),
                "clean": False if visible or conflicts else ("unknown" if withheld or paths else not parsed),
                "filtered": bool(withheld or paths),
                "sensitive_worktree_content": "not_copied; hidden working changes are unknown",
                "safe_changed_paths": safe_paths}

    def status(self, alias, paths=None, limit=25, cursor=None):
        paths = paths or []
        filters = [alias, paths]
        state = self.cursors.read(cursor, "git_status", filters)
        with self.snapshot(alias, "status", paths) as snapshot:
            if state and state["generation"] != snapshot.generation:
                raise Refusal("source_changed")
            result = self.status_data(snapshot, paths)
            result.pop("safe_changed_paths")
            start = state["offset"] if state else 0
            entries, used, end = [], 0, start
            for item in result["entries"][start:]:
                if len(entries) == limit or used + item_size(item) > 18000:
                    break
                entries.append(item)
                used += item_size(item)
                end += 1
            more = end < len(result["entries"])
            result["entries"] = entries
            result.update({"ok": True, "snapshot_budget_bytes": snapshot.budget_bytes, "head_commit": self.head_commit(snapshot), "git_version": self.version(snapshot), "source_generation": snapshot.generation,
                           "isolation": "sealed_sanitized_snapshot", "next_cursor": self.cursors.issue("git_status", filters, {"offset": end, "generation": snapshot.generation}) if more else None})
            return result

    def diff(self, alias, paths=None, staged=False, cursor=None):
        paths = paths or []
        filters = [alias, paths, staged]
        state = self.cursors.read(cursor, "git_diff", filters)
        with self.snapshot(alias, "staged" if staged else "diff", paths) as snapshot:
            if state and state["generation"] != snapshot.generation:
                raise Refusal("source_changed")
            # Both name enumeration and patch rendering use actual Git pathspecs.
            # Cached diff uses only HEAD/objects/index and never status/worktree.
            args = ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=all"]
            if staged:
                args.append("--cached")
            names = self.checked(snapshot, args + ["--name-only", "-z", "--", *paths])
            candidates, hidden = [], 0
            for name in names.split(b"\0"):
                if not name:
                    continue
                try:
                    path = name.decode("utf-8")
                    components(path)
                except (UnicodeDecodeError, Refusal):
                    raise Refusal("invalid_git_output") from None
                if sensitive(path):
                    hidden += 1
                else:
                    candidates.append(path)
            status_data = {"hidden_status_entries": hidden,
                           "hidden_conflicts": sum(sensitive(p) for p in snapshot.index_conflicts),
                           "filtered": bool(hidden or snapshot.hidden_paths or paths)}
            patch = ""
            if candidates:
                raw = self.checked(snapshot, args + ["--", *candidates])
                decoded = raw.decode("utf-8", "replace")
                # Withhold an entire patch containing a recognized Codex log
                # record, before redaction, snippets or serialization.
                for line in decoded.splitlines():
                    if line[:1] in {"+", "-", " "} and is_session_record(line[1:]):
                        raise Refusal("session_log_requires_exact_session_registration")
                patch = self.redactor.text(decoded)
            start = state["offset"] if state else 0
            lines = patch.splitlines()
            result, used, index = [], 0, start
            character = state.get("character", 0) if state else 0
            while index < len(lines) and len(result) < 200:
                full = lines[index]
                part, _ = clip(full[character:], 1800)
                text, _ = text_window(part)
                after = character + len(text)
                item = {"patch_line": index + 1, "text": text, "text_truncated": after < len(full),
                        "char_start": character, "char_end": after, "line_chars_redacted": len(full)}
                if used + item_size(item) > 18000:
                    break
                result.append(item)
                used += item_size(item)
                if after < len(full):
                    character = after
                else:
                    index, character = index + 1, 0
            return {"ok": True, "lines": result, "patch_line_count": len(lines),
                    "snapshot_budget_bytes": snapshot.budget_bytes,
                    "comparison": "index_vs_HEAD" if staged else "worktree_vs_index",
                    "untracked_content": "not_included", "isolation": "sealed_sanitized_snapshot",
                    "withheld_inventory_entries": len(snapshot.hidden_paths),
                    "offset_unit": "redacted_unicode_codepoints_per_line", "patch_sha256_redacted": digest(patch.encode()),
                    "hidden_status_entries": status_data["hidden_status_entries"],
                    "hidden_conflicts": status_data["hidden_conflicts"], "filtered": status_data["filtered"],
                    "git_version": self.version(snapshot), "source_generation": snapshot.generation,
                    "next_cursor": self.cursors.issue("git_diff", filters, {"offset": index, "character": character, "generation": snapshot.generation}) if index < len(lines) else None}

    def history_detail(self, alias, paths, message_cursor, cursor):
        filters = [alias, paths]
        ref = self.cursors.read(message_cursor, "git_message_ref", filters)
        if ref is None:
            raise Refusal("invalid_cursor")
        page_filters = [*filters, message_cursor]
        state = self.cursors.read(cursor, "git_message", page_filters)
        with self.snapshot(alias, "history", paths) as snapshot:
            if ref["generation"] != snapshot.generation:
                raise Refusal("source_changed")
            raw = self.checked(snapshot, ["show", "-s", "--no-show-signature", "--no-notes", "--format=%B", ref["commit"], "--"])
            full = self.redactor.text(raw.decode("utf-8", "replace")).rstrip()
            start = state["offset"] if state else 0
            part, end = text_window(full, start, 12000)
            return {"ok": True, "commit": ref["commit"], "message": part,
                    "char_start": start, "char_end": end, "total_chars_redacted": len(full),
                    "message_sha256_redacted": digest(full.encode()), "message_truncated": end < len(full),
                    "source_generation": snapshot.generation,
                    "next_cursor": self.cursors.issue("git_message", page_filters, {"offset": end}) if end < len(full) else None}

    def history(self, alias, paths=None, limit=10, cursor=None, message_cursor=None):
        paths = paths or []
        if cursor is not None and message_cursor is None and self.cursors.kind(cursor) == "git_content":
            filters = [alias, paths]
            state = self.cursors.read(cursor, "git_content", filters)
            result = self.history_detail(alias, paths, state["reference"], state["page"])
            inner = result["next_cursor"]
            result["mode"] = "commit_message_content"
            result["next_cursor"] = self.cursors.issue("git_content", filters, {**state, "page": inner}) if inner else None
            return result
        if message_cursor is not None:
            return self.history_detail(alias, paths, message_cursor, cursor)
        filters = [alias, paths]
        state = self.cursors.read(cursor, "git_history", filters)
        with self.snapshot(alias, "history", paths) as snapshot:
            if state and state["generation"] != snapshot.generation:
                raise Refusal("source_changed")
            skip = state["offset"] if state else 0
            head = self.head_commit(snapshot)
            raw = self.checked(snapshot, ["log", "--no-show-signature", "--no-notes", "--no-decorate", f"--max-count={limit + 1}", f"--skip={skip}", "--format=%H", "HEAD", "--", *paths]) if head else b""
            hashes = raw.decode("ascii").splitlines()
            commits, used = [], 0
            for sha in hashes[:limit]:
                if not re.fullmatch(r"[0-9a-f]{40}", sha):
                    raise Refusal("invalid_git_output")
                raw = self.checked(snapshot, ["show", "-s", "--no-show-signature", "--no-notes", "--format=%H%n%at%n%B", sha, "--"])
                text = self.redactor.text(raw.decode("utf-8", "replace"))
                fields = text.split("\n", 2)
                if len(fields) != 3 or not fields[1].isdigit():
                    raise Refusal("invalid_git_output")
                message, truncated = clip(fields[2].rstrip(), 1500)
                item = {"commit": sha, "unix_timestamp": int(fields[1]), "message": RedactedFragment(message),
                        "message_truncated": truncated, "message_chars_redacted": len(fields[2].rstrip())}
                if truncated:
                    item["message_cursor"] = self.cursors.issue("git_message_ref", filters, {
                        "commit": sha, "generation": snapshot.generation})
                    item["content_cursor"] = self.cursors.issue("git_content", filters, {
                        "reference": item["message_cursor"], "page": None})
                    item["detail_usage"] = "git_history with same alias/paths and cursor=content_cursor; continue next_cursor"
                if used + item_size(item) > 18000:
                    break
                commits.append(item)
                used += item_size(item)
            more = len(hashes) > len(commits)
            return {"ok": True, "commits": commits, "head_commit": head, "git_version": self.version(snapshot),
                    "snapshot_budget_bytes": snapshot.budget_bytes,
                    "source_generation": snapshot.generation, "paths_filtered": bool(paths),
                    "next_cursor": self.cursors.issue("git_history", filters, {"offset": skip + len(commits), "generation": snapshot.generation}) if more else None}
