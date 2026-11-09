"""Root-only systemd 219 credential preparation. Never used by MCP Workers.

Only ExecStartPre reads the persistent sources. The unchanged runtime Provider
continues to consume instance-named credentials from CREDENTIALS_DIRECTORY.
"""
import ctypes
import os
from pathlib import Path
import secrets
import stat

from .fs import DIR_FLAGS, FILE_FLAGS, Root, signature
from .credentials import validate_key
from .linux_credentials import validate_proxy
from .security import Refusal

TMPFS_MAGIC = 0x01021994


def runtime_name(store):
    return 'readonly-observer-' + store.namespace()


def runtime_path(store):
    return Path('/run') / runtime_name(store)


def is_tmpfs(fd):
    # fstatfs checks the pinned directory itself, including any nested mount.
    # A generously sized, long-aligned output buffer avoids ABI struct layout
    # assumptions beyond Linux's first f_type field (long).
    library = ctypes.CDLL(None, use_errno=True)
    function = library.fstatfs
    function.argtypes = [ctypes.c_int, ctypes.c_void_p]
    function.restype = ctypes.c_int
    buffer = (ctypes.c_long * 64)()
    if function(fd, ctypes.byref(buffer)) != 0:
        raise Refusal('runtime_filesystem_check_failed')
    return buffer[0] == TMPFS_MAGIC


def _file(info, modes):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in modes or not 0 < info.st_size <= 8193):
        raise Refusal('unsafe_legacy_credential_source')


def _read(source, kind):
    fd = os.open(kind, FILE_FLAGS, dir_fd=source.fd)
    try:
        before = os.fstat(fd)
        _file(before, {0o600})
        raw = os.read(fd, 8194)
        if len(raw) != before.st_size or signature(os.fstat(fd)) != signature(before):
            raise Refusal('legacy_credential_source_changed')
        value = raw.removesuffix(b'\n').decode('ascii')
        (validate_key if kind == 'runtime' else validate_proxy)(value)
        if signature(os.stat(kind, dir_fd=source.fd, follow_symlinks=False)) != signature(before):
            raise Refusal('legacy_credential_source_changed')
        return fd, before, raw
    except BaseException:
        os.close(fd)
        raise


def prepare(store):
    """Publish exactly enabled credentials, with no replacement and rollback.

    RuntimeDirectory must already exist, be empty/root-only and reside on
    tmpfs. A second invocation against an occupied directory refuses rather
    than treating an earlier startup's files as its own.
    """
    if os.geteuid() != 0 or os.getuid() != 0:
        raise Refusal('legacy_credentials_require_root')
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    store.require()
    if store.settings()['transport']['kind'] != 'tunnel':
        raise Refusal('legacy_staging_requires_tunnel_transport')
    expected = runtime_path(store)
    if os.environ.get('CREDENTIALS_DIRECTORY') != str(expected):
        raise Refusal('legacy_runtime_directory_mismatch')
    target = source = None
    opened, created = [], []
    success = False
    try:
        target = Root('credential-runtime', str(expected), workspace=False)
        info = os.fstat(target.fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal('unsafe_legacy_runtime_directory')
        if not is_tmpfs(target.fd):
            raise Refusal('legacy_runtime_directory_requires_tmpfs')
        if os.listdir(target.fd):
            raise Refusal('legacy_runtime_directory_not_empty; no_overwrite')
        # O_EXCL serializes overlapping preparations without accepting a stale
        # lock. It is deleted on success and failure, only if still our inode.
        lock = '.observer-stage-lock'
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=target.fd)
        created.append((lock, os.fstat(fd).st_ino))
        os.close(fd)
        source = Root('credential-source', str(store.home / 'credentials'), workspace=False)
        info = os.fstat(source.fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal('unsafe_legacy_source_directory')
        kinds = ['runtime'] + (['proxy'] if store.linux_settings()['proxy'] else [])
        # Validate every enabled source before publishing anything.
        for kind in kinds:
            opened.append((kind, *_read(source, kind)))
        for kind, source_fd, before, raw in opened:
            name = store.credential_name(kind)
            pending = '.pending-' + secrets.token_hex(16)
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=target.fd)
            inode = os.fstat(fd).st_ino
            created.append((pending, inode))
            try:
                os.fchmod(fd, 0o600)
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise Refusal('legacy_credential_write_failed')
                    remaining = remaining[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            # link/unlink atomically publishes a complete inode without ever
            # overwriting a destination. Both names exist only in ExecStartPre;
            # Manager starts after all pending names are removed (nlink == 1).
            os.link(pending, name, src_dir_fd=target.fd, dst_dir_fd=target.fd, follow_symlinks=False)
            created.append((name, inode))
            os.unlink(pending, dir_fd=target.fd)
        for kind, fd, before, raw in opened:
            if (signature(os.fstat(fd)) != signature(before)
                    or signature(os.stat(kind, dir_fd=source.fd, follow_symlinks=False)) != signature(before)):
                raise Refusal('legacy_credential_source_changed')
        current = os.stat(expected, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (os.fstat(target.fd).st_dev, os.fstat(target.fd).st_ino):
            raise Refusal('legacy_runtime_directory_changed')
        os.unlink(lock, dir_fd=target.fd)
        os.fsync(target.fd)
        success = True
        return {'prepared': len(kinds), 'backend': 'legacy-runtime', 'credential_values': 'never_returned'}
    except Refusal:
        raise
    except (OSError, ValueError, UnicodeError):
        raise Refusal('legacy_credential_staging_failed; raw_errors_suppressed') from None
    finally:
        for kind, fd, before, raw in opened:
            os.close(fd)
        if target is not None:
            cleanup_failed = False
            try:
                if not success:
                    for name, inode in reversed(created):
                        try:
                            if os.stat(name, dir_fd=target.fd, follow_symlinks=False).st_ino == inode:
                                os.unlink(name, dir_fd=target.fd)
                        except FileNotFoundError:
                            pass
                        except OSError:
                            cleanup_failed = True
                    try:
                        os.fsync(target.fd)
                    except OSError:
                        cleanup_failed = True
            finally:
                target.close()
                if source is not None:
                    source.close()
            if cleanup_failed:
                raise Refusal('legacy_credential_cleanup_failed; manual_runtime_review_required') from None
        elif source is not None:
            source.close()
