"""Linux-only systemd Credentials and private operator staging. Lazy imported."""
import os
import stat
import sys
from urllib.parse import urlsplit
from .security import Refusal
from .credentials import validate_key
from .fs import DIR_FLAGS, FILE_FLAGS, components, signature

def validate_proxy(value):
    try:
        if not isinstance(value, str) or len(value) > 8192 or any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError()
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname or url.path not in {"", "/"} or url.query or url.fragment:
            raise ValueError()
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError()
    except (ValueError, TypeError):
        raise Refusal("invalid_tunnel_proxy") from None
    return value


class SystemdCredentials:
    """Read only a named systemd credential; never fall back to env keys or disk.

    Native systemd 247+ or a restricted legacy ExecStartPre supplies the
    instance directory. Metadata checks are defense in depth, not proof of
    systemd provenance against the owning UID. No source fallback occurs.
    """
    def __init__(self, name, validator=validate_key):
        self.name, self.validator = name, validator

    def get(self):
        if not sys.platform.startswith("linux"):
            raise Refusal("systemd_credentials_require_linux")
        path = os.environ.get("CREDENTIALS_DIRECTORY", "")
        if not path.startswith("/"):
            raise Refusal("systemd_credentials_directory_required; use_foreground_run_in_unit")
        fd = None
        try:
            fd = os.open("/", DIR_FLAGS)
            for part in components(path[1:]):
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Refusal("unsafe_systemd_credentials_directory")
            secret = os.open(self.name, FILE_FLAGS, dir_fd=fd)
            try:
                info = os.fstat(secret)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) not in {0o400, 0o600} or not 0 < info.st_size <= 8193):
                    raise Refusal("unsafe_systemd_credential")
                raw = os.read(secret, 8194)
                if signature(os.fstat(secret)) != signature(info) or len(raw) != info.st_size:
                    raise Refusal("systemd_credential_changed")
                # Accept one terminal LF, as produced by common secret managers.
                return self.validator(raw.removesuffix(b"\n").decode("ascii"))
            finally:
                os.close(secret)
        except (OSError, UnicodeError, ValueError):
            raise Refusal("systemd_credential_unavailable_or_unsafe") from None
        finally:
            if fd is not None:
                os.close(fd)


def stage(store, kind, value):
    """Atomic private LoadCredential source. No value in JSON, backups or logs."""
    import secrets
    store.credential_name(kind)
    from .profile import private_directory
    validate_key(value) if kind == 'runtime' else validate_proxy(value)
    private_directory(store.home / 'credentials')
    directory = os.open(store.home / 'credentials', DIR_FLAGS)
    temporary = '.pending-' + secrets.token_hex(12)
    try:
        try:
            current = os.stat(kind, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                                    or current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600):
            raise Refusal('unsafe_staged_credential')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            raw = value.encode('ascii')
            while raw:
                raw = raw[os.write(fd, raw):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, kind, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def delete_staged(store, kind):
    """Delete local source only; already loaded systemd credentials remain live."""
    from .fs import Root
    store.credential_name(kind)
    try:
        root = Root('credential-source', str(store.home / 'credentials'), workspace=False)
    except FileNotFoundError:
        return
    try:
        info = os.stat(kind, dir_fd=root.fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refusal('unsafe_staged_credential')
        os.unlink(kind, dir_fd=root.fd)
    except FileNotFoundError:
        pass
    finally:
        root.close()
