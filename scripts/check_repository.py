"""Check or export only PUBLIC_FILES.txt; never walk private working directories.

This is a bounded file/pattern check, not an ownership or secret attestation.
Exports require a new destination and do not initialize Git or publish anything.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).absolute().parent))
from check_release import PATTERNS, allowed

ROOT = Path(__file__).absolute().parents[1]
MAX_FILE = 1024 * 1024


def read_regular(root, name):
    """Open only declared components, refusing symlinks and multiple hardlinks."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                raise ValueError('unsafe_public_file')
            raw = bytearray()
            while len(raw) <= MAX_FILE:
                block = os.read(file_fd, min(65536, MAX_FILE + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(file_fd)
            if len(raw) > MAX_FILE or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('public_file_changed')
            return bytes(raw), stat.S_IMODE(before.st_mode)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def public_files(root):
    raw, _ = read_regular(root, 'PUBLIC_FILES.txt')
    names = [line for line in raw.decode('utf-8').splitlines() if line and not line.startswith('#')]
    if not 1 <= len(names) <= 256 or names != sorted(set(names)):
        raise ValueError('invalid_public_manifest')
    for name in names:
        parts = PurePosixPath(name).parts
        if (not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name)
                or any(p in {'.', '..', '.local', '.git', '.venv'} for p in parts)
                or not allowed(name, 'sdist') or name in {'PKG-INFO', 'setup.cfg'}
                or '.egg-info' in name or '.dist-info' in name):
            raise ValueError('invalid_public_manifest')
    if not {'.gitignore', 'PUBLIC_FILES.txt', 'MANIFEST.in', 'LICENSE', 'README.md', 'README.zh-CN.md'} <= set(names):
        raise ValueError('invalid_public_manifest')
    return names


def gitignore_text(names):
    dirs = {str(p) for name in names for p in PurePosixPath(name).parents if str(p) != '.'}
    lines = ['# Generated from PUBLIC_FILES.txt; unknown files stay private until reviewed.', '/*']
    for directory in sorted(dirs, key=lambda n: (n.count('/'), n)):
        lines.extend(['!/' + directory + '/', '/' + directory + '/*'])
    lines.extend('!/' + name for name in names)
    return '\n'.join(lines) + '\n'


def manifest_text(names):
    return '# Explicit public source allowlist; generated from PUBLIC_FILES.txt.\nglobal-exclude *\n' + ''.join(
        'include ' + name + '\n' for name in names)


def inspect_repository(root):
    names = public_files(root)
    issues, hashes, total = [], {}, 0
    for name in names:
        try:
            raw, _ = read_regular(root, name)
        except (OSError, ValueError):
            issues.append({'category': 'missing_or_unsafe_public_file', 'location': name})
            continue
        total += len(raw)
        if total > 8 * 1024 * 1024:
            raise ValueError('public_tree_limit')
        hashes[name] = hashlib.sha256(raw).hexdigest()
        for category, pattern in PATTERNS.items():
            lines = sorted({raw.count(b'\n', 0, m.start()) + 1 for m in pattern.finditer(raw)})
            if lines:
                issues.append({'category': category, 'location': name, 'lines': lines[:32]})
        expected = {'.gitignore': gitignore_text(names), 'MANIFEST.in': manifest_text(names)}.get(name)
        if expected is not None and raw != expected.encode():
            issues.append({'category': 'manifest_policy_drift', 'location': name})
    return {'ok': not issues, 'public_files_checked': len(hashes), 'bytes_checked': total,
            'issues': issues, 'member_sha256': hashes,
            'scope': 'explicit_public_files_only; no_private_tree_or_history_scan; not_license_or_secret_attestation'}


def export_repository(root, destination):
    report = inspect_repository(root)
    if not report['ok']:
        raise ValueError('public_check_failed; export_not_started')
    destination = Path(destination).absolute()
    for parent in (destination, *destination.parents):
        if parent.is_symlink():
            raise ValueError('unsafe_export_destination')
    if destination.exists():
        raise ValueError('export_destination_must_not_exist')
    # Capture and verify every public byte before creating output; never copy a tree.
    content = {}
    for name, digest in report['member_sha256'].items():
        raw, mode = read_regular(root, name)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('public_source_changed; export_not_started')
        content[name] = (raw, mode)
    destination.mkdir(mode=0o700)  # Parent must already exist; no implicit scope expansion.
    for name, (raw, mode) in content.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o755 if mode & 0o111 else 0o644)
    if inspect_repository(destination)['member_sha256'] != report['member_sha256']:
        raise ValueError('export_verification_failed; partial_output_preserved')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path, metavar='NEW_DIRECTORY')
    args = parser.parse_args()
    try:
        report = export_repository(ROOT, args.export) if args.export else inspect_repository(ROOT)
        print(json.dumps(report, indent=2))
        return 0 if report['ok'] else 1
    except Exception:
        print('{"ok":false,"error":"invalid_or_unsafe_public_tree_or_destination; raw_errors_suppressed"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
