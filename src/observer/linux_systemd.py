"""Version-aware renderer; never installs a unit or accesses credential values."""
import re
import subprocess
import sys
from .security import Refusal
from .runtime import environment


def detect_version():
    """Ask the active manager, not the distro, Python, or only the client binary."""
    try:
        result = subprocess.run(['/bin/systemctl', 'show', '--property=Version'], env=environment(),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, close_fds=True, check=False)
        match = re.fullmatch(rb'Version=(\d+)[^\r\n]*\r?\n?', result.stdout)
        if result.returncode != 0 or not match:
            raise Refusal('systemd_manager_version_unavailable')
        return int(match[1])
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal('systemd_manager_version_unavailable') from None


def features(version):
    if type(version) is not int or version < 219:
        raise Refusal('systemd_219_or_newer_required')
    # Evaluate individual upstream introduction versions, independently of the
    # credential backend: paths=231, strict=232, LoadCredential=247.
    return {'native_credentials': version >= 247, 'path_directives': version >= 231,
            'strict_paths': version >= 232}


def quote(value, command=False):
    if any(ord(c) < 32 for c in str(value)):
        raise Refusal('invalid_unit_path')
    value = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if command:
        value = value.replace('$', '$$')
    return '"' + value + '"'


def legacy_path(value):
    value = str(value)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', value) or any(p in {'.', '..', ''} for p in value.split('/')[1:]):
        raise Refusal('systemd_219_path_cannot_be_encoded_safely')
    return value


def render(store, version=None):
    store.require()
    version = detect_version() if version is None else version
    caps = features(version)
    home = str(store.home)
    native = caps['native_credentials']
    tunnel = store.settings()['transport']['kind'] == 'tunnel'
    # v219 scalar path parsers retain quote characters. Use strictly validated,
    # unquoted paths there; refuse ambiguous paths instead of emitting bad units.
    working = legacy_path(home) if not native else legacy_path(home) if re.fullmatch(r'/[A-Za-z0-9_./-]+', home) else quote(home)
    arguments = [sys.executable, '-I', '-B', '-m', 'observer.cli', '--home', home]
    if native:
        start = ' '.join(quote(p, command=True) for p in arguments)
    else:
        start = ' '.join([legacy_path(sys.executable), '-I', '-B', '-m', 'observer.cli', '--home', legacy_path(home)])
    lines = ['[Unit]', 'Description=ReadOnly Observer instance', 'After=network-online.target',
             'Wants=network-online.target', '', '[Service]', 'Type=simple', 'UMask=0077',
             'WorkingDirectory=' + working]
    writable = [home]
    if not native and tunnel:
        from .linux_legacy import runtime_name, runtime_path
        runtime = str(runtime_path(store))
        lines += ['RuntimeDirectory=' + runtime_name(store), 'RuntimeDirectoryMode=0700',
                  'Environment=CREDENTIALS_DIRECTORY=' + runtime]
        writable.append(runtime)
    lines += ['ExecStartPre=' + start + ' recover --approve']
    if not native and tunnel:
        lines += ['ExecStartPre=' + start + ' _stage-credentials']
    lines += ['ExecStart=' + start + ' run', 'Restart=on-failure', 'RestartSec=5s',
              'KillMode=control-group', 'TimeoutStopSec=20s', 'NoNewPrivileges=true',
              'ProtectSystem=' + ('strict' if caps['strict_paths'] else 'full'),
              'ProtectHome=read-only', 'PrivateTmp=true']
    if caps['path_directives']:
        lines += ['ReadOnlyPaths=/ /tmp /var/tmp', 'ReadWritePaths=' + ' '.join(quote(p) for p in writable)]
    else:
        lines += ['ReadOnlyDirectories=/ /tmp /var/tmp', 'ReadWriteDirectories=' + ' '.join(legacy_path(p) for p in writable)]
    lines += ['LimitCORE=0', 'StandardOutput=null', 'StandardError=null']
    if native and tunnel:
        kinds = ['runtime'] + (['proxy'] if store.linux_settings()['proxy'] else [])
        lines += ['LoadCredential=' + store.credential_name(kind) + ':' + quote(store.home / 'credentials' / kind) for kind in kinds]
    return '\n'.join(lines + ['', '[Install]', 'WantedBy=multi-user.target', ''])
