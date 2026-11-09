"""Linux lifecycle adapter; reuses stable relay/protocol, never imported on Mac."""
import fcntl
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import subprocess
import threading
import time

from . import runtime as common, nodes
from .security import Refusal, binding, canonical
from .linux_credentials import validate_proxy

# Stable protocol and environment helpers are shared, not reimplemented.
argv, environment = common.argv, common.environment
check_binary, stop, connect = common.check_binary, common.stop, common.connect


def status(store):
    result = common.status(store)
    result['node'] = nodes.identity(store)
    if result['manager'] == 'running':
        result['configuration_pending'] |= (store.state.read_file('node-active.json') != nodes.identity(store)
                                            or store.state.read_file('linux-active.json') != store.linux_settings())
    return result


def start(store):
    store.require()
    before = status(store)
    if before['manager'] == 'running':
        return {**before, 'action': 'already_started'}
    if before['manager'] != 'not_running':
        raise Refusal('existing_manager_unreachable; no_takeover_or_PID_kill')
    common.socket_path(store, 'control.sock')
    common.socket_path(store, 'mcp.sock')
    env = environment()
    if store.settings()['transport']['kind'] == 'tunnel':
        path = os.environ.get('CREDENTIALS_DIRECTORY', '')
        if not path.startswith('/'):
            raise Refusal('systemd_credentials_directory_required; use_run_in_unit')
        env['CREDENTIALS_DIRECTORY'] = path
    child = subprocess.Popen(argv(store, '_manager'), env=env, cwd=store.home, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            failure = store.state.read_file('last-error.json', {'code': 'manager_start_failed'})
            raise Refusal(failure['code'])
        try:
            result = common.request(store, 'status')
            threading.Thread(target=child.wait, daemon=True).start()
            return {**result, 'action': 'started', 'ready': False,
                    'note': 'local process only; remote end-to-end remains unverified'}
        except (FileNotFoundError, ConnectionError, socket.timeout):
            time.sleep(0.05)
    common.kill_owned(child)
    raise Refusal('manager_start_timeout')


def client_config(store, tunnel, proxy=False):
    config = common.client_config(store, tunnel)
    # The client connects to the manager. The manager alone starts clean Workers.
    import shlex
    config['mcp']['commands'][0]['command'] = shlex.join(['/usr/bin/env', '-i', *argv(store, 'connect')])
    if proxy:
        config['control_plane']['http_proxy'] = 'env:OBSERVER_TUNNEL_PROXY'
    return config


def watch_parent(fd):
    """Pipe EOF terminates read-only workers even after manager SIGKILL."""
    def watch():
        try:
            while os.read(fd, 1):
                pass
        finally:
            os._exit(0)
    threading.Thread(target=watch, daemon=True).start()


def supervise_tunnel(store, parent_fd):
    """A local supervisor closes the real client when its manager dies."""
    transport = store.state.read_file('active.json')['settings']['transport']
    common.check_binary(transport['client'])
    command = [transport['client'], 'run', '--config', str(store.home / 'state/transport.json'),
               '--log.http-raw-unsafe=false', '--allow-remote-ui=false', '--open-web-ui=false']
    env = environment()
    for name in ('CONTROL_PLANE_API_KEY', 'OBSERVER_TUNNEL_PROXY', 'TMPDIR', 'XDG_CONFIG_HOME',
                 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_RUNTIME_DIR'):
        if name in os.environ:
            env[name] = os.environ[name]
    child = None
    previous = {}
    stopped = threading.Event()
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *a: stopped.set())
        child = subprocess.Popen(command, env=env, cwd=store.home, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        env.clear()
        with selectors.DefaultSelector() as selector:
            selector.register(parent_fd, selectors.EVENT_READ)
            while not stopped.is_set():
                result = child.poll()
                if result is not None:
                    return result or 2
                if selector.select(0.1) and not os.read(parent_fd, 1):
                    break
    finally:
        env.clear()
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0


def tunnel_lease(identifier):
    """Kernel-owned, UID-scoped lease; also works across systemd PrivateTmp.

    The Linux abstract socket has no filesystem artifact or protocol. Keeping
    its descriptor open owns the lease; kernel teardown releases it on crashes.
    Different hosts/UIDs still require operator-enforced unique identities.
    """
    import errno
    name = '\0readonly-observer-' + str(os.getuid()) + '-' + hashlib.sha256(identifier.encode()).hexdigest()
    lease = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        lease.bind(name)
        return lease.detach()
    except OSError as error:
        lease.close()
        if error.errno == errno.EADDRINUSE:
            raise Refusal('tunnel_already_in_use_on_this_host') from None
        raise Refusal('tunnel_lease_unavailable') from None


def recover(store):
    """Remove only reviewed, known runtime artifacts under an exclusive lease."""
    store.require()
    with store.state.directory() as directory:
        fd = os.open('manager.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            store.state.regular(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal('recovery_refused; manager_or_owned_children_still_running') from None
            artifacts = []
            for name in ('control.sock', 'mcp.sock', 'active.json', 'transport.json', 'node-active.json', 'linux-active.json', 'health.url'):
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                valid_kind = stat.S_ISSOCK(info.st_mode) if name.endswith('.sock') else stat.S_ISREG(info.st_mode)
                if not valid_kind or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise Refusal('unsafe_recovery_artifact; manual_review_required')
                artifacts.append((name, info.st_ino))
            for name, inode in artifacts:
                if os.stat(name, dir_fd=directory, follow_symlinks=False).st_ino != inode:
                    raise Refusal('recovery_artifact_changed')
                os.unlink(name, dir_fd=directory)
        finally:
            os.close(fd)
    return {'recovered_files': len(artifacts), 'credentials_accessed': False, 'remote_permissions': 'unchanged'}


def manage(store):
    store.require()
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    child, listeners, workers, previous, created = None, [], [], {}, []
    stopped = threading.Event()
    lock_fd = tunnel_fd = read_fd = write_fd = None
    def record(name):
        created.append((name, os.lstat(store.home / 'state' / name).st_ino))
    try:
        with store.state.directory() as directory:
            lock_fd = os.open('manager.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        store.state.regular(lock_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('manager_already_running') from None
        # Freeze all Linux-only sidecars along with the unchanged v1 snapshot.
        with store.mutation():
            snapshot, node, linux = store.snapshot(), nodes.identity(store), store.linux_settings()
            config = store.configuration()
            config.close()
        for name in ('control.sock', 'mcp.sock', 'active.json', 'transport.json', 'node-active.json', 'linux-active.json'):
            if os.path.lexists(store.home / 'state' / name):
                raise Refusal('stale_runtime_requires_explicit_local_review')
        for name, value in (('active.json', snapshot), ('node-active.json', node), ('linux-active.json', linux)):
            store.state.write_file(name, value)
            record(name)
        read_fd, write_fd = os.pipe()
        transport = snapshot['settings']['transport']
        if transport['kind'] == 'tunnel':
            common.check_binary(transport['client'])
            tunnel_fd = tunnel_lease(transport['tunnel_id'])
            store.state.write_file('transport.json', client_config(store, transport, linux['proxy']))
            record('transport.json')
            env = environment()
            env.update({'TMPDIR': str(store.home / 'cache'), 'XDG_CONFIG_HOME': str(store.home / 'config'),
                        'XDG_CACHE_HOME': str(store.home / 'cache'), 'XDG_DATA_HOME': str(store.home / 'cache'),
                        'XDG_RUNTIME_DIR': str(store.home / 'state')})
            try:
                env['CONTROL_PLANE_API_KEY'] = store.credential().get()
                if linux['proxy']:
                    env['OBSERVER_TUNNEL_PROXY'] = validate_proxy(store.credential('proxy').get())
                child = subprocess.Popen([*argv(store, '_tunnel'), '--parent-fd', str(read_fd)], env=env, cwd=store.home,
                                         pass_fds=(read_fd, lock_fd, tunnel_fd), stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            finally:
                env.clear()
        for name in ('control.sock', 'mcp.sock'):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(common.socket_path(store, name))
            os.chmod(common.socket_path(store, name), 0o600)
            listener.listen(8)
            listener.setblocking(False)
            listeners.append(listener)
            record(name)
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *a: stopped.set())
        while not stopped.is_set():
            if child is not None and child.poll() is not None:
                raise Refusal('transport_process_exited; remote_readiness_unverified')
            with selectors.DefaultSelector() as selector:
                for index, listener in enumerate(listeners):
                    selector.register(listener, selectors.EVENT_READ, index)
                for key, _ in selector.select(0.2):
                    connection, _ = key.fileobj.accept()
                    if key.data == 0:
                        connection.settimeout(1)
                        try:
                            data = bytearray()
                            while not data.endswith(b'\n') and len(data) <= 1024:
                                chunk = connection.recv(1025 - len(data))
                                if not chunk:
                                    break
                                data.extend(chunk)
                            query = json.loads(data) if data.endswith(b'\n') and len(data) <= 1024 else None
                            if query not in ({'action': 'status'}, {'action': 'stop'}):
                                reply = {'ok': False, 'error': 'invalid_control_request'}
                            else:
                                reply = {'ok': True, 'manager': 'running', 'node': node,
                                         'local_mcp': 'listener_running; probe_separately',
                                         'transport': 'local_stdio' if child is None else 'process_running; connection_unverified',
                                         'chatgpt_metadata': 'not_observed', 'end_to_end': 'not_observed',
                                         'active_sources': len(snapshot['approvals']['entries']),
                                         'active_transport': transport['kind'], 'active_revision': binding(snapshot)}
                                if query['action'] == 'stop':
                                    stopped.set()
                            connection.sendall(canonical(reply) + b'\n')
                        except (OSError, ValueError):
                            pass
                        finally:
                            connection.close()
                    else:
                        workers = [w for w in workers if w.is_alive()]
                        if len(workers) >= 4:
                            connection.close()
                            continue
                        process = subprocess.Popen([*argv(store, '_serve-active'), '--parent-fd', str(read_fd)],
                                                   env=environment(), cwd=store.home, pass_fds=(read_fd, lock_fd),
                                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                   start_new_session=True)
                        thread = threading.Thread(target=common.bridge, args=(connection, process, stopped), daemon=True)
                        thread.start()
                        workers.append(thread)
    except Refusal as error:
        store.state.write_file('last-error.json', {'code': error.code})
        return 2
    except Exception:
        store.state.write_file('last-error.json', {'code': 'manager_start_or_runtime_failed'})
        return 2
    finally:
        stopped.set()
        if write_fd is not None:
            os.close(write_fd)
        for listener in listeners:
            listener.close()
        try:
            common.kill_owned(child)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for worker in workers:
            worker.join(timeout=5)
        for name, inode in reversed(created):
            try:
                path = store.home / 'state' / name
                if os.lstat(path).st_ino == inode:
                    os.unlink(path)
            except OSError:
                pass
        for fd in (read_fd, tunnel_fd, lock_fd):
            if fd is not None:
                os.close(fd)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0
