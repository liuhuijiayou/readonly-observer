"""Instance-local Unix sockets. Only this manager owns and stops its children."""
from contextlib import ExitStack
import fcntl
import json
import os
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

from .profile import Store
from .fs import Root
from .security import Refusal, binding, canonical

def environment():
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}

def argv(store, command):
    # The code location comes from our installed package, never observed code.
    from pathlib import Path
    package_parent = str(Path(__file__).absolute().parents[1])
    bootstrap = "import sys;sys.path.insert(0," + repr(package_parent) + ");from observer.cli import main;raise SystemExit(main())"
    return [sys.executable, "-I", "-B", "-c", bootstrap, "--home", str(store.home), command]

def socket_path(store, name):
    path = str(store.home / "state" / name)
    if len(path.encode()) > 100:
        raise Refusal("instance_path_too_long_for_unix_socket; use_a_shorter_private_home")
    return path

def endpoint(store, name):
    path = str(store.home / "state" / name)
    st = os.lstat(path)
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Refusal("unsafe_control_socket")
    return socket_path(store, name)

def request(store, action):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(endpoint(store, "control.sock"))
        connection.sendall(canonical({"action": action}) + b"\n")
        buffer = bytearray()
        while not buffer.endswith(b"\n") and len(buffer) <= 16384:
            chunk = connection.recv(16385 - len(buffer))
            if not chunk:
                break
            buffer.extend(chunk)
        if len(buffer) > 16384 or not buffer.endswith(b"\n"):
            raise Refusal("invalid_control_reply")
        return json.loads(buffer)

def locked(store):
    with store.state.directory() as directory:
        fd = os.open("manager.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            store.state.regular(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            return False
        finally:
            os.close(fd)

def status(store):
    store.require()
    try:
        result = request(store, "status")
        active = store.state.read_file("active.json")
        result["configuration_pending"] = active != store.snapshot()
        return result
    except (FileNotFoundError, ConnectionError, socket.timeout):
        return {"manager": "unreachable_lock_held" if locked(store) else "not_running",
                "local_mcp": "not_observed", "transport": "not_observed",
                "chatgpt_metadata": "not_observed", "end_to_end": "not_observed",
                "other_processes": "not_inspected_or_stopped"}

def start(store):
    store.require()
    before = status(store)
    if before["manager"] == "running":
        return {**before, "action": "already_started"}
    if before["manager"] != "not_running":
        raise Refusal("existing_manager_unreachable; no_takeover_or_PID_kill")
    socket_path(store, "control.sock")
    socket_path(store, "mcp.sock")
    child = subprocess.Popen(argv(store, "_manager"), env=environment(), cwd=store.home,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True, start_new_session=True)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            failure = store.state.read_file("last-error.json", {"code": "manager_start_failed"})
            raise Refusal(failure["code"])
        try:
            result = request(store, "status")
            threading.Thread(target=child.wait, daemon=True).start()
            return {**result, "action": "started", "ready": False,
                    "note": "local process only; remote metadata and end-to-end must be verified separately"}
        except (FileNotFoundError, ConnectionError, socket.timeout):
            time.sleep(0.05)
    # Only the Popen object we just created can be terminated here.
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)
    raise Refusal("manager_start_timeout")

def stop(store):
    store.require()
    before = status(store)
    if before["manager"] == "not_running":
        return {"action": "already_stopped", "other_processes": "not_inspected_or_stopped"}
    if before["manager"] != "running":
        raise Refusal("manager_unreachable; no_PID_kill_or_lock_deletion")
    result = request(store, "stop")
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if not locked(store):
            return {**result, "action": "owned_instance_stopped", "other_processes": "not_inspected_or_stopped"}
        time.sleep(0.05)
    raise Refusal("owned_instance_stop_timeout; outcome_uncertain")

def kill_owned(child):
    if child is None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=2)

def client_config(store, tunnel):
    command = shlex.join(["/usr/bin/env", "-i", *argv(store, "_serve-active")])
    return {"config_version": 1,
            "control_plane": {"base_url": "https://api.openai.com", "tunnel_id": tunnel["tunnel_id"],
                              "api_key": "env:CONTROL_PLANE_API_KEY"},
            "mcp": {"commands": [{"channel": "main", "command": command}], "max_concurrent_requests": 1},
            "health": {"listen_addr": "127.0.0.1:0", "url_file": str(store.home / "state/health.url")},
            "admin_ui": {"open_browser": False}, "cloudflared": {"managed": False},
            "log": {"level": "warn", "format": "json", "file": "/dev/null"}}

def check_binary(filename):
    from pathlib import Path
    path = Path(filename)
    root = Root("transport", str(path.parent), workspace=False)
    try:
        fd = root.file(path.name)
        try:
            st = os.fstat(fd)
            if st.st_uid != os.getuid() or st.st_mode & 0o022 or not st.st_mode & 0o111:
                raise Refusal("unsafe_transport_binary")
        finally:
            os.close(fd)
    finally:
        root.close()

def bridge(connection, child, stopped):
    """Bounded relay only; MCP parser and input-frame limit stay in the child."""
    for fd in (connection.fileno(), child.stdin.fileno(), child.stdout.fileno()):
        os.set_blocking(fd, False)
    to_child, to_client = bytearray(), bytearray()
    client_eof, child_eof, stdin_closed = False, False, False
    try:
        while not stopped.is_set():
            if client_eof and not to_child and not stdin_closed:
                child.stdin.close()
                stdin_closed = True
            if child_eof and not to_client:
                break
            with selectors.DefaultSelector() as selector:
                client_events = (selectors.EVENT_READ if not client_eof and len(to_child) < 131072 else 0) | (selectors.EVENT_WRITE if to_client else 0)
                if client_events:
                    selector.register(connection, client_events, "client")
                if to_child and not stdin_closed:
                    selector.register(child.stdin, selectors.EVENT_WRITE, "stdin")
                if not child_eof and len(to_client) < 131072:
                    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                for key, mask in selector.select(0.1):
                    if key.data == "client":
                        if mask & selectors.EVENT_READ:
                            data = connection.recv(65536)
                            if data:
                                to_child.extend(data)
                            else:
                                client_eof = True
                        if mask & selectors.EVENT_WRITE:
                            del to_client[:connection.send(to_client)]
                    elif key.data == "stdin":
                        del to_child[:os.write(child.stdin.fileno(), to_child)]
                    else:
                        data = os.read(child.stdout.fileno(), 65536)
                        if data:
                            to_client.extend(data)
                        else:
                            child_eof = True
    except (OSError, ValueError):
        pass
    finally:
        connection.close()
        kill_owned(child)
        if not stdin_closed:
            child.stdin.close()
        child.stdout.close()

def manage(store):
    store.require()
    child, listeners, workers, previous = None, [], [], {}
    stopped = threading.Event()
    lock_fd = None
    created = []
    try:
        with store.state.directory() as directory:
            lock_fd = os.open("manager.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        store.state.regular(lock_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal("manager_already_running") from None
        with store.mutation():
            snapshot = store.snapshot()
            config = store.configuration()
            config.close()
        # Never replace stale sockets or active files automatically.
        for name in ("control.sock", "mcp.sock", "active.json", "transport.json"):
            if os.path.lexists(store.home / "state" / name):
                raise Refusal("stale_runtime_requires_explicit_local_review")
        store.state.write_file("active.json", snapshot)
        created.append(("active.json", os.lstat(store.home / "state/active.json").st_ino))
        transport = snapshot["settings"]["transport"]
        if transport["kind"] == "tunnel":
            check_binary(transport["client"])
            store.state.write_file("transport.json", client_config(store, transport))
            created.append(("transport.json", os.lstat(store.home / "state/transport.json").st_ino))
            env = environment()
            env.update({"TMPDIR": str(store.home / "cache"), "XDG_CONFIG_HOME": str(store.home / "config"),
                        "XDG_CACHE_HOME": str(store.home / "cache"), "XDG_DATA_HOME": str(store.home / "cache"),
                        "XDG_RUNTIME_DIR": str(store.home / "state")})
            try:
                env["CONTROL_PLANE_API_KEY"] = store.keychain().get()
                command = [transport["client"], "run", "--config", str(store.home / "state/transport.json"),
                           "--log.http-raw-unsafe=false", "--allow-remote-ui=false", "--open-web-ui=false"]
                child = subprocess.Popen(command, env=env, cwd=store.home, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         close_fds=True, start_new_session=True)
            finally:
                env.clear()
        for name in ("control.sock", "mcp.sock"):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path(store, name))
            os.chmod(socket_path(store, name), 0o600)
            listener.listen(8)
            listener.setblocking(False)
            listeners.append(listener)
            created.append((name, os.lstat(socket_path(store, name)).st_ino))
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *a: stopped.set())
        while not stopped.is_set():
            if child is not None and child.poll() is not None:
                raise Refusal("transport_process_exited; remote_readiness_unverified")
            with selectors.DefaultSelector() as selector:
                for index, listener in enumerate(listeners):
                    selector.register(listener, selectors.EVENT_READ, index)
                for key, _ in selector.select(0.2):
                    connection, _ = key.fileobj.accept()
                    if key.data == 0:
                        connection.settimeout(1)
                        try:
                            data = bytearray()
                            while not data.endswith(b"\n") and len(data) <= 1024:
                                chunk = connection.recv(1025 - len(data))
                                if not chunk:
                                    break
                                data.extend(chunk)
                            query = json.loads(data) if data.endswith(b"\n") and len(data) <= 1024 else None
                            if query not in ({"action": "status"}, {"action": "stop"}):
                                reply = {"ok": False, "error": "invalid_control_request"}
                            else:
                                reply = {"ok": True, "manager": "running", "local_mcp": "listener_running; probe_separately",
                                         "transport": "local_stdio" if child is None else "process_running; connection_unverified",
                                         "chatgpt_metadata": "not_observed", "end_to_end": "not_observed",
                                         "active_sources": len(snapshot["approvals"]["entries"]),
                                         "active_transport": transport["kind"],
                                         "active_revision": binding(snapshot)}
                                if query["action"] == "stop":
                                    stopped.set()
                            connection.sendall(canonical(reply) + b"\n")
                        except (OSError, ValueError):
                            pass
                        finally:
                            connection.close()
                    else:
                        if sum(t.is_alive() for t in workers) >= 4:
                            connection.close()
                            continue
                        process = subprocess.Popen(argv(store, "_serve-active"), env=environment(), cwd=store.home,
                                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                   close_fds=True, start_new_session=True)
                        thread = threading.Thread(target=bridge, args=(connection, process, stopped), daemon=True)
                        thread.start()
                        workers.append(thread)
    except Refusal as error:
        store.state.write_file("last-error.json", {"code": error.code})
        return 2
    except Exception:
        store.state.write_file("last-error.json", {"code": "manager_start_or_runtime_failed"})
        return 2
    finally:
        stopped.set()
        for listener in listeners:
            listener.close()
        try:
            kill_owned(child)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for worker in workers:
            worker.join(timeout=5)
        for name, inode in reversed(created):
            path = store.home / "state" / name
            try:
                if os.lstat(path).st_ino == inode:
                    os.unlink(path)
            except OSError:
                pass
        if lock_fd is not None:
            os.close(lock_fd)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0

def connect(store):
    store.require()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(endpoint(store, "mcp.sock"))
        def input_pump():
            try:
                while True:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if not data:
                        break
                    connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        threading.Thread(target=input_pump, daemon=True).start()
        while True:
            data = connection.recv(65536)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    return 0
