"""Deterministic synthetic data only. No login, network, or live sessions.

Run from the project with .venv/bin/python scripts/build_fixtures.py.
Reset replaces ONLY a directory bearing this builder's ownership marker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

PROJECT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from observer.gitreader import GIT, safe_env  # noqa: E402

STAMP = "2026-10-22T00:00:00Z"
SECRET = "SYNTHETIC_" + "SECRET_CANARY_927451"
PRIVATE = "SYNTHETIC_" + "REASONING_CANARY_382199"
MARKER = ".observer-generated"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def event(kind, payload, stamp=STAMP):
    return {"timestamp": stamp, "type": kind, "payload": payload}


def metadata(sid, cwd, title="Synthetic fixture"):
    return event("session_meta", {"id": sid, "cwd": str(cwd), "title": title,
                                  "rollout_path": "/outside/not-authorized.jsonl",
                                  "environment": {"password": SECRET}})


def jsonl(path, records, tail=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join((json.dumps(r, separators=(",", ":")) + "\n").encode() for r in records) + tail)


def git(repo, *args, data=None):
    env = safe_env(repo)
    env.update({"GIT_AUTHOR_DATE": STAMP, "GIT_COMMITTER_DATE": STAMP})
    result = subprocess.run([GIT, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                            cwd=repo, env=env, input=data, capture_output=True, timeout=5, check=False)
    if result.returncode:
        raise RuntimeError("synthetic_git_build_failed")
    return result.stdout


def init_repo(repo, dirty):
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "--initial-branch=main")
    git(repo, "config", "user.name", "Synthetic Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    write(repo / "tracked.txt", "baseline\n")
    write(repo / ".gitignore", "ignored.txt\n")
    write(repo / ".gitattributes", "tracked.txt diff=sentinel filter=sentinel\n")
    if dirty:
        write(repo / ".env.fixture", "password=" + SECRET + "\n")
    git(repo, "add", "--all")
    git(repo, "commit", "-m", "Initial synthetic fixture")
    if not dirty:
        return
    write(repo / "tracked.txt", "changed public source\npassword=" + SECRET + "\n")
    write(repo / "untracked.txt", "safe untracked source\n")
    write(repo / "ignored.txt", "safe ignored source\n")
    write(repo / "tokenization.py", "# legitimate public source name\n")
    stages = []
    for number in (1, 2, 3):
        sha = git(repo, "hash-object", "-w", "--stdin", data=f"password={SECRET}_{number}\n".encode()).strip()
        stages.append(b"100644 " + sha + f" {number}\t.env.fixture\n".encode())
    git(repo, "update-index", "--index-info", data=b"0 " + b"0" * 40 + b"\t.env.fixture\n" + b"".join(stages))
    # Inject only after all mutating setup commands. These scripts are never run.
    sentinel = repo.parent / "HELPER_EXECUTED"
    helper = repo / "helper-fixture.sh"
    command = "#!/bin/sh\nprintf forbidden > " + shlex.quote(str(sentinel)) + "\n"
    write(helper, command)
    helper.chmod(0o700)
    for name in ("post-index-change", "pre-auto-gc", "fsmonitor-watchman"):
        hook = repo / ".git/hooks" / name
        write(hook, command)
        hook.chmod(0o700)
    with (repo / ".git/config").open("a") as stream:
        stream.write(
            '\n[core]\n\tfsmonitor = "' + str(helper) + '"\n'
            '\thooksPath = "' + str(repo / ".git/hooks") + '"\n'
            '\tpager = "' + str(helper) + '"\n'
            '[diff]\n\texternal = "' + str(helper) + '"\n'
            '[diff "sentinel"]\n\tcommand = "' + str(helper) + '"\n'
            '\ttextconv = "' + str(helper) + '"\n'
            '[filter "sentinel"]\n\tclean = "' + str(helper) + '"\n'
            '\tsmudge = "' + str(helper) + '"\n'
            '[credential]\n\thelper = "!' + str(helper) + '"\n'
            '[alias]\n\tstatus = "!' + str(helper) + '"\n'
        )


def build(base=PROJECT / ".local/fixtures", reset=False):
    base = Path(base)
    # Lexical rejection must precede every filesystem check, mkdir or reset.
    if ".." in base.parts:
        raise RuntimeError("fixture_parent_traversal_denied")
    base = base.absolute()
    if not base.is_relative_to(PROJECT / ".local") or base == PROJECT / ".local":
        raise RuntimeError("fixture_destination_must_be_project_local")
    # Refuse symlink ancestors and unowned existing content.
    for parent in (base, *base.parents):
        if parent == PROJECT:
            break
        if parent.is_symlink():
            raise RuntimeError("unsafe_fixture_destination")
    if base.exists() and any(base.iterdir()):
        if (base / MARKER).is_symlink() or not (base / MARKER).is_file():
            raise RuntimeError("fixture_destination_not_owned")
        if not reset:
            return base
        shutil.rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    write(base / MARKER, "observer synthetic fixture v1\n")
    workspace = base / "workspace"
    write(workspace / "safe.txt", "public first line\npublic second line\npublic third line\n")
    write(workspace / "sub/readme.md", "public nested source\n")
    write(workspace / "tokenization.py", "# public tokenization module\n")
    write(workspace / "public-secret.txt", "safe\npassword=" + SECRET + "\n-----BEGIN PRIVATE KEY-----\n" + SECRET + "\n-----END PRIVATE KEY-----\nsafe end\n")
    write(workspace / ".env", "password=" + SECRET + "\n")
    write(workspace / "auth.json", json.dumps({"access_token": SECRET}))
    write(workspace / ".local/credentials/private.log", PRIVATE)
    write(base / "untouched/state.sqlite", "synthetic database placeholder\n")
    write(base / "untouched/state.sqlite-wal", "synthetic WAL placeholder\n")
    init_repo(base / "repo", True)
    init_repo(base / "clean_repo", False)
    sessions = base / "sessions"
    main = [
        metadata("synth-main", base / "repo", "Fixture password=" + SECRET),
        event("event_msg", {"type": "task_started", "turn_id": "turn-one"}),
        event("event_msg", {"type": "user_message", "message": "Inspect the public synthetic source"}),
        event("response_item", {"type": "reasoning", "summary": PRIVATE}),
        event("event_msg", {"type": "agent_reasoning", "text": PRIVATE}),
        event("unknown_future_event", {"text": PRIVATE, "environment": {"password": SECRET}}),
        event("response_item", {"type": "function_call", "name": "exec_command", "call_id": "call-1",
                                "arguments": json.dumps({"cmd": "python -m unittest password=" + SECRET, "env": {"private": PRIVATE}})}),
        event("response_item", {"type": "function_call_output", "call_id": "call-1",
                                "output": "Process exited with code 0\npassword=" + SECRET + "\nsynthetic tests passed"}),
        event("response_item", {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "I claim the task is complete"}]}),
        event("event_msg", {"type": "task_complete"}),
    ]
    jsonl(sessions / "active/filename-is-not-the-id.jsonl", main)
    jsonl(sessions / "archived/old.jsonl", [metadata("synth-archive", base / "repo"), event("event_msg", {"type": "turn_aborted"})])
    jsonl(sessions / "active/unknown.jsonl", [metadata("synth-unknown", base / "repo"), event("event_msg", {"type": "agent_message", "message": "completed all tasks"})])
    jsonl(sessions / "active/blocked.jsonl", [metadata("synth-blocked", base / "repo"), event("event_msg", {"type": "turn_blocked"})])
    jsonl(sessions / "active/partial.jsonl", [metadata("synth-partial", base / "repo"), event("event_msg", {"type": "user_message", "message": "complete event before pending tail"})], b'{"type":"event_msg","payload":')
    variants = base / "session_variants"
    jsonl(variants / "malformed.jsonl", [metadata("synth-malformed", base / "repo")], b"{complete malformed}\n")
    jsonl(variants / "oversize.jsonl", [metadata("synth-oversize", base / "repo")], b"x" * (256 * 1024 + 1) + b"\n")
    return base


def snapshot(base):
    """Source inventory/bytes/mtime hash; atime intentionally excluded."""
    result = {}
    for path in sorted(Path(base).rglob("*")):
        st = path.lstat()
        name = str(path.relative_to(base))
        if path.is_symlink():
            result[name] = {"kind": "symlink", "target": os.readlink(path)}
        elif path.is_file():
            result[name] = {"kind": "file", "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                            "mode": st.st_mode, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        else:
            result[name] = {"kind": "directory", "mode": st.st_mode, "mtime_ns": st.st_mtime_ns}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    result = build(reset=args.reset)
    print(json.dumps({"ok": True, "fixture_root": ".local/fixtures", "inventory_entries": len(snapshot(result)),
                      "helper_sentinel_absent": not (result / "HELPER_EXECUTED").exists()}))
