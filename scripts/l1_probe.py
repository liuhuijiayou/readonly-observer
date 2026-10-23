"""Actual L1 acceptance through the official MCP ClientSession + stdio_client.

Only generated fixtures are deliberately rewritten. Proof contains no source
text, queries, random markers, command outputs, credentials or absolute roots.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import secrets
import sys
from unittest.mock import patch

PROJECT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "scripts"))

from mcp import ClientSession
import mcp.client.stdio as stdio_module
from mcp.client.stdio import StdioServerParameters, stdio_client

from build_fixtures import PRIVATE, SECRET, build, event, jsonl, metadata, snapshot, write
from observer.security import canonical, digest
from observer.service import SPECS


def require(condition, name):
    if not condition:
        raise RuntimeError("L1 assertion failed: " + name)


def inventory_summary(base):
    data = snapshot(base)
    selected = ["repo/tracked.txt", "repo/.git/index", "sessions/active/filename-is-not-the-id.jsonl",
                "untouched/state.sqlite", "untouched/state.sqlite-wal"]
    return {"entries": len(data), "inventory_sha256": digest(canonical(data)),
            "selected_source_hashes": {p: data[p]["sha256"] for p in selected}}


def source_manifest():
    paths = [p for directory in ("src", "tests", "scripts") for p in (PROJECT / directory).rglob("*.py")]
    paths.extend(PROJECT / name for name in ("pyproject.toml", "requirements.lock", "PUBLIC_FILES.txt", "MANIFEST.in") if (PROJECT / name).is_file())
    return {str(path.relative_to(PROJECT)): digest(path.read_bytes()) for path in sorted(paths)}


async def run():
    logging.disable(logging.CRITICAL)
    # L1 owns this resettable root. Repeated runs never append to the operator's
    # ordinary .local/fixtures sessions or accumulate synthetic source events.
    fixtures = build(PROJECT / ".local/l1-fixtures", reset=True)
    logs = PROJECT / ".local/verification/l1"
    logs.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stderr_path = logs / ("l1-" + run_id + "-server.stderr.log")
    config_path = fixtures / "observer-config.json"
    relative = str(fixtures.relative_to(PROJECT))
    config_path.write_text(json.dumps({"workspaces": {"project": ".", "fixture": relative + "/workspace", "fixture_git": relative + "/repo"},
                                      "sessions": {"synthetic": relative + "/sessions"}, "strict_hardlinks": True}))
    secret_filename = fixtures / "sessions/active" / ("token=" + SECRET + ".jsonl")
    jsonl(secret_filename, [metadata("synth-private-filename", fixtures / "repo"),
          event("response_item", {"type": "message", "role": "assistant", "channel": "analysis",
                "content": [{"type": "output_text", "text": PRIVATE}]}),
          event("response_item", {"type": "message", "role": "assistant", "channel": "internal",
                "content": [{"type": "output_text", "text": PRIVATE}]}),
          event("response_item", {"type": "message", "role": "assistant", "channel": "final",
                "content": [{"type": "output_text", "text": "public channel projection"}]}),
          event("event_msg", {"type": "turn_completed"})])
    marker_path = fixtures / "repo/l1-marker.txt"
    write(marker_path, "l1-" + secrets.token_hex(16) + "\n")
    phases, assertions, called = {}, {}, set()
    captured = []
    real_create = stdio_module._create_platform_compatible_process

    async def capture_process(**kwargs):
        process = await real_create(**kwargs)
        captured.append(process)
        return process

    params = StdioServerParameters(command=sys.executable,
                                   args=["-B", "-m", "observer.server", "--config", str(config_path.relative_to(PROJECT))], cwd=str(PROJECT),
                                   env={"PYTHONPATH": str(PROJECT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
                                        "TMPDIR": str(PROJECT / ".local/tmp")})
    async def call(session, name, args, ok=True):
        result = await session.call_tool(name, args)
        require(len(result.content) == 1 and result.content[0].type == "text", "single_json_envelope")
        raw = result.content[0].text
        require(len(raw.encode()) <= 32768, "response_cap")
        require(SECRET not in raw and PRIVATE not in raw, "no_synthetic_canaries")
        body = json.loads(raw)
        require(body.get("observed_content_untrusted") is True, "untrusted_label")
        require(body.get("ok") is ok and bool(result.isError) is not ok, "tool_outcome")
        token = body.get("next_cursor")
        if token:
            require(len(token) == 46 and token.startswith("c1_"), "fixed_size_opaque_cursor")
            for candidate in (token, token[3:]):
                try:
                    decoded = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
                except ValueError:
                    continue
                require(SECRET.encode() not in decoded and PRIVATE.encode() not in decoded,
                        "no_canary_in_decoded_cursor")
        called.add(name)
        return body

    before = inventory_summary(fixtures)
    implementation_before = source_manifest()
    with stderr_path.open("w") as errlog:
        with patch.object(stdio_module, "_create_platform_compatible_process", capture_process):
            async with stdio_client(params, errlog=errlog) as (read, output):
                async with ClientSession(read, output, read_timeout_seconds=timedelta(seconds=5)) as session:
                    initialized = await session.initialize()
                    tools = (await session.list_tools()).tools
                    names = {t.name for t in tools}
                    require(names == set(SPECS), "fixed_tool_surface")
                    require(all(t.annotations and t.annotations.readOnlyHint is True for t in tools), "readonly_annotations")
                    assertions.update({"initialize": True, "fixed_tool_surface": True, "all_readonly_annotations": True})
                    await call(session, "observer_info", {})
                    await call(session, "workspace_list", {"alias": "fixture_git", "limit": 2})
                    first = await call(session, "workspace_read", {"alias": "fixture_git", "path": "l1-marker.txt"})
                    first_text = first["lines"][0]["text"]
                    require(first_text == marker_path.read_text().strip(), "marker_first_read")
                    await call(session, "workspace_glob", {"aliases": ["fixture", "fixture_git"], "pattern": "**/*.txt"})
                    await call(session, "workspace_search", {"aliases": ["fixture", "fixture_git"], "query": "public"})
                    await call(session, "session_list", {"sources": ["synthetic"]})
                    initial_session = await call(session, "session_read", {"source": "synthetic", "session_id": "synth-main"})
                    require(initial_session["at_eof"], "initial_session_eof")
                    await call(session, "session_search", {"sources": ["synthetic"], "session_id": "synth-main", "query": "tests passed"})
                    private_page = await call(session, "session_read", {"source": "synthetic", "session_id": "synth-private-filename", "limit": 1})
                    require([item.get("text") for item in private_page["events"]] == ["public channel projection"], "internal_channels_not_projected")
                    require("REDACTED" in private_page["metadata"]["path"], "secret_filename_redacted")
                    private_matches = await call(session, "session_search", {"sources": ["synthetic"], "session_id": "synth-private-filename", "query": PRIVATE})
                    require(not private_matches["matches"], "internal_channels_not_searchable")
                    await call(session, "session_read", {"source": "synthetic", "session_id": "synth-private-filename", "cursor": private_page["next_cursor"]})
                    await call(session, "session_state", {"source": "synthetic", "session_id": "synth-private-filename"})
                    await call(session, "session_read", {"source": "synthetic", "session_id": "synth-main", "cursor": private_page["next_cursor"]}, ok=False)
                    await call(session, "session_state", {"source": "synthetic", "session_id": "synth-private-filename", "cursor": private_page["next_cursor"]}, ok=False)
                    assertions.update({"internal_channels_omitted_before_search": True, "secret_filename_redacted": True,
                                       "opaque_cursor_decoding_no_canary": True, "cursor_operation_and_session_binding": True})
                    state = await call(session, "session_state", {"source": "synthetic", "session_id": "synth-main"})
                    require(state["task_verified"] == "unknown", "turn_not_task_verification")
                    status = await call(session, "git_status", {"alias": "fixture_git"})
                    require(status["hidden_conflicts"] >= 1 and status["clean"] is False, "hidden_sensitive_conflict_preserved")
                    await call(session, "git_diff", {"alias": "fixture_git"})
                    await call(session, "git_history", {"alias": "fixture_git"})
                    evidence = await call(session, "evidence_link", {"source": "synthetic", "session_id": "synth-main", "alias": "fixture_git", "path": "tracked.txt"})
                    require(evidence["association"] == "exact_registered_cwd" and evidence["execution_source_link"] == "not_established", "honest_evidence_association")
                    denied = [
                        ("workspace_read", {"alias": "fixture", "path": "/outside/not-authorized"}),
                        ("workspace_read", {"alias": "fixture", "path": "../repo/tracked.txt"}),
                        ("workspace_read", {"alias": "fixture_git", "path": ".env.fixture"}),
                        ("workspace_list", {"alias": "project", "path": ".local"}),
                        ("workspace_read", {"alias": "missing", "path": "safe.txt"}),
                        ("observer_info", {"workspaces": {"new": "/outside/not-authorized"}}),
                        ("register_root", {"alias": "new", "path": "/outside/not-authorized"}),
                        ("git_status", {"alias": "fixture_git", "args": ["--exec-path=" + SECRET]}),
                        ("workspace_read", {"alias": {"password": SECRET}, "path": "safe.txt"}),
                        ("password=" + SECRET, {}),
                    ]
                    for name, args in denied:
                        await call(session, name, args, ok=False)
                    assertions["denied_absolute_traversal_sensitive_alias_config_and_invalid_inputs"] = True
                    after = inventory_summary(fixtures)
                    require(before == after, "zero_source_writes_initial")
                    phases["initial_observation"] = {"before": before, "after": after, "unchanged": True}

                    write(marker_path, "l1-" + secrets.token_hex(16) + "\n")
                    second_before = inventory_summary(fixtures)
                    second = await call(session, "workspace_read", {"alias": "fixture_git", "path": "l1-marker.txt"})
                    require(second["lines"][0]["text"] != first_text and second["source_sha256"] != first["source_sha256"], "marker_rewrite_reread")
                    require(second["lines"][0]["text"] == marker_path.read_text().strip(), "marker_second_read")
                    second_after = inventory_summary(fixtures)
                    require(second_before == second_after, "zero_source_writes_reread")
                    phases["after_operator_marker_rewrite"] = {"before": second_before, "after": second_after, "unchanged": True}
                    assertions["random_marker_read_rewrite_reread"] = True

                    session_path = fixtures / "sessions/active/filename-is-not-the-id.jsonl"
                    append_text = "l1-append-" + secrets.token_hex(12)
                    with session_path.open("ab") as stream:
                        stream.write((json.dumps(event("event_msg", {"type": "user_message", "message": append_text}, datetime.now(timezone.utc).isoformat())) + "\n").encode())
                    append_before = inventory_summary(fixtures)
                    delta = await call(session, "session_read", {"source": "synthetic", "session_id": "synth-main", "cursor": initial_session["next_cursor"]})
                    require(len(delta["events"]) == 1 and delta["events"][0].get("text") == append_text, "incremental_append_delta")
                    append_after = inventory_summary(fixtures)
                    require(append_before == append_after, "zero_source_writes_append_read")
                    phases["after_operator_session_append"] = {"before": append_before, "after": append_after, "unchanged": True}
                    assertions["incremental_append_delta"] = True
                    saved_session = session
                    protocol = initialized.protocolVersion
            # Official context exit closes stdin and waits for the real process.
            require(captured and captured[0].returncode is not None, "server_process_stopped")
            failed = False
            try:
                await asyncio.wait_for(saved_session.call_tool("workspace_read", {"alias": "fixture_git", "path": "l1-marker.txt"}), timeout=2)
            except Exception:
                failed = True
            require(failed, "read_fails_after_process_stop")
            assertions["read_fails_after_process_stop"] = True
    require(not (fixtures / "HELPER_EXECUTED").exists(), "no_git_helpers")
    require(before == phases["initial_observation"]["after"], "initial_inventory_preserved")
    implementation_after = source_manifest()
    require(implementation_before == implementation_after, "implementation_sources_unchanged")
    stderr = stderr_path.read_text()
    require(SECRET not in stderr and PRIVATE not in stderr, "stderr_no_canary")
    assertions.update({"no_git_helper_sentinel": True, "no_observer_source_writes": True,
                       "no_synthetic_secret_or_reasoning_canaries": True, "responses_bounded": True,
                       "implementation_sources_unchanged": True, "stderr_no_canary": True,
                       "all_core_tools_called": set(SPECS) <= called})
    require(assertions["all_core_tools_called"], "all_core_tools_called")
    proof = {"level": "L1", "status": "passed", "observed_at": datetime.now(timezone.utc).isoformat(),
             "transport": "official mcp 1.30.0 ClientSession + stdio_client",
             "protocolVersion": protocol, "tools": sorted(names), "assertions": assertions,
             "observed_sources": "project-generated fixtures only", "source_observation_windows": phases,
             "implementation_sha256_before": implementation_before, "implementation_sha256_after": implementation_after,
             "fixture_lifecycle": "dedicated_owned_root_reset_before_each_run",
             "sqlite_coverage": "unsupported; state.sqlite/WAL are inert placeholders, not valid SQLite proof",
             "intentional_test_mutations": ["fixture marker rewrite", "fixture JSONL append"],
             "atime": "excluded; bytes, inventory, modes, source mtime, Git index and placeholder DB/WAL included",
             "logs": {"server_stderr": str(stderr_path.relative_to(PROJECT)), "client": str((logs / ("l1-" + run_id + "-client.json")).relative_to(PROJECT))},
             "L2": "not_run", "L3": "not_run"}
    target = logs / ("l1-" + run_id + "-evidence.json")
    require(SECRET not in json.dumps(proof) and PRIVATE not in json.dumps(proof), "evidence_no_canary")
    target.write_text(json.dumps(proof, indent=2) + "\n")
    (logs / ("l1-" + run_id + "-client.json")).write_text(json.dumps({"status": "passed", "assertions": assertions}, indent=2) + "\n")
    print(json.dumps({"L1": "passed", "protocolVersion": protocol, "tools": len(names),
                      "assertions": len(assertions), "proof": str(target.relative_to(PROJECT)), "L2": "not_run", "L3": "not_run"}))


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except Exception:
        print('{"L1":"failed","error":"see_development_checks; raw input suppressed"}')
        raise SystemExit(1) from None
