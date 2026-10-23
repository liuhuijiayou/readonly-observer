"""Security regressions through the installed official stdio client/server."""

import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import timedelta
import json
import logging
import sys

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import McpError
from pydantic import BaseModel

from support import PROJECT, ObserverCase, PRIVATE, SECRET, event, jsonl, metadata
from observer.security import MAX_INPUT_FRAME


class WireRequest(BaseModel):
    # Deliberately malformed tool parameters, serialized by ClientSession.
    method: str = "tools/call"
    params: dict


class MCPWireTests(ObserverCase):
    @asynccontextmanager
    async def client(self):
        logging.disable(logging.CRITICAL)
        path = self.extra / "stdio-config.json"
        path.write_text(json.dumps(self.values))
        params = StdioServerParameters(command=sys.executable,
                                      args=["-B", "-m", "observer.server", "--config", str(path.relative_to(PROJECT))],
                                      cwd=str(PROJECT), env={"PYTHONPATH": str(PROJECT / "src"), "PYTHONDONTWRITEBYTECODE": "1"})
        log = self.extra / "transport.stderr.log"
        with log.open("w") as errors:
            async with stdio_client(params, errlog=errors) as (read, output):
                async with ClientSession(read, output, read_timeout_seconds=timedelta(seconds=5)) as client:
                    await client.initialize()
                    yield client
        self.secret_free(log.read_text())

    async def checked_call(self, client, name, args):
        result = await client.call_tool(name, args)
        self.secret_free(result.model_dump(mode="json"))
        self.assertFalse(result.isError, "official MCP call failed")
        body = json.loads(result.content[0].text)
        self.assertTrue(body["ok"])
        self.assertLessEqual(len(result.content[0].text.encode()), 32768)
        token = body.get("next_cursor")
        if token:
            self.assertEqual(len(token), 46)
            # Try both the whole handle and its random component. Neither may
            # contain recoverable source data, even when the filename is secret.
            for candidate in (token, token[3:]):
                try:
                    decoded = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
                except ValueError:
                    continue
                self.assertTrue(SECRET.encode() not in decoded and PRIVATE.encode() not in decoded,
                                "cursor decoding exposed a canary")
        return body

    def test_internal_channel_and_secret_filename_opaque_cursor_full_mcp(self):
        records = [metadata("wire", self.extra, "token=" + SECRET)]
        for channel in ("analysis", "reasoning", "internal", "future_private"):
            records.append(event("response_item", {"type": "message", "role": "assistant", "channel": channel,
                           "content": [{"type": "output_text", "text": PRIVATE}]}))
        records.extend([event("response_item", {"type": "message", "role": "assistant", "channel": "final",
                        "content": [{"type": "output_text", "text": "public response"}]}),
                        event("event_msg", {"type": "turn_completed"})])
        jsonl(self.extra / ("token=" + SECRET + ".jsonl"), records)

        async def exercise():
            async with self.client() as client:
                listed = await self.checked_call(client, "session_list", {"sources": ["cases"]})
                self.assertIn("REDACTED", listed["sessions"][0]["path"])
                first = await self.checked_call(client, "session_read", {"source": "cases", "session_id": "wire", "limit": 1})
                self.assertEqual([item["text"] for item in first["events"]], ["public response"])
                await self.checked_call(client, "session_read", {"source": "cases", "session_id": "wire", "cursor": first["next_cursor"]})
                hidden = await self.checked_call(client, "session_search", {"sources": ["cases"], "query": PRIVATE})
                self.assertEqual(hidden["matches"], [])
                found = await self.checked_call(client, "session_search", {"sources": ["cases"], "query": ".*", "regex": True, "limit": 1})
                self.assertTrue(found["next_cursor"])
                state = await self.checked_call(client, "session_state", {"source": "cases", "session_id": "wire"})
                self.assertEqual(state["state"], "explicit_terminal_turn")
                self.assertEqual(state["task_verified"], "unknown")
        asyncio.run(exercise())

    def test_single_file_session_scope_hides_sibling_added_after_server_start(self):
        root = self.extra / "single-session-source"
        root.mkdir()
        jsonl(root / "authorized.jsonl", [
            metadata("authorized-session", self.extra),
            event("event_msg", {"type": "user_message", "message": "authorized public acceptance"}),
        ])
        self.values["sessions"]["exact"] = str(root)
        self.values["session_files"] = {"exact": {
            "path": "authorized.jsonl", "session_id": "authorized-session"}}

        async def exercise():
            async with self.client() as client:
                initial = await self.checked_call(client, "session_list", {"sources": ["exact"]})
                self.assertEqual([item["session_id"] for item in initial["sessions"]], ["authorized-session"])
                jsonl(root / "new-sibling.jsonl", [
                    metadata("unapproved-sibling", self.extra, title="SIBLING_NOT_AUTHORIZED_7129"),
                    event("event_msg", {"type": "assistant_message", "message": "SIBLING_CANARY_7129"}),
                ])

                listed = await self.checked_call(client, "session_list", {"sources": ["exact"]})
                self.assertEqual([item["session_id"] for item in listed["sessions"]], ["authorized-session"])
                read = await self.checked_call(client, "session_read", {
                    "source": "exact", "session_id": "authorized-session"})
                self.assertEqual([item["text"] for item in read["events"]], ["authorized public acceptance"])

                missing = await client.call_tool("session_read", {
                    "source": "exact", "session_id": "unapproved-sibling"})
                missing_body = json.loads(missing.content[0].text)
                self.assertEqual(missing_body.get("error"), "session_not_found")
                self.secret_free(missing.model_dump(mode="json"))

                hidden = await self.checked_call(client, "session_search", {
                    "sources": ["exact"], "query": "SIBLING_CANARY_7129"})
                self.assertEqual(hidden["matches"], [])
                self.assertIsNone(hidden["next_cursor"])

        asyncio.run(exercise())

    def test_malformed_mcp_argument_wire_does_not_echo_any_token_case(self):
        async def exercise():
            async with self.client() as client:
                for text in ("token=" + SECRET, json.dumps({"token": SECRET}), "AWS_SECRET_ACCESS_KEY=" + SECRET):
                    try:
                        await client.send_request(WireRequest(params={"name": "workspace_read", "arguments": [text]}), types.CallToolResult)
                    except McpError as exc:
                        self.assertEqual(exc.error.code, -32602)
                        self.secret_free(exc.error.model_dump(mode="json"))
                    else:
                        self.fail("malformed wire arguments were accepted")
                    result = await client.call_tool("workspace_read", {"alias": {"invalid": text}, "path": "safe.txt"})
                    self.assertTrue(result.isError)
                    self.secret_free(result.model_dump(mode="json"))
        asyncio.run(exercise())

    def test_oversized_input_frame_closes_transport_without_canary_echo(self):
        async def exercise():
            async with self.client() as client:
                try:
                    await asyncio.wait_for(client.call_tool("observer_info", {"padding": "x" * MAX_INPUT_FRAME + " token=" + SECRET}), timeout=5)
                except McpError as exc:
                    self.assertNotEqual(exc.error.code, 408, "transport waited instead of bounding the frame")
                    self.secret_free(exc.error.model_dump(mode="json"))
                else:
                    self.fail("oversized frame was accepted")
        asyncio.run(exercise())


    def test_complete_workspace_and_tool_output_pages_through_official_mcp(self):
        from build_fixtures import write
        value = "开源代码" * 4000 + " password=" + SECRET
        write(self.extra / "long-public.py", value + "\n")
        jsonl(self.extra / "full-wire.jsonl", [metadata("full-wire", self.extra),
              event("response_item", {"type": "function_call", "name": "exec_command", "call_id": "wire-full", "arguments": json.dumps({"cmd": "synthetic"})}),
              event("response_item", {"type": "function_call_output", "call_id": "wire-full", "output": {"exit_code": 0, "output": value}})])
        expected = self.observer.redactor.text(value)
        async def exercise():
            async with self.client() as client:
                tools = await client.list_tools()
                self.assertEqual(len(tools.tools), 13)
                self.assertTrue(all(t.annotations.readOnlyHint for t in tools.tools))
                parts, cursor = [], None
                for _ in range(100):
                    args = {"alias": "other", "path": "long-public.py"}
                    if cursor:
                        args["cursor"] = cursor
                    page = await self.checked_call(client, "workspace_read", args)
                    parts.extend(i["text"] for i in page["lines"])
                    cursor = page["next_cursor"]
                    if not cursor:
                        break
                self.assertIsNone(cursor)
                self.assertEqual("".join(parts), expected)
                preview = await self.checked_call(client, "session_read", {"source": "cases", "session_id": "full-wire"})
                item = next(e for e in preview["events"] if e.get("phase") == "result")
                parts, cursor = [], None
                for _ in range(100):
                    args = {"source": "cases", "session_id": "full-wire", "field": "output", "detail_cursor": item["detail_cursor"]}
                    if cursor:
                        args["cursor"] = cursor
                    page = await self.checked_call(client, "session_read", args)
                    parts.append(page["content"])
                    cursor = page["next_cursor"]
                    if not cursor:
                        break
                self.assertIsNone(cursor)
                self.assertEqual("".join(parts), expected)
                parts, cursor = [], item["content_cursors"]["output"]
                while cursor:
                    args = {"source": "cases", "session_id": "full-wire", "limit": 50, "cursor": cursor}
                    self.assertEqual(set(args), {"source", "session_id", "limit", "cursor"})
                    page = await self.checked_call(client, "session_read", args)
                    self.assertEqual(page["mode"], "field_content")
                    parts.append(page["content"])
                    cursor = page["next_cursor"]
                self.assertGreater(len(parts), 1)
                self.assertEqual("".join(parts), expected)
        asyncio.run(exercise())
