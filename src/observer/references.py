"""Exact references only. URLs never become filesystem paths."""
from urllib.parse import urlsplit
import re
from .security import Refusal

ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

def parse_reference(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise Refusal("invalid_session_reference")
    if ID.fullmatch(value):
        return ("cloud", value) if value.startswith("task_") else ("local", value)
    try:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
            raise ValueError
        if parsed.scheme == "codex" and parsed.netloc == "threads":
            sid = parsed.path.removeprefix("/")
            if UUID.fullmatch(sid):
                return "local", sid
        if parsed.scheme == "https" and parsed.netloc == "chatgpt.com":
            match = re.fullmatch(r"/codex/tasks/([A-Za-z0-9_-]{1,128})", parsed.path)
            if match:
                return "cloud", "https://chatgpt.com/codex/tasks/" + match[1]
    except (ValueError, TypeError):
        pass
    raise Refusal("invalid_session_reference")
