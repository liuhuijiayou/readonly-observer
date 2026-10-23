"""Shared budgets, redaction, opaque cursors, and generic error envelopes."""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import regex

MAX_JSON = 32 * 1024
MAX_SCAN = 4 * 1024 * 1024
MAX_RECORD = 256 * 1024
MAX_RESULTS = 50
MAX_LINES = 200
MAX_ENTRIES = 4000
SCAN_SECONDS = 1.0
MAX_INPUT_FRAME = 64 * 1024
CURSOR_TTL = 600
MAX_CURSORS = 256
MAX_CURSOR_BYTES = 4 * 1024 * 1024
MAX_CURSOR_STATE = 64 * 1024


class Refusal(Exception):
    """Only static, public codes may leave the process."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass
class Budget:
    remaining: int = MAX_SCAN
    deadline: float = field(default_factory=lambda: time.monotonic() + SCAN_SECONDS)
    entries: int = 0

    def check(self, size: int = 0, entries: int = 0) -> None:
        self.remaining -= size
        self.entries += entries
        if self.remaining < 0 or self.entries > MAX_ENTRIES:
            raise Refusal("scan_limit")
        if time.monotonic() > self.deadline:
            raise Refusal("scan_timeout")


class RedactedFragment(str):
    """Internal marker: whole logical text was redacted before this slice."""


class Redactor:
    """One pipeline for all public strings; not a complete secret detector."""

    def __init__(self, roots: dict[str, str] | None = None):
        self.roots = sorted((roots or {}).items(), key=lambda v: -len(v[0]))

    def text(self, value: str) -> str:
        # Match complete OR unterminated PEM blocks BEFORE any line slicing.
        value = re.sub(
            r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            lambda m: "[REDACTED PRIVATE KEY]" + "\n" * m.group(0).count("\n"), value,
        )
        # Quoted multiline assignments are logical values too. Redact them
        # whole before paging, preserving newline positions; an unterminated
        # value is withheld through EOF. Triple delimiters take precedence.
        prefix = (r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
                  r"client[_-]?secret|api[_-]?secret|secret[_-]?key|aws_secret_access_key|"
                  r"private[_-]?key|session[_-]?token|id[_-]?token|token|auth|password|passwd|"
                  r"secret|credential|authorization)\b[\"']?\s*[:=]\s*)")
        for delimiter in (chr(34) * 3, chr(39) * 3, chr(34), chr(39)):
            quoted = re.escape(delimiter)
            pattern = prefix + quoted + r"(?:\\[\s\S]|(?!" + quoted + r")[\s\S])*?(?:" + quoted + r"|\Z)"
            try:
                value = regex.sub(pattern, lambda m: m[1] + "[REDACTED]" + "\n" * m[0][len(m[1]):].count("\n"),
                                  value, timeout=0.05)
            except TimeoutError:
                raise Refusal("redaction_timeout") from None
        value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
                       lambda m: "Bearer [REDACTED]" + "\n" * m.group(0).count("\n"), value)
        value = re.sub(
            r'''(?ix)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|'''
            r'''client[_-]?secret|api[_-]?secret|secret[_-]?key|aws_secret_access_key|'''
            r'''private[_-]?key|session[_-]?token|id[_-]?token|token|auth|password|passwd|'''
            r'''secret|credential|authorization)\b'''
            r'''["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;}]+)''',
            r"\1[REDACTED]", value,
        )
        value = re.sub(
            r"\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}|"
            r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|"
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{30,})\b",
            "[REDACTED]", value,
        )
        try:
            # Repeated JWT-looking starts without separators can make an
            # unbounded backtracking substitution rescan the same suffixes.
            value = regex.sub(
                r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])",
                "[REDACTED JWT]", value, timeout=0.015,
            )
        except TimeoutError:
            raise Refusal("redaction_timeout") from None
        for root, alias in self.roots:
            value = value.replace(root, f"[root:{alias}]")
        # Common credential-bearing URLs, including in commands and errors.
        value = re.sub(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", value)
        return value

    def clean(self, value: Any) -> Any:
        if isinstance(value, RedactedFragment):
            return str(value)
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, dict):
            return {self.text(str(k)): self.clean(v) for k, v in value.items()}
        return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def binding(value: Any) -> str:
    return digest(canonical(value))


class Cursors:
    def __init__(self):
        # Only random capabilities cross the boundary. State, including source
        # names and call pairing, stays in this process and expires on restart.
        self._states = OrderedDict()
        self._bytes = 0

    def _discard_oldest(self):
        _, (_, _, _, raw) = self._states.popitem(last=False)
        self._bytes -= len(raw)

    def _expire(self):
        now = time.monotonic()
        while self._states and next(iter(self._states.values()))[0] <= now:
            self._discard_oldest()

    def issue(self, operation: str, filters: Any, state: dict) -> str:
        raw = canonical(state)
        if len(raw) > MAX_CURSOR_STATE:
            raise Refusal("cursor_limit")
        self._expire()
        while len(self._states) >= MAX_CURSORS or self._bytes + len(raw) > MAX_CURSOR_BYTES:
            self._discard_oldest()
        token = "c1_" + secrets.token_urlsafe(32)
        self._states[token] = (time.monotonic() + CURSOR_TTL, operation, binding(filters), raw)
        self._bytes += len(raw)
        return token

    def kind(self, token):
        """Routing hint from OUR bounded store, never from client token text.

        Callers must still use read() with the exact operation and filters.
        """
        self._expire()
        if not isinstance(token, str) or not re.fullmatch(r"c1_[A-Za-z0-9_-]{43}", token):
            raise Refusal("invalid_cursor")
        try:
            return self._states[token][1]
        except KeyError:
            raise Refusal("invalid_cursor") from None

    def read(self, token: str | None, operation: str, filters: Any) -> dict | None:
        if token is None:
            return None
        try:
            if not isinstance(token, str) or not re.fullmatch(r"c1_[A-Za-z0-9_-]{43}", token):
                raise ValueError
            self._expire()
            _, op, filter_hash, raw = self._states[token]
            if op != operation or filter_hash != binding(filters):
                raise ValueError
            # Decode a fresh copy so a refused/partial read cannot mutate an
            # earlier checkpoint. Total stored bytes and capability count cap RAM.
            return json.loads(raw)
        except (ValueError, KeyError, TypeError):
            raise Refusal("invalid_cursor") from None


def clip(text: str, size: int = 1800) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= size:
        return text, False
    return raw[:size].decode("utf-8", "ignore"), True


def text_window(value: str, start: int = 0, byte_limit: int = 6000):
    """Slice ONLY already-redacted logical text. Offsets count Unicode codepoints."""
    low, high = start, min(len(value), start + byte_limit)
    while low < high:
        middle = (low + high + 1) // 2
        if len(canonical(value[start:middle])) <= byte_limit:
            low = middle
        else:
            high = middle - 1
    return RedactedFragment(value[start:low]), low


def item_size(item: Any) -> int:
    return len(canonical(item))


class Matcher:
    def __init__(self, query: str, is_regex: bool, redactor: Redactor):
        # Never search raw content or raw secret queries.
        self.query = redactor.text(query)
        self.pattern = None
        if is_regex:
            try:
                self.pattern = regex.compile(self.query, regex.VERSION1)
            except regex.error:
                raise Refusal("invalid_regex") from None

    def matches(self, text: str) -> bool:
        if self.pattern is None:
            return self.query in text
        try:
            return self.pattern.search(text, timeout=0.015) is not None
        except TimeoutError:
            raise Refusal("regex_timeout") from None


def envelope(redactor: Redactor, data: dict) -> dict:
    result = redactor.clean({"observed_content_untrusted": True, **data})
    if item_size(result) > MAX_JSON - 512:
        return {"observed_content_untrusted": True, "ok": False, "error": "response_limit"}
    return result
