import base64
import unittest
from unittest.mock import patch

from support import SECRET
from observer.security import Cursors, Refusal


class CursorTests(unittest.TestCase):
    def test_state_is_not_encoded_in_capability_and_reads_are_independent(self):
        cursors = Cursors()
        state = {"filename": "token=" + SECRET + ".jsonl", "nested": {"offset": 1}}
        token = cursors.issue("operation", ["alias", "filter"], state)
        self.assertEqual(len(token), 46)
        decoded = base64.urlsafe_b64decode(token[3:] + "=")
        self.assertTrue(SECRET.encode() not in decoded, "cursor leaked state")
        self.assertTrue(b"filename" not in decoded, "cursor encoded source state")
        first = cursors.read(token, "operation", ["alias", "filter"])
        first["nested"]["offset"] = 999
        self.assertEqual(cursors.read(token, "operation", ["alias", "filter"])["nested"]["offset"], 1)
        for operation, filters in (("other", ["alias", "filter"]), ("operation", ["other", "filter"]),
                                   ("operation", ["alias", "different"])):
            with self.assertRaises(Refusal):
                cursors.read(token, operation, filters)
        with self.assertRaises(Refusal):
            Cursors().read(token, "operation", ["alias", "filter"])

    def test_retention_is_expiring_count_and_byte_bounded(self):
        now = [100.0]
        with patch("observer.security.time.monotonic", side_effect=lambda: now[0]), patch("observer.security.MAX_CURSORS", 2):
            cursors = Cursors()
            first = cursors.issue("op", [], {"offset": 0})
            cursors.issue("op", [], {"offset": 1})
            last = cursors.issue("op", [], {"offset": 2})
            with self.assertRaises(Refusal):
                cursors.read(first, "op", [])
            self.assertEqual(cursors.read(last, "op", [])["offset"], 2)
            now[0] += 601
            with self.assertRaises(Refusal):
                cursors.read(last, "op", [])
        with patch("observer.security.MAX_CURSOR_BYTES", 150):
            cursors = Cursors()
            first = cursors.issue("op", [], {"value": "x" * 80})
            cursors.issue("op", [], {"value": "x" * 80})
            with self.assertRaises(Refusal):
                cursors.read(first, "op", [])
            self.assertLessEqual(cursors._bytes, 150)
