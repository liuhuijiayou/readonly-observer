"""Independent regression for bounded redaction of adversarial public text."""

from pathlib import Path
import subprocess
import sys
import unittest

PROJECT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(PROJECT / 'src'))


class IndependentRedactionBudgetTests(unittest.TestCase):
    def test_repeated_jwt_prefixes_finish_or_refuse_within_budget(self):
        project = Path(__file__).absolute().parents[1]
        # This is synthetic public text, not a credential. Many JWT-looking
        # starts exposed quadratic rescanning in the original substitution.
        code = """
from observer.security import Redactor, Refusal
try:
    Redactor().text('eyJ-' * 40000)
except (Refusal, TimeoutError):
    pass
print('BOUNDED_REDACTION_OK')
"""
        env = {
            'PATH': '/usr/bin:/bin',
            'PYTHONPATH': str(project / 'src'),
            'PYTHONDONTWRITEBYTECODE': '1',
            'TMPDIR': str(project / '.local/tmp'),
        }
        try:
            child = subprocess.run(
                [sys.executable, '-B', '-c', code], cwd=project, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3, check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail('160KB adversarial redaction exceeded the bounded CPU window')
        self.assertEqual(child.returncode, 0, 'redaction must complete or refuse safely')
        self.assertEqual(child.stdout.strip(), b'BOUNDED_REDACTION_OK')

    def test_valid_urlsafe_jwt_edges_are_fully_redacted(self):
        from observer.security import Redactor
        redactor = Redactor()
        for suffix in ('abcdefghijk-', 'abcdefghijk_'):
            value = 'eyJabcdefgh.abcdefghi.' + suffix
            self.assertEqual(redactor.text(value), '[REDACTED JWT]')
        self.assertEqual(redactor.text('before eyJabcdefgh.abcdefghi.abcdefghijk- after'),
                         'before [REDACTED JWT] after')
