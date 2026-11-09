"""Synthetic regression suite; optional isolated Git, never a production override."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT / p) for p in ('src', 'tests', 'scripts')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git', type=Path, help='Explicit modern Git for this test process only')
    parser.add_argument('--pattern', default='test_*.py')
    args = parser.parse_args()
    if args.git:
        info = args.git.stat()
        if not args.git.is_absolute() or not args.git.is_file() or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            parser.error('unsafe test Git executable')
        import observer.gitreader as reader
        import build_fixtures
        reader.GIT = reader.FIXED_ARGS[0] = build_fixtures.GIT = str(args.git)
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern=args.pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'tests': result.testsRun, 'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
                      'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
                      'python': sys.version.split()[0], 'platform': sys.platform, 'real_tunnel': False,
                      'real_credentials_or_sessions': False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
