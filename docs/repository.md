# Development and contributing

Start with [English README](../README.md) or [中文 README](../README.zh-CN.md). The runtime uses one CLI implementation in `src/observer/cli.py`; `Observer.command` is an optional thin menu launcher. See the [architecture](product-design.md), [CLI/MCP reference](config-reference.md) and [security boundary](../SECURITY.md) before changing behavior.

## Set up and verify

Use the documented macOS / Python 3.14 target with Git installed. From a reviewed source tree:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -I -B scripts/check_repository.py
.venv/bin/python -I -B -m unittest discover -s tests -q
.venv/bin/python -I -B scripts/l1_probe.py
```

Tests create isolated synthetic repositories and sessions under `.local/`; they do not need real session history, Keychain values, tunnels or ChatGPT. The SDK probe writes timestamped evidence under `.local/verification/l1/`. Do not register personal sources just to run the suite. A passing local suite is not evidence of remote connectivity or support on another platform.

## Build and check artifacts

```sh
.venv/bin/python -m pip install 'build==1.2.2.post1' 'setuptools==80.9.0'
.venv/bin/python -I -B -m build --no-isolation
.venv/bin/python -I -B scripts/check_release.py \
  dist/local_readonly_observer-0.3.3-py3-none-any.whl \
  dist/local_readonly_observer-0.3.3.tar.gz
```

These names correspond to the current `pyproject.toml` version. For clean-package verification, extract the source archive into a new directory and repeat the tests in a fresh environment. Verify an installed wheel through MCP independently of development source paths. Keep implementation, synthetic tests, installed-package checks, deployed versions and remote checks as separate claims.

## Reviewed files and clean exports

`PUBLIC_FILES.txt` is the reviewed inventory. `.gitignore` and `MANIFEST.in` must match it. `scripts/check_repository.py` checks allowlisted files and bounded private-data patterns, and can export them to a new directory:

```sh
.venv/bin/python -I -B scripts/check_repository.py --export /absolute/path/to/new-reviewed-source
```

The destination must not exist; its parent must already exist. Symlinks, multiply linked files and existing output are refused. A failed export preserves partial output for review, rather than deleting it. It never copies `.local`, `.git`, environments or instance configuration. `scripts/check_release.py` separately checks archive members.

New files remain ignored until intentionally reviewed and added to all applicable inventories. Update `PUBLIC_FILES.txt`, `.gitignore` and `MANIFEST.in` together, and update the applicable hard-coded `TOP` / `DOCS` filename allowlists in `scripts/check_release.py`; the three inventories alone do not make a new LICENSE, document or other file acceptable to packaging checks. A passing pattern scan is not a confidentiality, ownership, license or security certification. Do not publish the working directory wholesale or force-add ignored files; inspect the exact Git index and history. Ignore rules do not scrub existing commits.

## Preparing a change

- Keep changes focused and add synthetic regression coverage for changed behavior.
- Preserve local-only approval, exact-session scope, no-follow filesystem checks and version-bound pagination. Do not widen access to make tests pass.
- Update both READMEs when the first-run workflow changes, and update the manual/reference for interface changes.
- Include reproduction steps and verification results without real paths, session content, credentials or raw private logs.
- Report ordinary bugs through [Issues](https://github.com/liuhuijiayou/readonly-observer/issues) and propose code changes through [pull requests](https://github.com/liuhuijiayou/readonly-observer/pulls). Submit only work you have the right to contribute under the project's [MIT License](../LICENSE); security findings follow [SECURITY.md](../SECURITY.md).

## Keep runtime data separate

Never move credentials, original sessions, active state, transport executables or observed projects as repository cleanup. Keep deployed program installations and instance homes independent from the source tree. Preserve actual runtime references at their installed paths; moving a virtual environment can break absolute entry points.

Private backups and recovery material do not belong in source distributions. Review conflicts before restoring any backup; do not overwrite current files blindly. Documentation-only changes can produce a new archive while leaving runtime module hashes unchanged, so record the new artifact hash rather than relabeling a deployed artifact.

Release maintainers must verify the exact source, artifacts and destination for every publication. See [release requirements](release-scope.md).

## Publication review workflow

These are preparation steps, not permission to publish or rewrite history. Use a trusted terminal on the intended source copy. Do not paste private command output into a public issue. A cloud snapshot without `.git` cannot establish anything about the original repository's history.

### 1. Review the existing repository locally, if it has Git history

```sh
git status --short --untracked-files=all
git status --short --ignored
git ls-files
git diff --stat
git diff --check
git diff
git diff --cached --name-status
git diff --cached --check
git diff --cached
```

Review tracked files as well as ignored/untracked files. An ignored file can still be tracked from an earlier commit. Check private settings, logs, fixtures and generated artifacts against [the exclusion list](release-scope.md#3-what-must-stay-out). Do not run `git add .` or `git add -f` in a mixed private working directory.

If existing history is intended for publication, inspect its refs and paths before authorizing that history:

```sh
git for-each-ref --format='%(refname)'
git log --all --oneline --decorate
git log --all --name-only --format= --
git log --all --stat --
```

These commands are **an inventory, not a secret audit**. Review the actual patches/blobs reachable from every ref you plan to publish, including renamed/deleted files, with an approved local secret-review process. Do not infer that `--all` includes unreachable objects or unpublished working files. Original remotes/configuration can themselves be private; inspect them locally if relevant without copying them to the deliverable. If no repository exists, skip these Git commands rather than claim a history review occurred.

No history audit or cleanup is performed by `check_repository.py`. Stop publication on an uncertain finding. Removing an exposed secret from the current file does not revoke it or erase historical copies; use the owner's credential and history-remediation process. Do not automatically rewrite or push history.

### 2. Export only the reviewed source contract

From the original source tree with its installed development environment:

```sh
.venv/bin/python -I -B scripts/check_repository.py
.venv/bin/python -I -B scripts/check_repository.py \
  --export /absolute/path/to/new-reviewed-source
```

Use a fresh destination with an existing parent. Review the report before continuing. The export omits the original `.git`, so it creates a clean source copy, not a cleaned version of existing history. It does not establish ownership. Unknown files, including future CI files, will not export until all inventories are intentionally updated.

### 3. Verify the exported copy and its distributions

Change to the new export, create a fresh Python 3.14 environment, and run the setup/test/build commands above. The export should run the same synthetic suite. Preserve verification summaries and artifact hashes privately; only publish a sanitized summary, not raw local evidence.

```sh
shasum -a 256 dist/local_readonly_observer-0.3.3-py3-none-any.whl \
  dist/local_readonly_observer-0.3.3.tar.gz
```

Run `scripts/check_release.py` on those exact archives before recording their hashes. Validate installation in another fresh environment and exercise the installed MCP service against synthetic approved fixtures, not personal sessions. A static repository check does not replace the supported Python 3.14 runtime suite. No CI workflow is currently supplied; local results must not be labeled CI.

### 4. Stage only after rights, license and destination decisions

For an explicitly approved **new clean source repository**, initialize Git in the export, not the mixed working directory. The following snippet stages only the exact current inventory; it neither commits nor publishes:

```sh
git init
.venv/bin/python - <<'PY'
from pathlib import Path
import subprocess
names = [s for s in Path('PUBLIC_FILES.txt').read_text().splitlines()
         if s and not s.startswith('#')]
subprocess.run(['git', 'add', '--', *names], check=True)
PY
git diff --cached --name-status
git diff --cached --stat
git diff --cached --check
git diff --cached
```

Before committing, inspect the full staged diff and check the index for unexpected entries:

```sh
.venv/bin/python - <<'PY'
from pathlib import Path
import subprocess
allowed = {s for s in Path('PUBLIC_FILES.txt').read_text().splitlines()
           if s and not s.startswith('#')}
tracked = set(subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')) - {''}
assert tracked == allowed, 'Index differs from reviewed inventory; inspect before proceeding'
print('Index matches reviewed inventory; content/history review is still required')
PY
```

This exact-inventory check is intended for the fresh export. Do not use it to delete legitimate files from an established repository. Commit identity, history preservation, remote creation, tags, pushes and release uploads remain separate decisions. This guide intentionally provides no automatic push command.

### 5. Final release review

Confirm every gate in [release-scope.md](release-scope.md): actual root license, rights, security contact, source/tag identity, inspected history, exact package members and redistribution obligations. Source repository and binary release assets have different contents; do not add the installer or `dist/` to Git simply to distribute them. If any gate is unresolved, keep the result as a reviewed private candidate.
