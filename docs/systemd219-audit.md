# systemd 219 implementation and acceptance audit

This is the follow-up to the [earlier Linux adapter audit](implementation-audit.md). Existing uncommitted work on `linux-platform-adapter` was preserved; no reset, commit, push, release, system upgrade or production service start occurred. See [中文 deployment](systemd219.md) / [English deployment](systemd219.en.md).

## Architecture

The original Manager Provider remains CREDENTIALS_DIRECTORY-only. Systemd247+ uses native LoadCredential. For 219–246, a restricted root ExecStartPre prepares only enabled instance credentials in a systemd-created 0700 RuntimeDirectory on verified tmpfs. Source/target no-follow, ownership, modes, links, size, content and identity checks fail closed. Publication does not overwrite existing files; failed preparations clean only this attempt's inodes. Systemd owns runtime cleanup. Credential IDs, persistent source locations, source grants and Mac implementation are unchanged.

Version detection queries PID1 through systemctl. Individual feature thresholds are evaluated: directory path directives from231, strict protection from232, native credentials from247. The 219 renderer uses unquoted validated absolute scalar paths, historical ReadOnlyDirectories/ReadWriteDirectories, ProtectSystem=full and exact home/runtime write exceptions. Explicit read-only `/tmp`/`/var/tmp` rules close PrivateTmp's otherwise writable temporary mounts.

Key implementation: `linux_legacy.py` (tmpfs, source validation, atomic no-replace copy, rollback), `linux_systemd.py` (detection/feature matrix/render), `cli.py` (internal local staging), `test_systemd219.py` (synthetic negative paths), and `systemd_smoke.py` (actual service lifecycles with a network-free fake client).

## Actual environment and boundaries

Actual OS: CentOS7; active manager and tools: systemd219; CPython3.14.10; root. `/run` was inspected and is tmpfs. System Git1.8.3.1 is insufficient for the existing regression fixtures; the existing isolated Git2.47.3 is used only by the test runner. No system binaries or users were changed.

Production credential sources were checked with lstat only. Their owner/mode/nlink/size metadata remained root/0600/1 within limits; atime, mtime and ctime checks confirmed they were not accessed or modified during this work. No production Runtime Key, Proxy URL, auth file or session body was read or logged. Production configuration/authorization inode, size, mode, mtime and ctime were preserved; only non-secret config was read to render the final review unit. No target-project source was read or changed. No existing unit was overwritten.

All integration instances and credentials were synthetic. Unit source files, fake clients, test installations and logs are under the workspace's ignored `.local/verification/systemd219/`. Systemctl created only uniquely named temporary runtime links; systemd created their RuntimeDirectories. Tests stopped services, removed runtime links and confirmed directory cleanup. No official Tunnel binary or network connection was started.

## Verification

| Evidence category | Final actual result |
| --- | --- |
| Full synthetic regression suite | 241 tests: 240 passed, 0 failures/errors, 1 skipped |
| New version/staging regression subset (included above) | 18/18 passed |
| Actual systemd219 services with synthetic sources/fake client | 3/3 passed, 0 failures/errors/skips; unsafe-source test includes missing/mode/symlink/content subcases |
| Total distinct unittest cases | **244: 243 passed, 0 failures/errors, 1 skipped**; repeats are not counted again |
| Generated production review unit | Actual systemd219 verify exit0, no generated-unit configuration error |
| Isolated wheel install and deployment installer targeting a venv without pip | Passed; production venv unchanged |
| Public tree and artifacts | 80 reviewed public files; wheel/source allowlist, bounded patterns and license checks passed |
| Native247+ and macOS | Native247+ unavailable locally; Mac native-framework test skipped, compatibility simulation passed |
| Real Tunnel / ChatGPT | Not started or tested |

Commands: `.venv314/bin/python -I scripts/test_suite.py --git /tmp/observer-git/bin/git`; `.local/build-venv/bin/python -I scripts/systemd_smoke.py`; `systemd-analyze verify` on the generated unit; `scripts/check_repository.py` and `scripts/check_release.py`. The modern Git path is a pre-existing isolated test tool; production still uses its existing Git selection. Synthetic tests, real systemd219 tests, hosted CI and real Tunnel tests are separate evidence categories.

An initial real-219 run exposed writable private `/tmp`, despite ReadOnlyDirectories=/. The unit was corrected to mark `/tmp` and `/var/tmp` explicitly read-only. Subsequent actual service tests passed. This failure and fix were not hidden by skipping or weakening the assertion.

Systemd-analyze verify returns zero for generated test units and the final production review unit. The host additionally emits a warning that an unrelated existing unit is marked executable. That unit was not modified; no generated-unit configuration error was reported.

Actual-219 integration covers RuntimeDirectory creation/modes/tmpfs, exact selected copies, Manager credential/proxy loading, 13 read-only MCP tools and observer_info, direct inspection of only synthetic Workers' environment, denied synthetic project/tmp writes, SIGTERM cleanup, client failure/automatic restart with re-staged rotated synthetic key, and missing/mode/symlink/content source refusal plus failed-start cleanup. Partial publication/write/fsync failures and source swaps are covered by synthetic fault-injection tests.

Native247+ templates and the unchanged Provider have regression tests; native systemd247+ was not available locally. Native macOS framework validation remains skipped on Linux; Mac compatibility simulation passes and Mac core files are unchanged. Hosted CI is supplied but has not run for this uncommitted change. Real Tunnel/ChatGPT acceptance is **not performed**, as required by the execution boundary.

## Production review artifacts and manual boundary

After actual219 synthetic integration succeeded, the existing production instance's unit was generated into the ignored verification directory and checked using the actual systemd219 verifier. The reviewed wheel is built separately from the existing production venv. No actual instance reinitialization, credential re-entry, key copying, Tunnel-ID change or source reapproval occurred.

The operator must review artifacts, update the Observer package in the existing venv, verify the unit and install it only at an unused unit path or separately review an existing deployment. Do not run two units for one home. Real ExecStartPre reading of persistent sources and actual Tunnel connection happen only when the operator explicitly deploys/starts that service. Detailed commands and risks are documented in both languages.

Persistent sources are root-only plaintext, not encrypted at rest; checked tmpfs can swap. Legacy runtime files are accessible/writable by root. These are not equivalent to LoadCredentialEncrypted or a hostile-root sandbox. Stop/cleanup does not revoke remote keys or permissions.

## File accounting for this follow-up

**22 public files changed: 17 modified, 5 new**, measured against the per-file hashes captured at the start of this request, rather than treating all previous uncommitted Linux changes as this request's work. The cumulative Git workspace has 42 changed/new files; earlier work remains preserved. Public filenames were added together to PUBLIC_FILES.txt, MANIFEST.in, .gitignore and release allowlists. Mac credentials/profile/runtime/server implementations are unchanged.

- `.github/workflows/ci.yml`
- `.gitignore`
- `MANIFEST.in`
- `PUBLIC_FILES.txt`
- `README.md`
- `README.zh-CN.md`
- `SECURITY.md`
- `docs/deployment.md`
- `docs/deployment.zh-CN.md`
- `docs/implementation-audit.md`
- `docs/release-scope.md`
- `docs/systemd219-audit.md` (new)
- `docs/systemd219.en.md` (new)
- `docs/systemd219.md` (new)
- `scripts/check_release.py`
- `scripts/systemd_smoke.py`
- `src/observer/cli.py`
- `src/observer/linux_credentials.py`
- `src/observer/linux_legacy.py` (new)
- `src/observer/linux_systemd.py`
- `tests/test_linux.py`
- `tests/test_systemd219.py` (new)
