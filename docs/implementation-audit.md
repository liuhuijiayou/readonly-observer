# Linux adapter implementation and verification audit

Subsequent systemd 219 implementation and actual integration evidence are recorded in the [separate audit](systemd219-audit.md); the earlier 247+ limitation below is historical.

This development branch adds Linux support while preserving the stable Mac implementation. It has not been committed, pushed or published. See [English deployment](deployment.md) and [中文部署](deployment.zh-CN.md) for the architecture, complete new-machine procedure, identity, isolation, proxy, root boundary, rotation, replacement and four-layer revocation runbooks.

## Evidence boundaries

The workspace began clean on `main` at `18e3a4f`. Work is isolated on `linux-platform-adapter`. No pre-existing modifications were overwritten. The initial additions to shared Keychain/Store code were removed before final implementation; `credentials.py`, `profile.py`, `runtime.py`, `server.py`, settings schema and existing example settings match the starting revision. Mac default behavior and Keychain service/account derivation are covered by synthetic compatibility tests. No Mac was contacted or modified.

The provided environment description said Ubuntu 22.04/systemd249. Actual read-only inspection showed **CentOS 7 userspace, systemd219, Git1.8.3.1, root and CPython3.14.10**. Therefore this report does not claim native Ubuntu22.04/systemd249 execution. A temporary modern Git2.47.3 was built under `/tmp` from the official Git source; the synthetic test runner selects it only within its test process. Production Git selection remains `/usr/bin/git`. No system Git, user, firewall or cloud security group was modified.

The first baseline run with system Git failed during fixture setup: 32 tests ran with 17 class-setup errors because old Git cannot accept `init --initial-branch`. An intermediate modern-Git run found 15 failures, including root Git private index refresh, Linux directory rename detection and a stale fixture inconsistent with the repository's latest `.local` policy. Linux-specific fixes retain snapshot/no-follow checks; the stale private fixture moved beneath the already-denied `credentials` directory. No file access policy was broadened.

All tests use synthetic projects, exact synthetic JSONL files and synthetic credentials. Fake Tunnel executables only inspect their supplied local environment and wait/exit; no real Tunnel Client is started and no remote connection is made. The requested real project directory was neither read nor modified, no real Codex session body/auth file/Runtime Key was read, and no Observer instance was registered against personal data.

## Architecture and relevant implementation

| File | Responsibility |
| --- | --- |
| `src/observer/cli.py` | Lazy Linux dispatch; additive local node, recovery, revocation, proxy and unit commands; unchanged Mac branches |
| `src/observer/nodes.py` | Optional public identity without host/address disclosure; legacy fallback without migration |
| `src/observer/linux.py` | Inherits original Store; Linux sidecars, random identity, retirement and source revocation |
| `src/observer/linux_credentials.py` | systemd-only provider, fail-closed validation, secure local staging/rotation/deletion |
| `src/observer/linux_commands.py` | Hidden terminal input and reference-only metadata |
| `src/observer/linux_runtime.py` | Reuses original protocol/relay/config helpers; Linux manager, client supervision, pipe shutdown, inherited leases, bounded recovery, per-UID Tunnel guard |
| `src/observer/linux_systemd.py` | Per-instance service rendering, LoadCredential, control group lifecycle and filesystem restrictions |
| `src/observer/linux_git.py` | Disables private snapshot index refresh for Linux root execution |
| `src/observer/linux_fs.py` | Reopens selected path after descriptor traversal to detect Linux directory replacement |
| `src/observer/service.py` | Additive public node information; same 13 read-only tools and schemas |
| `tests/test_linux.py`, `tests/test_platform_compat.py` | Credentials, isolation, processes, crash, migration/revocation and Mac compatibility |
| `scripts/test_suite.py`, `scripts/systemd_smoke.py`, `.github/workflows/ci.yml` | Reproducible synthetic summary, opt-in native systemd smoke, Linux/Mac CI |

## Official source audit

Five official Tunnel documents were fetched/read: [OpenAI Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels), [client README](https://github.com/openai/tunnel-client/blob/master/README.md), [configuration](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md), [onboarding](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md), [permissions](https://github.com/openai/tunnel-client/blob/master/docs/permissions.md). The systemd247 Credentials reference was returned/read through official documentation search; fetching the systemd249 page timed out. Official Git `builtin/diff.c` was inspected from the temporary source build to confirm private index refresh behavior. Two official client implementation files were also inspected: [runtimeconfig/config.go](https://github.com/openai/tunnel-client/blob/master/pkg/runtimeconfig/config.go) and [runtimeconfig/file_config.go](https://github.com/openai/tunnel-client/blob/master/pkg/runtimeconfig/file_config.go), confirming the actual flag, environment mapping and proxy reference resolution. Total: **9 official documents/source files read**, excluding unsuccessful fetches and duplicate views. No claim relies on an invented Tunnel transfer or key reissue API.

The client docs confirm `control_plane.http_proxy`, `--control-plane.http-proxy`, `CONTROL_PLANE_HTTP_PROXY` and `env:VAR`. The Linux adapter reuses the current `client_config` and changes only the Linux transport environment/config. Repository inspection and bounded Git-history searches found no existing standalone Mac proxy adapter to port; the stable Mac client configuration was preserved.

Reusing an existing Tunnel ID with a newly issued authorized runtime key is an inference from the documented separation of these inputs. Preserving a ChatGPT connection must be validated in the actual account/workspace. Observer does not create/revoke keys, administer Platform roles, delete tunnels or disconnect ChatGPT.

## Final test and file accounting

| Check | Actual local result |
| --- | --- |
| `.venv314/bin/python -I scripts/test_suite.py --git /tmp/observer-git/bin/git` | 223 tests: **222 passed, 0 failures, 0 errors, 1 skipped** |
| Linux adapter subset | 19/19 passed: fail-closed credentials, atomic rotation, proxy and actual Worker spawn environment, concurrent isolation, leases, crashes/restart/recovery, local revocation/retirement and replacement |
| Mac compatibility subset | 6 tests: 5 passed using simulated Darwin and mocked APIs; 1 native-framework test skipped on Linux |
| `.venv314/bin/python -I scripts/systemd_smoke.py` | 1 test skipped because local systemd219 lacks Credentials; no unit installed |
| Aggregate distinct unittest cases (suite + systemd smoke) | **224 total: 222 passed, 0 failures/errors, 2 skipped**; repeated runs are not counted again |
| Native systemd247+ smoke in CI | Supplied, not executed here; no hosted CI run claimed |
| Wheel and source artifact inspection | Both passed filename allowlist, bounded secret-pattern and license metadata checks |
| Fresh wheel installation in a separate venv | Passed manager start/stop, MCP initialize/tools-list/observer_info and 13 read-only annotations; synthetic public source only |
| Public-source check | 75 reviewed files passed; private trees and Git history are outside the check |
| `git diff --check` | Passed |

The complete suite was rerun after the abstract-socket lease change. A final Linux subset pass also covers the subsequent unit-quoting adjustment. Final build/inspection is repeated after this audit update. Local results are not a hosted CI result.

Three simulated public nodes (`codex-observer-mac`, `codex-observer-linux1`, `codex-observer-linux2`) ran concurrently through actual local MCP processes. These are Linux-hosted simulations, not a real Mac test. Their node IDs, homes, source markers, sockets and credential namespaces differed; stopping one left the others usable. Two fake Tunnel processes ran concurrently with distinct IDs/keys, and only the client/supervisor received proxy/key data. Actual Worker spawn environments were inspected using synthetic values. No real Tunnel process or remote connection was started.

Migration tests preserve the selected public identity and configured Tunnel ID while requiring new instance credentials and fresh source authorization; local retirement/revocation tests assert that remote key/Platform/ChatGPT access remains unchanged. Issuance/revocation in Platform and a retained ChatGPT connection were not tested. Native macOS framework/Keychain behavior, native Ubuntu22.04/systemd249, the official client binary's networking, and actual simultaneous three-node ChatGPT acceptance remain **unverified**.

Structured source review covered **40 distinct Python files**: 24 runtime modules, 6 scripts and 10 test/support files (targeted excerpts included; this is not a claim of line-by-line review of all repository code). Nine official technical documents/source files were read as listed above; build-package metadata/downloads are not counted as documentation. The regression suite exercises the other existing tests as well.

There are **37 changed/new public files: 21 modified and 16 new**, with **26 new unittest cases** (19 Linux, 6 Mac compatibility, 1 opt-in systemd smoke). No commit or push was made. Untracked private build environments/artifacts remain excluded by the reviewed manifest. Existing real Observer homes and source authorizations were not overwritten.

## Complete changed-file inventory

- `.gitignore`
- `MANIFEST.in`
- `PUBLIC_FILES.txt`
- `README.md`
- `README.zh-CN.md`
- `SECURITY.md`
- `docs/config-reference.md`
- `docs/migration.md`
- `docs/product-design.md`
- `docs/product-manual.md`
- `docs/release-scope.md`
- `docs/repository.md`
- `docs/troubleshooting.md`
- `pyproject.toml`
- `scripts/build_fixtures.py`
- `scripts/check_release.py`
- `src/observer/cli.py`
- `src/observer/gitreader.py`
- `src/observer/service.py`
- `src/observer/workspace.py`
- `tests/test_filesystem.py`
- `.github/workflows/ci.yml` (new)
- `docs/deployment.md` (new)
- `docs/deployment.zh-CN.md` (new)
- `docs/implementation-audit.md` (new)
- `scripts/systemd_smoke.py` (new)
- `scripts/test_suite.py` (new)
- `src/observer/linux.py` (new)
- `src/observer/linux_commands.py` (new)
- `src/observer/linux_credentials.py` (new)
- `src/observer/linux_fs.py` (new)
- `src/observer/linux_git.py` (new)
- `src/observer/linux_runtime.py` (new)
- `src/observer/linux_systemd.py` (new)
- `src/observer/nodes.py` (new)
- `tests/test_linux.py` (new)
- `tests/test_platform_compat.py` (new)
