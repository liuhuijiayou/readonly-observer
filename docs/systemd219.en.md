# Safe deployment on systemd 219

Linux uses the **active systemd manager's version**, obtained from `systemctl show --property=Version`, to select individual features. It does not infer support from the distribution, Python or only the systemctl binary. Unknown/unreachable versions and versions below 219 fail closed. Existing Mac implementation and defaults are unchanged. See [中文说明](systemd219.md), [actual verification](systemd219-audit.md) and the [full deployment guide](deployment.md).

| Manager version | Credential backend | Filesystem directives |
| --- | --- | --- |
| 219–230 | Restricted ExecStartPre staging into RuntimeDirectory | ProtectSystem=full; ReadOnlyDirectories/ReadWriteDirectories |
| 231 | Same staging | ProtectSystem=full; ReadOnlyPaths/ReadWritePaths |
| 232–246 | Same staging | ProtectSystem=strict; ReadOnlyPaths/ReadWritePaths |
| 247+ | Native LoadCredential | ProtectSystem=strict; ReadOnlyPaths/ReadWritePaths |

Introduction versions are established from the [v219 manual](https://github.com/systemd/systemd/blob/v219/man/systemd.exec.xml), [v231/v232 release notes](https://github.com/systemd/systemd/blob/v232/NEWS) and [native Credentials reference](https://www.freedesktop.org/software/systemd/man/247/systemd.exec.html). Native credentials never invoke legacy staging. Credential IDs and the Manager's Provider protocol remain unchanged.

## Legacy startup

Systemd first creates the instance-specific `/run/readonly-observer-<namespace>` with mode 0700. ExecStartPre then runs the existing bounded `recover --approve`, followed by internal `_stage-credentials`. ExecStart directly runs one foreground `observer run`; there is no shell, background process wrapper or second Manager.

The restricted staging helper requires root, an exact instance-specific CREDENTIALS_DIRECTORY, a root-owned 0700 directory and **tmpfs verified with fstatfs on the pinned directory descriptor**. It opens only this instance's `credentials/runtime` and, when enabled, `credentials/proxy`. It checks directory ownership/mode, component-by-component O_NOFOLLOW, regular files, root ownership, exact 0600 mode, one link, size, valid ASCII/content, and matching descriptor/path identities around reads.

All selected sources are validated before publication. A fresh O_EXCL lock and random O_EXCL temporary files prevent concurrent takeover. File bytes are fsynced, then link/unlink atomically publishes complete files without overwriting destinations. Final filenames are the existing credential IDs, mode 0600 and nlink=1. Directory metadata is fsynced. Any failure removes only this attempt's created inodes; unknown files are preserved and cause refusal. Cleanup errors return static codes requiring local review. The helper never emits credential values.

Manager still reads only CREDENTIALS_DIRECTORY. There is no source-file, JSON, ordinary environment key or other-instance fallback. The internal helper is not an MCP tool and should not be manually run against production. Use one systemd unit per home; additional instances use different homes. Systemd removes RuntimeDirectory on stop, failed startup and restart; each next startup stages afresh. These lifecycles were tested on actual systemd 219 using synthetic material.

The 219 unit contains no LoadCredential, ProtectSystem=strict or ReadWritePaths. Scalar paths and path lists are unquoted validated absolute paths, avoiding the old WorkingDirectory quote parsing issue. Ambiguous characters, including whitespace, quotes, percent, dollar and backslash, cause generation refusal.

ReadOnlyDirectories includes `/`, `/tmp` and `/var/tmp`; only the exact instance home and RuntimeDirectory are writable. Explicit temporary-directory rules are necessary because PrivateTmp otherwise supplies writable temporary mounts. Actual integration tests verified that the synthetic observed project and private `/tmp` were read-only. NoNewPrivileges, KillMode=control-group, UMask=0077, LimitCORE=0 and raw-output suppression remain enabled.

Proxy is a separate credential; ordinary configuration stores only its enabled flag. Only the owned transport supervisor/client receives the key/proxy. Workers receive neither key, proxy, CREDENTIALS_DIRECTORY nor inherited SSH-shell proxy variables. No credential values appear in EnvironmentFile, Environment directives or command arguments.

## Production deployment after reviewing test evidence

Actual 219 synthetic integration passed before rendering the real instance's review unit. **No production unit was installed or started; no real Tunnel was launched.** Existing keys, Tunnel identity and source grants are preserved, with no credential re-entry.

The reviewed wheel and production unit live in the repository's private `.local/verification/systemd219/` output, excluded from Git. Use the exact artifact paths in the final report. Check for an existing service using the same home before installing anything: do not run a second unit for that home, overwrite an existing unit or silently replace its deployment.

The following are operator deployment steps, not actions performed by the implementation/test run. Review the wheel and unit, then update only the Observer package in the existing venv. Keep the venv at its original location. A separate build pip can target a venv that has no pip:

```sh
BUILD_PY=/absolute/reviewed/build-venv/bin/python
TARGET_PY=/absolute/observer/venv/bin/python
WHEEL=/absolute/reviewed/local_readonly_observer-0.1.0-py3-none-any.whl
UNIT=/absolute/reviewed/observer-linux1.service
"$BUILD_PY" -I -m pip --python "$TARGET_PY" install \
  --no-index --no-deps --force-reinstall "$WHEEL"
systemd-analyze verify "$UNIT"
```

Install only at a confirmed unused unit name. Noclobber prevents overwriting a unit. If the first command fails, stop and review the existing deployment; do not continue.

```sh
DEST=/etc/systemd/system/observer-linux1.service
if (umask 022; set -C; cat "$UNIT" > "$DEST"); then
  systemctl daemon-reload && systemctl enable --now observer-linux1.service
else
  printf '%s\n' 'Refusing overwrite; review the existing unit.' >&2
fi
```

Real deployment's ExecStartPre will securely read the existing source credentials; synthetic tests did not read them. Confirm local status and a harmless approved marker, then verify the existing ChatGPT connection's node identity and 13 read-only tools. No new Tunnel is required. Actual ChatGPT calls are necessary for remote acceptance; local process state is insufficient.

Use systemctl for stop/restart. After stopping, confirm the RuntimeDirectory shown in the generated unit no longer exists. On failure inspect service status/static error codes, not credential contents or raw client logs. Do not delete unknown runtime files to force takeover; first establish that the service and its owned children are stopped.

## Security differences

Persistent legacy sources are **root-only plaintext, not encrypted at rest**, and are not equivalent to LoadCredentialEncrypted. Runtime copies are in checked tmpfs; tmpfs can still swap, and this feature does not configure swap/disk encryption. Root and the root service identity can access or modify these files. Same-UID malicious processes are outside the application boundary.

Read-only mounts prevent ordinary writes, but do not remove root's OS powers. A compromised privileged process or later submounts can exceed old systemd's filesystem restrictions. No kernel-level hostile-root sandbox is claimed. The shared 13-tool MCP API still has no writes, arbitrary execution, remote approval expansion or session control. Local cleanup does not revoke a remote key, Platform permission or ChatGPT connection.

## Reproduce synthetic checks

```sh
python3.14 -I scripts/test_suite.py
python3.14 -I scripts/test_suite.py --git /absolute/isolated/git
/path/to/installed/test/python -I scripts/systemd_smoke.py
```

The last command requires Linux root and active systemd219+. It links only uniquely named temporary test units at runtime, with source units/fixtures under the repository's `.local`; systemd-created `/run` links and directories are removed afterward. The fake client has no network operations. Tests do not use existing units, production credentials or real sessions. On 247+ it exercises native LoadCredential; legacy-specific source mode/symlink checks are covered separately. Hosted CI and native platform results must be distinguished from local actual-219 results.
