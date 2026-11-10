# Linux terminal wizard implementation audit

This change is awaiting human review: no production deployment, commit, push or release was performed. It adds an installer/upgrader for future independent Linux nodes. The earlier hand-installed production instance is not adopted or modified. See the complete [English SOP](deployment.md#terminal-wizard-sop) and [中文 SOP](deployment.zh-CN.md#终端向导-sop).

## Implementation and boundary

- `scripts/install_linux_node.sh` and `scripts/upgrade_linux_node.sh` are executable Bash bootstraps. `scripts/linux_node.py` implements the shared Linux-only terminal wizard and deployment journal using Python3.14 stdlib. No changes to the existing macOS credential, profile, runtime or MCP server implementations were needed.
- The installer prompts for all node, installation/home, exact project/session, Tunnel display name/explicit ID, Client path, proxy enablement and unit fields. It detects only Client metadata, never downloads a binary. Humans approve code, source grants, unit and startup separately. There is no unattended authorization option.
- Runtime Key/Proxy URL enter only the existing Observer hidden-TTY credential CLI. The shell/controller never receive them. A Linux-only opt-in key ownership guard inside that CLI prevents registered same-host key reuse. Claims are root-private fingerprints, not recoverable key values. Cross-host uniqueness still requires separate Platform issuance and explicit human attestation.
- Code is exported through the public inventory into an immutable-path release; each release has its own venv. Existing checkouts are not reset/cleaned. The home remains independent of code versions. Homes, units and local Tunnel claims cannot be taken over implicitly. Existing credentials require explicit keep/rotate during owned-install recovery.
- Upgrades stop only the recorded unit, preserve source approvals and credential files, back up configuration plus state metadata, and build/verify a new release. Unit replacement needs human review and an unchanged prior digest/origin. Failed builds/startup restore the previous unit/version. Refusal, interruption and `--no-start` leave services stopped. Retained releases, a private journal and backup `RESTORE.txt` support rollback/recovery.
- The existing systemd version detector and renderer select checked RuntimeDirectory staging for 219–246 or native LoadCredential for 247+. Staging/source validation, CREDENTIALS_DIRECTORY-only Manager reads, Worker environment isolation and read-only tools remain unchanged.

## Verification record

Final validation on Linux/Python3.14.10: **273 distinct cases, 272 passed, 0 failed/errors, 1 skipped**. This includes 269 suite cases (268 passed, native Mac framework check skipped) and 4 actual-systemd219 integration cases (all passed). The 28 new wizard cases are a subset of the suite. Repeated runs, the final TTY-only rerun, packaging checks and individual subtests are not added to the distinct-case total. Synthetic fixtures use temporary projects/sessions, synthetic credentials and fake Tunnel Clients. No production credential contents, actual session bodies or remote Tunnel were accessed.

| Check | Command | Actual result |
| --- | --- | --- |
| Full suite, including both generated backends and Mac compatibility guards | `.venv314/bin/python -I scripts/test_suite.py --git /absolute/isolated/git` | 269 cases: 268 passed, 0 failed/errors, 1 skipped; 114.672s |
| Actual systemd219 credential lifecycle | `.venv314/bin/python -I scripts/systemd_smoke.py` | 3 passed, 0 failed/skipped; 10.880s |
| Actual systemd219 wizard deployment lifecycle | `.venv314/bin/python -I scripts/linux_wizard_smoke.py --git /absolute/isolated/git` | 1 passed, 0 failed/skipped; 15.037s |
| Complete real TTY wizard, including final leave-stopped choice | Isolated unittest rerun of `WizardTests.test_real_tty_metadata_wizard_and_hidden_cli_complete_without_editing_config` | 1 passed; 4.152s; already included in suite count |

The isolated test Git was2.47.3; the actual active Manager was219. Private command logs are under `.local/verification/linux-wizard/`, outside the public inventory. Earlier development runs exposed prompt flushing, mixed CLI stderr/JSON, and a missing offline argument in the smoke harness; these were fixed before the final passing checks.

This request changes **20 public files: 13 modified, 7 new**. The public inventory now contains87 files. Both shell launchers are executable0755; syntax/help checks pass. Public-tree and final wheel/sdist checks cover the synchronized inventory, MANIFEST, gitignore and release filename allowlists. Local build artifacts/logs remain private; no staging, commit or push was done. The unchanged hashes of `credentials.py`, `profile.py`, `runtime.py` and `server.py` were checked against the start-of-task snapshot.

The test harness drives the real existing credential CLI through pseudo terminals, checks terminal ECHO is disabled before sending synthetic secrets, and checks transcripts contain neither key nor proxy value. A complete real terminal wizard test enters metadata and approvals without editing configuration files. Transaction tests cover both generated backends, multiple instances, existing home/unit protection, refusal, Ctrl+C, resume, explicit keep/rotation, duplicate host key/Tunnel, exact session grants, upgrade/rollback and failed/abandoned upgrades.

Actual systemd tests create only unique synthetic runtime units and remove them afterward. They check credential staging/permissions, provider access, fake Client proxy, Worker environment, filesystem read-only behavior, 13 MCP tools, SIGTERM, crash/restart, restaging, invalid sources, failed-start cleanup, and installer-driven install/upgrade/rollback. The opt-in smoke scripts intentionally operate temporary units under `/run`; ordinary installer tests use a fake systemd host.

## Unverified behavior and operational risks

- This host has systemd219 and Python3.14.10. Native 247+ is covered by generated-unit/provider tests and the supplied Ubuntu CI, not a local native Manager run. Real macOS/Keychain and hosted CI execution remain unverified here. Linux guards/compatibility tests are not a substitute for Mac acceptance.
- The host's stock Git is older than the required2.28. Tests inject an existing isolated modern Git only into synthetic fixtures; the production wizard checks `/usr/bin/git` and refuses an unsupported installation. No system packages, users, firewall or systemd version were changed. Stock CentOS7 without approved modern prerequisites is not a supported one-command install.
- Isolated venv/package tests install a built wheel offline with fixture dependency paths. Actual dependency download/provisioning on a fresh Ubuntu/CentOS machine has not been exercised. A verified Python with venv/ensurepip, modern Git, trusted dependencies and operator-verified Client are prerequisites; the wizard is not an OS bootstrapper. Missing prerequisites fail before deployment.
- Existing manual deployments lack installer ownership metadata and are refused by the upgrader. Their documented manual recovery path remains available; automatic adoption would need a separate reviewed migration.
- Root is the deployment/runtime account in this iteration. It can bypass local permissions, fingerprints and authorization records; this cannot isolate secrets from a hostile root or same-UID process. Source code and dependency wheels are trusted executable input approved by the operator.
- Persistent Linux credential sources are root-only0600 plaintext, not static encryption. Legacy staging verifies tmpfs, which can still be swapped unless the host independently controls swap. No claim of LoadCredentialEncrypted equivalence is made.
- Managed same-host duplicate checks do not prove uniqueness across machines, UIDs, old unregistered instances or accounts. Issue an independent Tunnel and Runtime Key for every concurrent node. No central service or remote revocation API is introduced.
- Retained versions/backups use disk and are not automatically deleted. Power-loss recovery can need operator review; unknown unit edits are always refused. Stop/delete are local actions and do not revoke Platform permissions or remove ChatGPT connections.
- No real Tunnel connectivity was tested. Platform Tunnel/key creation and each ChatGPT MCP connection remain manual. Local validation cannot establish remote readiness.
