# Public release scope and readiness

ReadOnly Observer is maintained by `liuhuijiayou` under the [MIT License](../LICENSE), with the public repository at [liuhuijiayou/readonly-observer](https://github.com/liuhuijiayou/readonly-observer). The reviewed source inventory has **87 files** in [PUBLIC_FILES.txt](../PUBLIC_FILES.txt). This checklist defines what release maintainers must verify for each distribution; a bounded scan does not establish ownership or guarantee absence of secrets.

## 1. Release gates

| Gate | Required decision or evidence | Current boundary |
| --- | --- | --- |
| Rights and license | Preserve the MIT license and dependency notices; confirm rights and any employer obligations for new contributions | Root LICENSE and package license metadata are included; review provenance of new material |
| Usable source | Include code, dependency metadata, synthetic tests, safe examples and instructions needed to build/test/change it | Explicit reviewed inventory exists; verify the exact export and artifacts |
| Confidentiality | Review every published file, intended Git history/refs and final archives | Pattern checker is bounded; it does not audit Git history or prove absence of secrets |
| Honest verification | Record actual commands, environment, result and artifact hashes; separate local tests from remote operation | Platform restrictions and local/remote distinction are documented; do not turn a synthetic test into real-session acceptance |
| Publication plan | Confirm repository, release tag/assets and security/contribution channels | Use the project repository, Issues/PRs and the private reporting channel in SECURITY.md |

The Open Source Definition concerns license freedoms, not a compulsory collection of GitHub files. CONTRIBUTING, SECURITY and CODE_OF_CONDUCT are useful community practices, not by themselves an OSI qualification. Private reporting is documented in SECURITY.md; contribution guidance lives in docs/repository.md. A Linux/macOS synthetic CI workflow is supplied; hosted execution is pending. No code of conduct is present.

## 2. What belongs in the source repository

For this project's reviewed source distribution, include **all current inventory entries**, not a hand-selected subset. The following groups account for all 87 files; the inventory is authoritative for exact filenames.

| Current paths | Count | Purpose |
| --- | ---: | --- |
| `.gitignore`, `MANIFEST.in`, `PUBLIC_FILES.txt` | 3 | Reviewed-source and packaging boundary |
| `LICENSE`, `README.md`, `README.zh-CN.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md` | 5 | Project license, entry points, security scope and dependency notices |
| `pyproject.toml`, `requirements.lock`, `requirements-macos-py314.lock`, `dependencies-tested.json` | 4 | Build metadata and dependency/tested-environment records |
| `.github/workflows/ci.yml` | 1 | Synthetic macOS/Linux CI and Linux systemd smoke |
| `Observer.command` | 1 | Optional CLI menu launcher, currently included in the source contract |
| The 14 `.md` files listed under `docs/` | 14 | Operation, design, maintenance and publication documentation |
| `examples/instance-settings.json` | 1 | Empty stdio settings without real grants or secrets |
| `scripts/build_fixtures.py`, `scripts/check_release.py`, `scripts/check_repository.py`, `scripts/l1_probe.py`, `scripts/test_suite.py`, `scripts/systemd_smoke.py`, `scripts/install_linux_node.sh`, `scripts/upgrade_linux_node.sh`, `scripts/linux_node.py`, `scripts/linux_wizard_smoke.py` | 10 | Linux deployment/recovery and synthetic fixture, protocol, systemd and packaging verification helpers |
| The 26 `.py` files listed under `src/observer/` | 26 | Runtime implementation; exact names are in the inventory |
| `src/observer/resources/settings.schema.json` and the 3 files under `src/observer/resources/licenses/` | 4 | Public schema and preserved dependency notices |
| The 18 `.py` files listed under `tests/` | 18 | Synthetic regression tests and support code |

The root `LICENSE` and `THIRD_PARTY_NOTICES.md` are included in package license metadata and both distribution archives. Preserve the three dependency license/NOTICE resources as well. When adding or renaming public files, update `PUBLIC_FILES.txt`, `.gitignore`, `MANIFEST.in` and the applicable filename allowlists in `scripts/check_release.py` together. Any license changes also require matching `pyproject.toml` metadata and freshly verified artifacts; inventory changes alone are insufficient.

Optional future repository additions, not required by OSI as filenames: a dedicated CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, issue templates, additional CI targets and architecture illustrations. Add only when there is an owner and a usable process behind them. Do not fabricate a tracker, mailbox, build badge or CI result.

## 3. What must stay out

Do not upload these items as source, release assets, issues, screenshots or test evidence:

- `.local/` including `.local/verification/`, `.local/maintenance/`, archives and generated fixtures/results that contain local details; use synthetic inputs and summarize safe results instead.
- `.venv/`, other development environments, `__pycache__/`, editable-install metadata and local dependency caches.
- Instance `config/`, `state/`, `cache/`, `logs/`, including settings with real transport identifiers, `approvals.json`, `backup-*.json`, `active.json`, `transport.json`, sockets and locks. Actual instance homes may live outside the repository and are never export inputs.
- Credentials, Keychain data, API keys, real account/tunnel/session IDs, private project paths, raw JSONL sessions, personal conversations and unredacted execution logs.
- Downloaded Tunnel executables, local installers, historical/private candidates and unrelated third-party binaries that have not received artifact-level license and provenance review.
- The working tree's `.git/` directory as a copied archive. A newly published Git repository will necessarily have its own metadata; what must not be transferred blindly is the original private repository's history, refs, remotes or configuration.
- `dist/`, `build/` and generated archives as source-tree content. Selected, separately verified distribution files may instead be release assets under the next section.

`.gitignore` defaults to denying unknown files, but this does not remove already tracked content or past commits. A clean current tree/export says nothing about an existing repository's historical secrets. If an actual credential is discovered, revoke/rotate it through its owner before deciding how to remove exposure; do not treat deletion or history editing as revocation. History rewriting and publication require separate authorization.

## 4. Source repository versus release assets

**Source repository:** reviewed maintainable source, tests, metadata and documentation and the root license. Use the clean export workflow in [repository.md](repository.md), not a ZIP of the working directory. A public Git destination and the history to publish must be explicitly approved.

**Tag/release assets:** a versioned wheel and source archive built from the reviewed source; publish only after archive membership, notices, version and package behavior have been checked. Rebuild after license or documentation changes; earlier candidate archives do not acquire those changes. Associate assets with the correct source tag/commit and provide SHA-256 values and a concise platform/verification statement. Publish project assets through [GitHub Releases](https://github.com/liuhuijiayou/readonly-observer/releases).

The wheel includes Observer runtime/resources, not the entire repository's tests and docs; the source distribution includes the approved source contract. Neither currently vendors Python, Git, Tunnel or dependency distributions. Dependency metadata is not itself a vulnerability or license audit.

An offline macOS installer bundle is a **separate optional artifact**, not a required Git upload and not generated by the current public source build commands. Existing private bundles must not be uploaded automatically. Before publishing one, review its builder and complete manifest, every bundled wheel/binary's notices and redistribution obligations, supported Python/platform, checksums and clean-install behavior. Linking THIRD_PARTY_NOTICES.md alone is not a substitute for required bundled license material.

## 5. Pre-publication checklist

- [ ] Rights and applicable employer obligations for the release are confirmed; root license, inventories, package metadata and final artifacts agree.
- [ ] Publication destination, visibility and intended history/refs are approved.
- [ ] A maintainer/private security reporting channel is real and documented; contribution instructions do not invent infrastructure.
- [ ] The clean export, staged files and any history intended for publication are reviewed for private information and third-party obligations.
- [ ] Synthetic tests, SDK probe, clean package install and archive checks have actual environment/result records. Unverified platforms and remote behavior stay labeled as such.
- [ ] Artifact versions and hashes match their source tag/commit; no personal instance, real log, credential or unrelated binary is included.
- [ ] Release notes describe implemented behavior and limits, rather than private deployment history or unsupported claims.

Complete this checklist for each release; it is not a record of a particular deployment or a result of a static pattern scan. Follow [the executable review workflow](repository.md#publication-review-workflow) for preparation; do not push merely because a checker passes.

## References

- [OSI Open Source Definition](https://opensource.org/osd): freedoms required of an open-source license.
- [Open Source Guides: legal side](https://opensource.guide/legal/): permissions, licensing and contributor considerations.
- [GitHub: removing sensitive repository data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository): exposure, credential rotation and history limitations.
- [GitHub: about releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases): source tags and separately attached release assets.
