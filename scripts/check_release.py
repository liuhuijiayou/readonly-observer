"""Inspect explicitly supplied source/wheel artifacts; never scans local sources.

Reports categories and approved member locations, never matched values. This
bounded pattern check cannot certify ownership, license or absence of secrets.
"""
import argparse
from email.parser import BytesParser
import hashlib
import json
from itertools import islice
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

MODULES = {"__init__", "cli", "config", "credentials", "fs", "gitreader", "profile", "references", "registry", "runtime", "security", "server", "service", "sessions", "workspace", "wrappers", "nodes", "linux", "linux_commands", "linux_credentials", "linux_fs", "linux_git", "linux_runtime", "linux_systemd", "linux_legacy"}
TESTS = {"support", "test_cursors", "test_filesystem", "test_git_evidence", "test_independent_redaction_budget", "test_mcp_wire", "test_next_phase", "test_product", "test_redaction", "test_sessions", "test_release", "test_scoped_search", "test_session_references", "test_repository", "test_linux", "test_platform_compat", "test_systemd219"}
DOCS = {"product-design", "product-manual", "config-reference", "migration", "troubleshooting", "release-scope", "repository", "deployment", "deployment.zh-CN", "implementation-audit", "systemd219", "systemd219.en", "systemd219-audit"}
TOP = {".gitignore", "PUBLIC_FILES.txt", "LICENSE", "README.md", "README.zh-CN.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "Observer.command", "pyproject.toml", "MANIFEST.in", "requirements.lock", "requirements-macos-py314.lock", "dependencies-tested.json", "PKG-INFO", "setup.cfg"}
RESOURCE = {"observer/resources/settings.schema.json", "observer/resources/licenses/mcp-LICENSE", "observer/resources/licenses/regex-LICENSE.txt", "observer/resources/licenses/regex-NOTICE.txt"}
DIST_INFO = "local_readonly_observer-0.1.0.dist-info"
LICENSE_FILES = {"LICENSE", "THIRD_PARTY_NOTICES.md"}
WHEEL_LICENSE_MEMBERS = {DIST_INFO + "/licenses/" + name for name in LICENSE_FILES}
META = {"PKG-INFO", "METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt", "dependency_links.txt", "requires.txt", "SOURCES.txt"}
PATTERNS = {
    "literal_tunnel_identifier": re.compile(rb"\btunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}\b"),
    "personal_absolute_path": re.compile(rb"/(?:Users|home)/(?!Shared(?:/|[\"']))[a-zA-Z0-9_.-]+/"),
    "local_real_session_identifier": re.compile(rb"\b01[a-f0-9]{6}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"),
    "private_development_runtime": re.compile(rb"\.local/(?:dev-cli|tunnel-runtime|downloads|bin)/"),
    "literal_api_key_candidate": re.compile(rb"\b(?:sk-(?:proj-|svcacct-)?[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{25,}|AKIA[A-Z0-9]{16})\b"),
}

def allowed(name, kind):
    if kind == "wheel" and name in WHEEL_LICENSE_MEMBERS:
        return True
    if kind == "sdist":
        if name in TOP or name in {"examples/instance-settings.json", ".github/workflows/ci.yml"}:
            return True
        if name in {"scripts/build_fixtures.py", "scripts/l1_probe.py", "scripts/check_release.py", "scripts/check_repository.py", "scripts/test_suite.py", "scripts/systemd_smoke.py"}:
            return True
        if name.startswith("tests/") and name[6:].endswith(".py") and name[6:-3] in TESTS:
            return True
        if name.startswith("docs/") and name[5:].endswith(".md") and name[5:-3] in DOCS:
            return True
        if name.startswith("src/"):
            name = name[4:]
    if name in RESOURCE or name in {"observer/" + p + ".py" for p in MODULES}:
        return True
    parts = PurePosixPath(name).parts
    return (len(parts) == 2 and parts[0] in {"local_readonly_observer.egg-info", DIST_INFO} and parts[1] in META)

def members(path):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > 256:
                raise ValueError("archive_member_limit")
            for item in archive.infolist():
                if item.is_dir():
                    continue
                if item.file_size > 1024 * 1024 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("unsafe_archive_member")
                yield "wheel", item.filename, archive.read(item)
    else:
        with tarfile.open(path, "r:gz") as archive:
            items = archive.getmembers()
            if len(items) > 256:
                raise ValueError("archive_member_limit")
            roots = {PurePosixPath(i.name).parts[0] for i in items}
            if len(roots) != 1:
                raise ValueError("invalid_source_root")
            for item in items:
                if item.isdir():
                    continue
                if not item.isfile() or item.size > 1024 * 1024:
                    raise ValueError("unsafe_archive_member")
                yield "sdist", str(PurePosixPath(*PurePosixPath(item.name).parts[1:])), archive.extractfile(item).read()

def inspect(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16*1024*1024:
        raise ValueError("invalid_artifact_file")
    issues, evidence, total, kind, license_metadata = [], {}, 0, None, None
    for index, (kind, name, raw) in enumerate(members(path)):
        total += len(raw)
        if total > 8 * 1024 * 1024:
            raise ValueError("archive_total_limit")
        parts = PurePosixPath(name).parts
        if not parts or name.startswith("/") or any(p in {".", ".."} for p in parts) or not allowed(name, kind):
            issues.append({"category": "member_outside_allowlist", "location": "member_index_" + str(index)})
            continue
        evidence[name] = hashlib.sha256(raw).hexdigest()
        if name == ("PKG-INFO" if kind == "sdist" else DIST_INFO + "/METADATA"):
            license_metadata = BytesParser().parsebytes(raw)
        for category, pattern in PATTERNS.items():
            matches = list(islice(pattern.finditer(raw), 32))
            if matches:
                issues.append({"category": category, "location": name,
                               "lines": sorted({raw.count(b"\n", 0, m.start()) + 1 for m in matches})})
    required = ({"LICENSE", "PKG-INFO", "README.md", "README.zh-CN.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "src/observer/cli.py", "tests/test_product.py"}
                | {"src/" + name for name in RESOURCE}
                if kind == "sdist" else {"observer/cli.py", "observer/runtime.py", DIST_INFO + "/METADATA"} | RESOURCE | WHEEL_LICENSE_MEMBERS)
    if not required <= set(evidence):
        issues.append({"category": "required_public_files_missing", "location": "artifact"})
    if (license_metadata is None or license_metadata.get_all("License-Expression") != ["MIT"]
            or set(license_metadata.get_all("License-File", [])) != LICENSE_FILES):
        issues.append({"category": "missing_or_invalid_license_metadata", "location": "artifact_metadata"})
    return {"artifact": path.name, "kind": kind, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "members_checked": len(evidence), "uncompressed_bytes": total,
            "checks_passed": not issues, "issues": issues, "member_sha256": evidence,
            "scope": "allowlist_and_bounded_patterns_only; not_a_secret_or_license_attestation"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        reports = [inspect(path) for path in args.artifacts]
        print(json.dumps({"ok": all(r["checks_passed"] for r in reports), "artifacts": reports}, indent=2))
        return 0 if all(r["checks_passed"] for r in reports) else 1
    except Exception:
        print('{"ok":false,"error":"invalid_or_unsafe_artifact; raw_errors_suppressed"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
