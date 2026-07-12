#!/usr/bin/env python3
"""Build and verify deterministic PLAN-004 supply-chain evidence."""

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


SCHEMA = "helixos.plan-004-release-evidence/1"
EXPECTED_CYCLONEDX_VERSION = "0.5.9"
EXPECTED_AUDIT_VERSION = "0.22.2"
EXPECTED_RUSTSEC_REVISION = "6e3286f4efa8c142fb33e5ea4342c8db6693cf34"
EXPECTED_SPDX_REVISION = "c4a7237ec8f4654e867546f9f409749300f1bf4c"
EXPECTED_SQLITE_VERSION = "3.53.2"
EXPECTED_SQLITE_SOURCE_ID = (
    "2026-06-03 19:12:13 "
    "d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
)
EXPECTED_LIBSQLITE_VERSION = "0.38.1"
EXPECTED_RUSQLITE_VERSION = "0.40.1"
EXPECTED_FILE_ID_VERSION = "0.2.3"
MANIFEST_NAME = "MANIFEST.sha256"
LOCAL_M4_ARTIFACTS = (
    (
        "benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.json",
        "ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12",
    ),
    (
        "benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.recovery-transfer.json",
        "da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e",
    ),
)
SECRET_MARKERS = (
    "github_pat_",
    "ghp_",
    "gho_",
    "authorization: bearer",
    "x-access-token:",
)
TRIAGED_RUSTSEC_WARNINGS = {"RUSTSEC-2025-0134"}
REVIEWED_INPUT_PATHS = (
    "kernel/Cargo.lock",
    "kernel/rust-toolchain.toml",
    "kernel/helix-coordinator-sqlite/Cargo.toml",
    ".github/workflows/durable-preparation.yml",
    "specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql",
    "specs/004-durable-preparation/contracts/preparation-backup-manifest-v1.schema.json",
    "specs/004-durable-preparation/contracts/preparation-backup-provenance-attestation-v1.schema.json",
    "specs/004-durable-preparation/contracts/recovery-snapshot-manifest-v1.schema.json",
    "specs/004-durable-preparation/contracts/recovery-root-metadata-v1.schema.json",
    "contracts/fixtures/durable-preparation-v1/cases.json",
    "contracts/fixtures/durable-preparation-v1/expected-outcomes.json",
)
EXPECTED_REMOVAL_PACKAGES = {
    "helix-contracts",
    "helix-plan-eligibility",
    "helix-replay-sqlite",
    "helixos-kernel",
    "helixos-mcp-shim",
    "helixos-provision",
}
REMOVAL_BASELINE_COMMIT = "01a9181ef83539c0516139f8285551a9dfabc3b5"
REMOVAL_BASELINE_LOCK_SHA256 = (
    "f3b6c0cb07f9e9ddec2f6b64cb3b00f7df99fd93066315e92f1a5dfa4b3498f8"
)
REMOVAL_PROTECTED_PATHS = (
    "kernel/helix-contracts",
    "contracts/fixtures/plan-envelope-v1",
    "kernel/helix-plan-eligibility",
    "contracts/fixtures/plan-eligibility-v1",
    "kernel/helix-replay-sqlite",
    "contracts/fixtures/durable-replay-store-v1",
    "specs/003-durable-replay-store/contracts",
    "kernel/helixos-kernel",
    "kernel/helixos-mcp-shim",
    "kernel/helixos-provision",
)


class EvidenceError(RuntimeError):
    """Raised when evidence cannot be proven rather than guessed."""


@dataclass(frozen=True)
class SQLiteSource:
    version: str
    source_id: str
    source_sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid JSON evidence: {}: {}".format(path, error))


def run_checked(argv: List[str], cwd: Path) -> str:
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip()
        raise EvidenceError("command failed ({}): {}".format(" ".join(argv), message))
    return completed.stdout.strip()


def git_revision(repository: Path, revision: str = "HEAD") -> str:
    return run_checked(["git", "rev-parse", "{}^{{commit}}".format(revision)], repository)


def dependency_closure(metadata: dict, root_name: str) -> Set[str]:
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise EvidenceError("cargo metadata lacks packages or resolve graph")
    roots = [item.get("id") for item in packages if item.get("name") == root_name]
    if len(roots) != 1 or not isinstance(roots[0], str):
        raise EvidenceError("cargo metadata must contain exactly one {}".format(root_name))
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        raise EvidenceError("cargo metadata resolve graph lacks nodes")
    by_id = {item.get("id"): item for item in nodes if isinstance(item.get("id"), str)}
    visited: Set[str] = set()
    pending = [roots[0]]
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        node = by_id.get(package_id)
        if node is None:
            raise EvidenceError("cargo metadata lacks resolve node {}".format(package_id))
        visited.add(package_id)
        dependency_ids: List[str] = []
        detailed = node.get("deps")
        if isinstance(detailed, list) and detailed:
            for dependency in detailed:
                dependency_id = dependency.get("pkg")
                kinds = dependency.get("dep_kinds") or []
                production = any(
                    (kind.get("kind") or "normal") in {"normal", "build"}
                    for kind in kinds
                )
                if production and isinstance(dependency_id, str):
                    dependency_ids.append(dependency_id)
        else:
            dependency_ids = [
                item for item in node.get("dependencies", []) if isinstance(item, str)
            ]
        pending.extend(dependency_ids)
    return visited


def production_package_identities(
    metadata: dict, selected_ids: Set[str]
) -> Set[Tuple[str, str, str]]:
    identities: Set[Tuple[str, str, str]] = set()
    selected_packages = [
        package for package in metadata.get("packages", []) if package.get("id") in selected_ids
    ]
    if len(selected_packages) != len(selected_ids):
        raise EvidenceError("production closure references an unknown package")
    for package in selected_packages:
        name = package.get("name")
        version = package.get("version")
        source = package.get("source") or "workspace-path"
        if not all(isinstance(value, str) and value for value in (name, version, source)):
            raise EvidenceError("production package identity is incomplete")
        identity = (name, version, source)
        if identity in identities:
            raise EvidenceError("production package identity is duplicated")
        identities.add(identity)
    return identities


def production_dependency_adjacency(
    metadata: dict, selected_ids: Set[str]
) -> Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]]:
    packages = {
        package.get("id"): package
        for package in metadata.get("packages", [])
        if package.get("id") in selected_ids
    }
    identity_by_id = {
        package_id: (
            package.get("name"),
            package.get("version"),
            package.get("source") or "workspace-path",
        )
        for package_id, package in packages.items()
    }
    nodes = {
        node.get("id"): node
        for node in (metadata.get("resolve") or {}).get("nodes", [])
        if node.get("id") in selected_ids
    }
    if set(packages) != selected_ids or set(nodes) != selected_ids:
        raise EvidenceError("production adjacency lacks package or resolve nodes")
    result = {}
    for package_id in selected_ids:
        dependency_ids: Set[str] = set()
        detailed = nodes[package_id].get("deps")
        if isinstance(detailed, list) and detailed:
            for dependency in detailed:
                dependency_id = dependency.get("pkg")
                kinds = dependency.get("dep_kinds") or []
                if (
                    dependency_id in selected_ids
                    and any(
                        (kind.get("kind") or "normal") in {"normal", "build"}
                        for kind in kinds
                    )
                ):
                    dependency_ids.add(dependency_id)
        else:
            dependency_ids.update(
                dependency_id
                for dependency_id in nodes[package_id].get("dependencies", [])
                if dependency_id in selected_ids
            )
        result[identity_by_id[package_id]] = {
            identity_by_id[dependency_id] for dependency_id in dependency_ids
        }
    return result


def resolved_sqlite_features(metadata: dict, selected_ids: Set[str]) -> dict:
    packages = {
        package.get("id"): package
        for package in metadata.get("packages", [])
        if package.get("id") in selected_ids
    }
    nodes = {
        node.get("id"): node
        for node in (metadata.get("resolve") or {}).get("nodes", [])
        if node.get("id") in selected_ids
    }
    requirements = {
        ("rusqlite", EXPECTED_RUSQLITE_VERSION): {"backup", "bundled", "serialize"},
        ("libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION): {
            "bundled",
            "bundled_bindings",
            "cc",
        },
    }
    result = {}
    for (name, version), required in requirements.items():
        matches = [
            package_id
            for package_id, package in packages.items()
            if package.get("name") == name and package.get("version") == version
        ]
        if len(matches) != 1 or matches[0] not in nodes:
            raise EvidenceError("resolved graph lacks exact {} {} node".format(name, version))
        features = set(nodes[matches[0]].get("features") or [])
        missing = required - features
        if missing:
            raise EvidenceError(
                "resolved {} features lack {}".format(name, ", ".join(sorted(missing)))
            )
        result[name] = sorted(features)
    return result


def validate_audit_report(report: dict) -> None:
    for field in ("database", "lockfile", "vulnerabilities", "warnings"):
        if not isinstance(report.get(field), dict):
            raise EvidenceError("cargo-audit report lacks {} object".format(field))
    vulnerabilities = report["vulnerabilities"]
    listed = vulnerabilities.get("list")
    if not isinstance(listed, list):
        raise EvidenceError("cargo-audit vulnerabilities list is absent")
    count = vulnerabilities.get("count", len(listed))
    found = vulnerabilities.get("found", bool(listed))
    if found or count != 0 or listed:
        raise EvidenceError("RustSec vulnerabilities were found")
    for category, entries in report["warnings"].items():
        if entries in (None, [], {}):
            continue
        if not isinstance(entries, list):
            raise EvidenceError("cargo-audit warning category is malformed: {}".format(category))
        for entry in entries:
            warning_ids = set(
                re.findall(
                    r"RUSTSEC-[0-9]{4}-[0-9]{4}",
                    json.dumps(entry, sort_keys=True),
                )
            )
            if (
                category != "unmaintained"
                or len(warning_ids) != 1
                or not warning_ids.issubset(TRIAGED_RUSTSEC_WARNINGS)
            ):
                raise EvidenceError("RustSec report contains an untriaged warning")


def _component_names(sbom: dict) -> Dict[str, List[dict]]:
    components = sbom.get("components")
    if not isinstance(components, list):
        raise EvidenceError("CycloneDX document lacks components")
    result: Dict[str, List[dict]] = {}
    for component in components:
        name = component.get("name") if isinstance(component, dict) else None
        if isinstance(name, str):
            result.setdefault(name, []).append(component)
    return result


def _require_component(components: Dict[str, List[dict]], name: str, version: str) -> None:
    matches = components.get(name, [])
    if not any(item.get("version") == version for item in matches):
        raise EvidenceError("SBOM lacks {} {}".format(name, version))


def _walk_dicts(value: object) -> Iterable[dict]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            for item in _walk_dicts(child):
                yield item
    elif isinstance(value, list):
        for child in value:
            for item in _walk_dicts(child):
                yield item


def _stable_workspace_ref(component: dict, old_ref: str) -> str:
    name = component.get("name")
    version = component.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise EvidenceError("workspace SBOM component lacks stable name/version")
    suffix = old_ref.split("#", 1)[1] if "#" in old_ref else ""
    target = suffix[len(version) :].strip() if suffix.startswith(version) else suffix.strip()
    result = "urn:helixos:cargo-workspace:{}@{}".format(
        _safe_name(name), _safe_name(version)
    )
    if target:
        result += ":{}".format(_safe_name(target.replace(" ", "-")))
    return result


def _sanitize_local_purl(value: str) -> str:
    if "?" not in value:
        return value
    base, query = value.split("?", 1)
    qualifiers = [
        item
        for item in query.split("&")
        if not item.lower().startswith("download_url=file://")
    ]
    return base + (("?" + "&".join(qualifiers)) if qualifiers else "")


def sanitize_sbom_workspace_paths(sbom: dict) -> dict:
    result = copy.deepcopy(sbom)
    result.pop("serialNumber", None)
    metadata = result.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    references: Dict[str, str] = {}
    reverse: Dict[str, str] = {}
    for component in _walk_dicts(result):
        old_ref = component.get("bom-ref")
        if not isinstance(old_ref, str) or not old_ref.startswith("path+file://"):
            continue
        stable = _stable_workspace_ref(component, old_ref)
        conflicting = reverse.get(stable)
        if conflicting is not None and conflicting != old_ref:
            raise EvidenceError("workspace SBOM references collapse after sanitization")
        references[old_ref] = stable
        reverse[stable] = old_ref

    def rewrite(value: object) -> object:
        if isinstance(value, str):
            if value in references:
                return references[value]
            if value.startswith("pkg:cargo/") and "download_url=file://" in value.lower():
                return _sanitize_local_purl(value)
            return value
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        return value

    sanitized = rewrite(result)
    encoded = json.dumps(sanitized, sort_keys=True)
    if "path+file://" in encoded or "download_url=file://" in encoded.lower():
        raise EvidenceError("SBOM retains a machine-local workspace path")
    return sanitized


def augment_sbom(sbom: dict, sqlite: SQLiteSource) -> dict:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise EvidenceError("SBOM must be CycloneDX 1.5 JSON")
    result = sanitize_sbom_workspace_paths(sbom)
    components = _component_names(result)
    _require_component(components, "file-id", EXPECTED_FILE_ID_VERSION)
    _require_component(components, "rusqlite", EXPECTED_RUSQLITE_VERSION)
    _require_component(components, "libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION)
    if not any(name == "windows-sys" or name.startswith("windows_") for name in components):
        raise EvidenceError("SBOM lacks target-specific windows-sys components")
    if "SQLite" in components:
        raise EvidenceError("SBOM already contains an ambiguous SQLite component")
    native_ref = "pkg:generic/sqlite@{}".format(sqlite.version)
    native = {
        "bom-ref": native_ref,
        "type": "library",
        "name": "SQLite",
        "version": sqlite.version,
        "hashes": [{"alg": "SHA-256", "content": sqlite.source_sha256}],
        "licenses": [{"license": {"name": "Public Domain"}}],
        "purl": native_ref,
        "properties": [
            {"name": "helixos:bundled-by", "value": "libsqlite3-sys-0.38.1"},
            {"name": "helixos:sqlite-source-id", "value": sqlite.source_id},
        ],
    }
    result["components"].append(native)
    result["components"].sort(
        key=lambda item: (
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("bom-ref", "")),
        )
    )
    dependencies = result.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise EvidenceError("CycloneDX dependencies must be a list")
    libsqlite = next(
        item
        for item in result["components"]
        if item.get("name") == "libsqlite3-sys"
        and item.get("version") == EXPECTED_LIBSQLITE_VERSION
    )
    libsqlite_ref = libsqlite.get("bom-ref")
    if isinstance(libsqlite_ref, str):
        dependency = next(
            (item for item in dependencies if item.get("ref") == libsqlite_ref),
            None,
        )
        if dependency is None:
            dependency = {"ref": libsqlite_ref, "dependsOn": []}
            dependencies.append(dependency)
        depends_on = dependency.setdefault("dependsOn", [])
        if native_ref not in depends_on:
            depends_on.append(native_ref)
            depends_on.sort()
    if not any(item.get("ref") == native_ref for item in dependencies):
        dependencies.append({"ref": native_ref, "dependsOn": []})
    dependencies.sort(key=lambda item: str(item.get("ref", "")))
    return result


def validate_retained_sbom(
    sbom: dict,
    sqlite: SQLiteSource,
    expected_identities: Set[Tuple[str, str, str]],
    expected_adjacency: Dict[
        Tuple[str, str, str], Set[Tuple[str, str, str]]
    ],
) -> None:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise EvidenceError("retained SBOM is not CycloneDX 1.5")
    if "serialNumber" in sbom or "timestamp" in (sbom.get("metadata") or {}):
        raise EvidenceError("retained SBOM contains volatile UUID/timestamp metadata")
    components = sbom.get("components")
    metadata_component = (sbom.get("metadata") or {}).get("component")
    dependencies = sbom.get("dependencies")
    if (
        not isinstance(components, list)
        or not isinstance(metadata_component, dict)
        or not isinstance(dependencies, list)
    ):
        raise EvidenceError("retained SBOM lacks component/dependency structure")
    encoded = json.dumps(sbom, sort_keys=True)
    if "path+file://" in encoded or "download_url=file://" in encoded.lower():
        raise EvidenceError("retained SBOM exposes a workspace path")

    native = [
        component
        for component in components
        if component.get("name") == "SQLite"
        and component.get("version") == sqlite.version
    ]
    if len(native) != 1:
        raise EvidenceError("retained SBOM lacks one exact bundled SQLite component")
    native_component = native[0]
    native_ref = native_component.get("bom-ref")
    if native_component.get("hashes") != [
        {"alg": "SHA-256", "content": sqlite.source_sha256}
    ]:
        raise EvidenceError("retained SBOM SQLite source digest mismatch")
    properties = native_component.get("properties") or []
    if {
        "name": "helixos:sqlite-source-id",
        "value": sqlite.source_id,
    } not in properties:
        raise EvidenceError("retained SBOM SQLite source ID mismatch")

    cargo_components = [metadata_component] + [
        component for component in components if component is not native_component
    ]
    actual_pairs: Set[Tuple[str, str]] = set()
    references: Set[str] = set()
    for component in cargo_components + [native_component]:
        name = component.get("name")
        version = component.get("version")
        reference = component.get("bom-ref")
        if not isinstance(name, str) or not isinstance(version, str):
            raise EvidenceError("retained SBOM component identity is incomplete")
        if not isinstance(reference, str) or not reference or reference in references:
            raise EvidenceError("retained SBOM component reference is missing or duplicated")
        references.add(reference)
        if component is not native_component:
            pair = (name, version)
            if pair in actual_pairs:
                raise EvidenceError("retained SBOM cargo component is duplicated")
            actual_pairs.add(pair)
    expected_pairs = {(name, version) for name, version, _source in expected_identities}
    if len(expected_pairs) != len(expected_identities):
        raise EvidenceError("production closure has ambiguous name/version identities")
    expected_identity_by_pair = {
        (name, version): (name, version, source)
        for name, version, source in expected_identities
    }
    if actual_pairs != expected_pairs:
        missing = sorted(expected_pairs - actual_pairs)
        extra = sorted(actual_pairs - expected_pairs)
        raise EvidenceError(
            "retained SBOM production closure mismatch (missing={}, extra={})".format(
                missing, extra
            )
        )

    dependency_by_ref = {}
    for dependency in dependencies:
        reference = dependency.get("ref") if isinstance(dependency, dict) else None
        depends_on = dependency.get("dependsOn", []) if isinstance(dependency, dict) else None
        if (
            not isinstance(reference, str)
            or reference in dependency_by_ref
            or not isinstance(depends_on, list)
            or any(item not in references for item in depends_on)
        ):
            raise EvidenceError("retained SBOM dependency graph is malformed")
        dependency_by_ref[reference] = depends_on
    if set(dependency_by_ref) != references:
        raise EvidenceError("retained SBOM dependency nodes do not cover every component")
    libsqlite = next(
        component
        for component in cargo_components
        if component.get("name") == "libsqlite3-sys"
        and component.get("version") == EXPECTED_LIBSQLITE_VERSION
    )
    if native_ref not in dependency_by_ref.get(libsqlite["bom-ref"], []):
        raise EvidenceError("retained SBOM does not bind libsqlite3-sys to SQLite source")
    ref_to_pair = {
        component["bom-ref"]: (component["name"], component["version"])
        for component in cargo_components
    }
    if set(expected_adjacency) != expected_identities:
        raise EvidenceError("expected production dependency adjacency is incomplete")
    native_pair = ("SQLite", sqlite.version)
    for reference, pair in ref_to_pair.items():
        identity = expected_identity_by_pair[pair]
        expected_targets = {
            (name, version) for name, version, _source in expected_adjacency[identity]
        }
        if pair == ("libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION):
            expected_targets.add(native_pair)
        actual_targets = {
            native_pair if target == native_ref else ref_to_pair[target]
            for target in dependency_by_ref[reference]
        }
        if actual_targets != expected_targets:
            raise EvidenceError(
                "retained SBOM dependency adjacency mismatch for {} {}".format(*pair)
            )
    if dependency_by_ref[native_ref]:
        raise EvidenceError("retained native SQLite dependency node must be a leaf")


def _manifest_files(root: Path) -> List[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EvidenceError("evidence bundle contains symlink: {}".format(path))
        if path.is_file() and path.name != MANIFEST_NAME:
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def write_sha256_manifest(root: Path) -> Path:
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lines = [
        "{}  {}".format(sha256_file(path), path.relative_to(root).as_posix())
        for path in _manifest_files(root)
    ]
    manifest = root / MANIFEST_NAME
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest


def verify_sha256_manifest(root: Path) -> None:
    root = root.resolve()
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        raise EvidenceError("evidence bundle lacks {}".format(MANIFEST_NAME))
    entries: Dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            raise EvidenceError("malformed SHA-256 manifest line")
        digest, relative = match.groups()
        if relative in entries or relative.startswith("/") or ".." in Path(relative).parts:
            raise EvidenceError("unsafe or duplicate manifest path: {}".format(relative))
        entries[relative] = digest
    if list(entries) != sorted(entries):
        raise EvidenceError("SHA-256 manifest is not sorted")
    actual = {
        path.relative_to(root).as_posix(): path for path in _manifest_files(root)
    }
    if set(actual) != set(entries):
        raise EvidenceError("SHA-256 manifest file set mismatch")
    for relative, path in actual.items():
        if sha256_file(path) != entries[relative]:
            raise EvidenceError("digest mismatch for {}".format(relative))


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._+-]", "_", value)
    if not cleaned or cleaned in {".", ".."}:
        raise EvidenceError("unsafe evidence filename")
    return cleaned


def _lock_value(raw: str) -> str:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError("unsupported Cargo.lock string: {}".format(error))
    if not isinstance(value, str):
        raise EvidenceError("Cargo.lock field is not a string")
    return value


def parse_lock_packages(text: str) -> Dict[Tuple[str, str, str], str]:
    records: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for line in text.splitlines():
        if line == "[[package]]":
            if current is not None:
                records.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = re.fullmatch(r"(name|version|source|checksum) = (\".*\")", line)
        if match:
            current[match.group(1)] = _lock_value(match.group(2))
    if current is not None:
        records.append(current)
    result: Dict[Tuple[str, str, str], str] = {}
    for record in records:
        if "source" not in record:
            continue
        required = {"name", "version", "source", "checksum"}
        if not required.issubset(record):
            raise EvidenceError("registry Cargo.lock package lacks identity/checksum")
        key = (record["name"], record["version"], record["source"])
        if key in result:
            raise EvidenceError("duplicate Cargo.lock package identity")
        result[key] = record["checksum"]
    return result


def _license_files(package_root: Path) -> List[Path]:
    prefixes = ("license", "licence", "copying", "notice", "unlicense")
    result = []
    for path in package_root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        relative = path.relative_to(package_root)
        if any(part in {".git", "target"} for part in relative.parts):
            continue
        if path.name.lower().startswith(prefixes):
            result.append(path)
    return sorted(result, key=lambda path: path.relative_to(package_root).as_posix())


def _spdx_ids(expression: str) -> List[str]:
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
    return sorted({token for token in tokens if token.upper() not in {"AND", "OR", "WITH"}})


def _copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise EvidenceError("required evidence source is missing: {}".format(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(source), str(destination))


def _bundle_relative(path: Path, bundle: Path) -> str:
    return path.relative_to(bundle).as_posix()


def _find_crate_archive(manifest: Path, name: str, version: str) -> Path:
    source_root = manifest.parent.parent
    if source_root.parent.name != "src":
        raise EvidenceError("package is not in a standard Cargo registry source cache")
    registry = source_root.parent.parent
    archive = registry / "cache" / source_root.name / "{}-{}.crate".format(name, version)
    if not archive.is_file():
        raise EvidenceError("Cargo registry archive is absent: {}".format(archive.name))
    return archive


def _copy_license_evidence(
    metadata: dict,
    selected_ids: Set[str],
    cargo_lock: Path,
    spdx_root: Path,
    bundle: Path,
) -> dict:
    packages = {item["id"]: item for item in metadata["packages"]}
    lock_checksums = parse_lock_packages(cargo_lock.read_text(encoding="utf-8"))
    inventory = []
    copied_spdx: Set[str] = set()
    external_count = 0
    for package_id in sorted(
        selected_ids,
        key=lambda value: (
            packages[value].get("name", ""),
            packages[value].get("version", ""),
            packages[value].get("source") or "",
        ),
    ):
        package = packages[package_id]
        name = package["name"]
        version = package["version"]
        source = package.get("source")
        manifest = Path(package["manifest_path"]).resolve()
        entry = {
            "name": name,
            "version": version,
            "scope": "production",
            "source": source or "workspace-path",
            "license_expression": package.get("license") or "NOASSERTION",
            "retained_files": [],
        }
        if source:
            external_count += 1
            expression = package.get("license")
            if not isinstance(expression, str) or not expression.strip():
                raise EvidenceError("external package lacks license expression: {}".format(name))
            checksum = lock_checksums.get((name, version, source))
            if not checksum:
                raise EvidenceError("external package lacks locked checksum: {} {}".format(name, version))
            entry["cargo_lock_checksum_sha256"] = checksum
            package_root = manifest.parent
            destination_root = bundle / "licenses" / "packages" / _safe_name(
                "{}-{}".format(name, version)
            )
            retained_sources = [manifest]
            retained_sources.extend(_license_files(package_root))
            readme = package.get("readme")
            if isinstance(readme, str):
                readme_path = Path(readme)
                if readme_path.is_file() and readme_path not in retained_sources:
                    retained_sources.append(readme_path)
            for source_file in sorted(
                set(retained_sources),
                key=lambda path: path.relative_to(package_root).as_posix(),
            ):
                relative = source_file.relative_to(package_root)
                destination = destination_root / relative
                _copy_file(source_file, destination)
                entry["retained_files"].append(
                    {
                        "path": _bundle_relative(destination, bundle),
                        "sha256": sha256_file(destination),
                    }
                )
            for identifier in _spdx_ids(expression):
                text_path = spdx_root / "text" / "{}.txt".format(identifier)
                kind = "text"
                if not text_path.is_file():
                    text_path = spdx_root / "exceptions" / "{}.txt".format(identifier)
                    kind = "exceptions"
                if not text_path.is_file():
                    raise EvidenceError(
                        "SPDX license-list checkout lacks text for {} ({})".format(
                            identifier, expression
                        )
                    )
                key = "{}/{}".format(kind, text_path.name)
                destination = bundle / "licenses" / "spdx" / key
                if key not in copied_spdx:
                    _copy_file(text_path, destination)
                    copied_spdx.add(key)
        else:
            entry["manifest_sha256"] = sha256_file(manifest)
        inventory.append(entry)
    spdx_texts = []
    for key in sorted(copied_spdx):
        path = bundle / "licenses" / "spdx" / key
        spdx_texts.append(
            {
                "identifier": path.stem,
                "kind": path.parent.name,
                "path": _bundle_relative(path, bundle),
                "sha256": sha256_file(path),
            }
        )
    result = {
        "schema": "helixos.plan-004-license-inventory/1",
        "root_package": "helix-coordinator-sqlite",
        "scope": "normal-and-build-dependency-closure-with-all-targets",
        "package_count": len(inventory),
        "external_package_count": external_count,
        "workspace_package_count": len(inventory) - external_count,
        "spdx_license_list_revision": EXPECTED_SPDX_REVISION,
        "spdx_texts": spdx_texts,
        "packages": inventory,
    }
    write_json(bundle / "licenses" / "inventory.json", result)
    return result


def _sqlite_source(metadata: dict, selected_ids: Set[str]) -> Tuple[dict, Path, Path, Path]:
    packages = [
        item
        for item in metadata["packages"]
        if item["id"] in selected_ids
        and item.get("name") == "libsqlite3-sys"
        and item.get("version") == EXPECTED_LIBSQLITE_VERSION
    ]
    if len(packages) != 1:
        raise EvidenceError("production closure lacks exact libsqlite3-sys package")
    package = packages[0]
    package_root = Path(package["manifest_path"]).resolve().parent
    source = package_root / "sqlite3" / "sqlite3.c"
    header = package_root / "sqlite3" / "sqlite3.h"
    if not source.is_file() or not header.is_file():
        raise EvidenceError("bundled SQLite amalgamation is absent")
    text = source.read_text(encoding="utf-8", errors="strict")
    source_match = re.search(r'#define SQLITE_SOURCE_ID\s+"([^"]+)"', text)
    version_match = re.search(r'#define SQLITE_VERSION\s+"([^"]+)"', text)
    if not source_match or source_match.group(1) != EXPECTED_SQLITE_SOURCE_ID:
        raise EvidenceError("bundled SQLite source ID mismatch")
    if not version_match or version_match.group(1) != EXPECTED_SQLITE_VERSION:
        raise EvidenceError("bundled SQLite version mismatch")
    archive = _find_crate_archive(
        Path(package["manifest_path"]), "libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION
    )
    return package, source, header, archive


def _copy_required_inputs(repository: Path, bundle: Path) -> List[dict]:
    result = []
    for relative in REVIEWED_INPUT_PATHS:
        source = repository / relative
        destination = bundle / "reviewed-inputs" / relative
        _copy_file(source, destination)
        result.append({"path": relative, "sha256": sha256_file(destination)})
    return result


def _copy_local_m4(repository: Path, bundle: Path) -> List[dict]:
    evidence = repository / "specs" / "004-durable-preparation" / "evidence"
    result = []
    for filename, expected_digest in LOCAL_M4_ARTIFACTS:
        source = evidence / filename
        if sha256_file(source) != expected_digest:
            raise EvidenceError("local-only physical M4 artifact digest changed")
        destination = bundle / "local-only-physical-m4" / filename
        _copy_file(source, destination)
        result.append(
            {
                "path": _bundle_relative(destination, bundle),
                "sha256": expected_digest,
                "status": "local-only-not-immutable-not-power-loss",
            }
        )
    return result


def _copy_tool_output(
    source: Path,
    destination: Path,
    replacements: Iterable[Tuple[str, str]] = (),
) -> str:
    text = source.read_text(encoding="utf-8").replace("\r\n", "\n")
    for raw, replacement in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if raw:
            text = text.replace(raw, replacement)
            text = text.replace(raw.replace("/", "\\"), replacement)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    return text.strip()


def _require_tool_version(text: str, tool: str, expected: str) -> None:
    executable_names = {tool, "{}-{}".format(tool, tool.rsplit("-", 1)[-1])}
    if not any(
        re.search(
            r"(?:^|\s){}\s+v?{}(?:\s|$)".format(
                re.escape(name), re.escape(expected)
            ),
            text,
        )
        for name in executable_names
    ):
        raise EvidenceError("{} version is not pinned to {}".format(tool, expected))


def _assert_clean_tracked_checkout(repository: Path) -> None:
    for argv in (["git", "diff", "--quiet"], ["git", "diff", "--cached", "--quiet"]):
        completed = subprocess.run(argv, cwd=str(repository), check=False)
        if completed.returncode != 0:
            raise EvidenceError("tracked checkout is not clean")


def _require_provenance_value(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip() or value.strip().lower() in {
        "none",
        "null",
        "unknown",
        "unset",
    }:
        raise EvidenceError("{} provenance is unavailable".format(label))


def build_bundle(args: argparse.Namespace) -> None:
    repository = Path(args.repository).resolve()
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    source_commit = git_revision(repository)
    if source_commit != args.source_commit:
        raise EvidenceError("source commit does not match checkout HEAD")
    _assert_clean_tracked_checkout(repository)
    for label, value in (
        ("artifact name", args.artifact_name),
        ("GitHub repository", args.github_repository),
        ("workflow ref", args.workflow_ref),
        ("run ID", args.run_id),
        ("run attempt", args.run_attempt),
        ("runner OS", args.runner_os),
        ("runner architecture", args.runner_arch),
        ("runner name", args.runner_name),
        ("runner image OS", args.image_os),
        ("runner image version", args.image_version),
        ("source timestamp", args.source_timestamp),
        ("scan timestamp", args.scan_timestamp),
    ):
        _require_provenance_value(label, value)

    metadata = load_json(Path(args.metadata))
    audit = load_json(Path(args.audit_report))
    sbom = load_json(Path(args.sbom))
    if not isinstance(metadata, dict) or not isinstance(audit, dict) or not isinstance(sbom, dict):
        raise EvidenceError("supply-chain inputs must be JSON objects")
    validate_audit_report(audit)
    selected_ids = dependency_closure(metadata, "helix-coordinator-sqlite")
    selected_identities = production_package_identities(metadata, selected_ids)
    selected_adjacency = production_dependency_adjacency(metadata, selected_ids)

    advisory_db = Path(args.advisory_db).resolve()
    advisory_revision = git_revision(advisory_db)
    if advisory_revision != EXPECTED_RUSTSEC_REVISION:
        raise EvidenceError("RustSec advisory database revision mismatch")
    advisory_timestamp = run_checked(
        ["git", "show", "-s", "--format=%cI", advisory_revision], advisory_db
    )
    spdx_root = Path(args.spdx_license_list).resolve()
    if git_revision(spdx_root) != EXPECTED_SPDX_REVISION:
        raise EvidenceError("SPDX license-list-data revision mismatch")

    tool_sources = {
        "rustc-version.txt": Path(args.rustc_version),
        "cargo-version.txt": Path(args.cargo_version),
        "cargo-cyclonedx-version.txt": Path(args.cargo_cyclonedx_version),
        "cargo-audit-version.txt": Path(args.cargo_audit_version),
        "python-version.txt": Path(args.python_version),
        "tool-binary-digests.txt": Path(args.tool_binary_digests),
        "cargo-tree.txt": Path(args.cargo_tree),
    }
    tool_text: Dict[str, str] = {}
    machine_path_replacements = (
        (str(repository), "<repo>"),
        (str(Path.home()), "<home>"),
    )
    for filename, source in tool_sources.items():
        tool_text[filename] = _copy_tool_output(
            source,
            output / "toolchain" / filename,
            machine_path_replacements,
        )
    if "rustc 1.96.1 " not in tool_text["rustc-version.txt"]:
        raise EvidenceError("Rust compiler is not pinned to 1.96.1")
    if "cargo 1.96.1 " not in tool_text["cargo-version.txt"]:
        raise EvidenceError("Cargo is not pinned to 1.96.1")
    _require_tool_version(
        tool_text["cargo-cyclonedx-version.txt"],
        "cargo-cyclonedx",
        EXPECTED_CYCLONEDX_VERSION,
    )
    _require_tool_version(
        tool_text["cargo-audit-version.txt"], "cargo-audit", EXPECTED_AUDIT_VERSION
    )

    sqlite_features = resolved_sqlite_features(metadata, selected_ids)
    sqlite_package, sqlite_c, sqlite_h, sqlite_archive = _sqlite_source(
        metadata, selected_ids
    )
    source_digest = sha256_file(sqlite_c)
    sqlite = SQLiteSource(
        EXPECTED_SQLITE_VERSION, EXPECTED_SQLITE_SOURCE_ID, source_digest
    )
    augmented = augment_sbom(sbom, sqlite)
    validate_retained_sbom(
        augmented, sqlite, selected_identities, selected_adjacency
    )
    write_json(output / "sbom" / "plan-004-sbom.cdx.json", augmented)

    cargo_lock = repository / "kernel" / "Cargo.lock"
    lock_package_count = len(re.findall(r"(?m)^\[\[package\]\]$", cargo_lock.read_text(encoding="utf-8")))
    if audit["lockfile"].get("dependency-count") != lock_package_count:
        raise EvidenceError("RustSec locked dependency count does not match Cargo.lock")
    inventory = _copy_license_evidence(
        metadata, selected_ids, cargo_lock, spdx_root, output
    )
    lock_checksums = parse_lock_packages(cargo_lock.read_text(encoding="utf-8"))
    archive_checksum = lock_checksums.get(
        (
            "libsqlite3-sys",
            EXPECTED_LIBSQLITE_VERSION,
            sqlite_package["source"],
        )
    )
    if not archive_checksum or sha256_file(sqlite_archive) != archive_checksum:
        raise EvidenceError("libsqlite3-sys crate archive does not match Cargo.lock")
    native_files = (
        (sqlite_archive, output / "native" / sqlite_archive.name),
        (sqlite_c, output / "native" / "sqlite3.c"),
        (sqlite_h, output / "native" / "sqlite3.h"),
    )
    for source, destination in native_files:
        _copy_file(source, destination)
    native_metadata = {
        "schema": "helixos.plan-004-native-sqlite/1",
        "libsqlite3_sys_version": EXPECTED_LIBSQLITE_VERSION,
        "libsqlite3_sys_crate_sha256": archive_checksum,
        "sqlite_version": EXPECTED_SQLITE_VERSION,
        "sqlite_source_id": EXPECTED_SQLITE_SOURCE_ID,
        "sqlite3_c_sha256": source_digest,
        "sqlite3_h_sha256": sha256_file(sqlite_h),
        "link_profile": "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static",
        "resolved_features": sqlite_features,
        "license": "Public Domain notice embedded in retained sqlite3.c/sqlite3.h",
    }
    write_json(output / "native" / "sqlite3-source-metadata.json", native_metadata)

    _copy_file(Path(args.audit_report), output / "rustsec" / "report.json")
    _copy_tool_output(
        Path(args.audit_stderr),
        output / "rustsec" / "stderr.txt",
        machine_path_replacements,
    )
    write_json(
        output / "rustsec" / "database.json",
        {
            "schema": "helixos.rustsec-database-evidence/1",
            "cargo_audit_version": EXPECTED_AUDIT_VERSION,
            "database_revision": advisory_revision,
            "database_commit_timestamp": advisory_timestamp,
            "scan_timestamp": args.scan_timestamp,
            "command": [
                "cargo",
                "audit",
                "--db",
                "<pinned-rustsec-db>",
                "--no-fetch",
                "--file",
                "kernel/Cargo.lock",
                "--json",
            ],
            "result": "zero-vulnerabilities-warnings-retained",
        },
    )
    reviewed_inputs = _copy_required_inputs(repository, output)
    local_m4 = _copy_local_m4(repository, output)
    workflow_path = repository / ".github" / "workflows" / "durable-preparation.yml"
    descriptor = {
        "schema": SCHEMA,
        "acceptance_id": "PLAN-004",
        "claim_status": "pending-until-catalogued-overall-remains-pending-evidence",
        "artifact_binding": {
            "artifact_name": args.artifact_name,
            "archive_digest": "published-after-upload",
            "attestation_subject": "actions/upload-artifact artifact-digest output",
        },
        "source": {
            "repository": args.github_repository,
            "commit": source_commit,
            "commit_timestamp": args.source_timestamp,
            "tracked_checkout_clean": True,
        },
        "workflow": {
            "path": ".github/workflows/durable-preparation.yml",
            "sha256": sha256_file(workflow_path),
            "ref": args.workflow_ref,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
        },
        "runner": {
            "os": args.runner_os,
            "arch": args.runner_arch,
            "name": args.runner_name,
            "image_os": args.image_os,
            "image_version": args.image_version,
        },
        "toolchain": {
            "rust": "1.96.1",
            "cargo_cyclonedx": EXPECTED_CYCLONEDX_VERSION,
            "cargo_audit": EXPECTED_AUDIT_VERSION,
            "rustsec_database_revision": advisory_revision,
            "spdx_license_list_revision": EXPECTED_SPDX_REVISION,
        },
        "supply_chain": {
            "sbom": "sbom/plan-004-sbom.cdx.json",
            "sbom_format": "CycloneDX 1.5 JSON; all targets; bundled SQLite added",
            "license_inventory": "licenses/inventory.json",
            "production_package_count": inventory["package_count"],
            "external_package_count": inventory["external_package_count"],
            "rustsec_report": "rustsec/report.json",
            "rustsec_stderr": "rustsec/stderr.txt",
            "rustsec_result": "zero-vulnerabilities-warnings-retained",
            "native_sqlite": native_metadata,
        },
        "reviewed_inputs": reviewed_inputs,
        "physical_m4_artifacts": local_m4,
    }
    write_json(output / "descriptor.json", descriptor)
    write_sha256_manifest(output)
    verify_bundle(output, repository, require_removal=False)


def _text_files(root: Path) -> Iterable[Path]:
    for path in _manifest_files(root):
        if path.stat().st_size > 12 * 1024 * 1024:
            continue
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue
        yield path


def _bundle_file(root: Path, relative: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or relative.startswith("/")
        or ".." in Path(relative).parts
    ):
        raise EvidenceError("unsafe retained evidence path")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise EvidenceError("retained evidence path escapes bundle")
    if not candidate.is_file():
        raise EvidenceError("retained evidence file is absent: {}".format(relative))
    return candidate


def _current_metadata(repository: Path) -> Tuple[dict, Set[str], Set[Tuple[str, str, str]]]:
    raw = run_checked(
        [
            "cargo",
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
            "--manifest-path",
            "kernel/Cargo.toml",
        ],
        repository,
    )
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError("current cargo metadata is invalid: {}".format(error))
    selected_ids = dependency_closure(metadata, "helix-coordinator-sqlite")
    return metadata, selected_ids, production_package_identities(metadata, selected_ids)


def _validate_toolchain_files(root: Path) -> None:
    rustc = _bundle_file(root, "toolchain/rustc-version.txt").read_text(encoding="utf-8")
    cargo = _bundle_file(root, "toolchain/cargo-version.txt").read_text(encoding="utf-8")
    cyclonedx = _bundle_file(
        root, "toolchain/cargo-cyclonedx-version.txt"
    ).read_text(encoding="utf-8")
    audit = _bundle_file(root, "toolchain/cargo-audit-version.txt").read_text(
        encoding="utf-8"
    )
    _bundle_file(root, "toolchain/python-version.txt")
    _bundle_file(root, "toolchain/cargo-tree.txt")
    if "rustc 1.96.1 " not in rustc or "cargo 1.96.1 " not in cargo:
        raise EvidenceError("retained Rust/Cargo version is not pinned")
    _require_tool_version(cyclonedx, "cargo-cyclonedx", EXPECTED_CYCLONEDX_VERSION)
    _require_tool_version(audit, "cargo-audit", EXPECTED_AUDIT_VERSION)
    digest_lines = _bundle_file(
        root, "toolchain/tool-binary-digests.txt"
    ).read_text(encoding="utf-8").splitlines()
    parsed = {}
    for line in digest_lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (cargo-cyclonedx|cargo-audit)", line)
        if not match or match.group(2) in parsed:
            raise EvidenceError("retained tool binary digests are malformed")
        parsed[match.group(2)] = match.group(1)
    if set(parsed) != {"cargo-cyclonedx", "cargo-audit"}:
        raise EvidenceError("retained tool binary digests are incomplete")


def _validate_reviewed_inputs(root: Path, repository: Path, descriptor: dict) -> None:
    entries = descriptor.get("reviewed_inputs")
    if not isinstance(entries, list):
        raise EvidenceError("release descriptor lacks reviewed inputs")
    indexed = {}
    for entry in entries:
        relative = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(relative, str)
            or relative in indexed
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise EvidenceError("release descriptor reviewed input is malformed")
        indexed[relative] = digest
    if set(indexed) != set(REVIEWED_INPUT_PATHS):
        raise EvidenceError("release descriptor reviewed input set is incomplete")
    for relative, digest in indexed.items():
        retained = _bundle_file(root, "reviewed-inputs/{}".format(relative))
        source = repository / relative
        if not source.is_file():
            raise EvidenceError("current reviewed input is absent: {}".format(relative))
        if sha256_file(retained) != digest or sha256_file(source) != digest:
            raise EvidenceError("reviewed input digest mismatch: {}".format(relative))


def _validate_license_inventory(
    root: Path,
    inventory: dict,
    metadata: dict,
    expected_identities: Set[Tuple[str, str, str]],
    repository: Path,
) -> None:
    if (
        inventory.get("schema") != "helixos.plan-004-license-inventory/1"
        or inventory.get("root_package") != "helix-coordinator-sqlite"
        or inventory.get("spdx_license_list_revision") != EXPECTED_SPDX_REVISION
    ):
        raise EvidenceError("license inventory identity is invalid")
    packages = inventory.get("packages")
    if not isinstance(packages, list):
        raise EvidenceError("license inventory package list is absent")
    package_by_identity = {}
    external_count = 0
    required_spdx: Set[str] = set()
    retained_package_files: Set[str] = set()
    lock_checksums = parse_lock_packages(
        (repository / "kernel" / "Cargo.lock").read_text(encoding="utf-8")
    )
    metadata_packages = {
        (
            package.get("name"),
            package.get("version"),
            package.get("source") or "workspace-path",
        ): package
        for package in metadata.get("packages", [])
    }
    for entry in packages:
        if not isinstance(entry, dict):
            raise EvidenceError("license inventory package entry is malformed")
        identity = (
            entry.get("name"),
            entry.get("version"),
            entry.get("source"),
        )
        if identity in package_by_identity or identity not in expected_identities:
            raise EvidenceError("license inventory package identity is unknown or duplicated")
        package_by_identity[identity] = entry
        if entry.get("scope") != "production":
            raise EvidenceError("license inventory package scope is not production")
        if identity[2] == "workspace-path":
            manifest = Path(metadata_packages[identity]["manifest_path"])
            if entry.get("manifest_sha256") != sha256_file(manifest):
                raise EvidenceError("workspace manifest digest mismatch in license inventory")
            if entry.get("retained_files") != []:
                raise EvidenceError("workspace license entry unexpectedly retains registry files")
            continue
        external_count += 1
        expression = entry.get("license_expression")
        if not isinstance(expression, str) or not expression or expression == "NOASSERTION":
            raise EvidenceError("external license expression is absent")
        required_spdx.update(_spdx_ids(expression))
        expected_checksum = lock_checksums.get(identity)
        if entry.get("cargo_lock_checksum_sha256") != expected_checksum:
            raise EvidenceError("license inventory Cargo.lock checksum mismatch")
        retained = entry.get("retained_files")
        if not isinstance(retained, list) or not retained:
            raise EvidenceError("external license/source files are absent")
        for retained_entry in retained:
            relative = retained_entry.get("path") if isinstance(retained_entry, dict) else None
            digest = retained_entry.get("sha256") if isinstance(retained_entry, dict) else None
            if (
                not isinstance(relative, str)
                or not relative.startswith("licenses/packages/")
                or relative in retained_package_files
                or not isinstance(digest, str)
            ):
                raise EvidenceError("retained package license file entry is malformed")
            path = _bundle_file(root, relative)
            if sha256_file(path) != digest:
                raise EvidenceError("retained package license file digest mismatch")
            retained_package_files.add(relative)
    if set(package_by_identity) != expected_identities:
        raise EvidenceError("license inventory does not cover production closure")
    if (
        inventory.get("package_count") != len(packages)
        or inventory.get("external_package_count") != external_count
        or inventory.get("workspace_package_count") != len(packages) - external_count
    ):
        raise EvidenceError("license inventory counts are inconsistent")
    actual_package_files = {
        path.relative_to(root).as_posix()
        for path in (root / "licenses" / "packages").rglob("*")
        if path.is_file()
    }
    if actual_package_files != retained_package_files:
        raise EvidenceError("retained package license file set is inconsistent")

    spdx_entries = inventory.get("spdx_texts")
    if not isinstance(spdx_entries, list):
        raise EvidenceError("license inventory SPDX texts are absent")
    spdx_ids: Set[str] = set()
    spdx_paths: Set[str] = set()
    for entry in spdx_entries:
        identifier = entry.get("identifier") if isinstance(entry, dict) else None
        relative = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        kind = entry.get("kind") if isinstance(entry, dict) else None
        if (
            not isinstance(identifier, str)
            or identifier in spdx_ids
            or kind not in {"text", "exceptions"}
            or not isinstance(relative, str)
            or relative in spdx_paths
            or not isinstance(digest, str)
        ):
            raise EvidenceError("SPDX text inventory entry is malformed")
        path = _bundle_file(root, relative)
        if path.stem != identifier or path.parent.name != kind or sha256_file(path) != digest:
            raise EvidenceError("SPDX text identity or digest mismatch")
        spdx_ids.add(identifier)
        spdx_paths.add(relative)
    if spdx_ids != required_spdx:
        raise EvidenceError("SPDX texts do not cover every license expression")
    actual_spdx_paths = {
        path.relative_to(root).as_posix()
        for path in (root / "licenses" / "spdx").rglob("*")
        if path.is_file()
    }
    if actual_spdx_paths != spdx_paths:
        raise EvidenceError("retained SPDX text file set is inconsistent")


def _validate_native_evidence(
    root: Path,
    native: dict,
    metadata: dict,
    selected_ids: Set[str],
    repository: Path,
) -> SQLiteSource:
    sqlite_c = _bundle_file(root, "native/sqlite3.c")
    sqlite_h = _bundle_file(root, "native/sqlite3.h")
    archive = _bundle_file(root, "native/libsqlite3-sys-0.38.1.crate")
    if (
        native.get("schema") != "helixos.plan-004-native-sqlite/1"
        or native.get("libsqlite3_sys_version") != EXPECTED_LIBSQLITE_VERSION
        or native.get("sqlite_version") != EXPECTED_SQLITE_VERSION
        or native.get("sqlite_source_id") != EXPECTED_SQLITE_SOURCE_ID
        or native.get("link_profile")
        != "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static"
    ):
        raise EvidenceError("retained native SQLite identity is invalid")
    if (
        native.get("sqlite3_c_sha256") != sha256_file(sqlite_c)
        or native.get("sqlite3_h_sha256") != sha256_file(sqlite_h)
    ):
        raise EvidenceError("retained SQLite source/header digest mismatch")
    source_text = sqlite_c.read_text(encoding="utf-8")
    if EXPECTED_SQLITE_SOURCE_ID not in source_text or (
        '#define SQLITE_VERSION        "{}"'.format(EXPECTED_SQLITE_VERSION)
        not in source_text
    ):
        raise EvidenceError("retained SQLite amalgamation identity mismatch")
    libsqlite_packages = [
        package
        for package in metadata.get("packages", [])
        if package.get("id") in selected_ids
        and package.get("name") == "libsqlite3-sys"
        and package.get("version") == EXPECTED_LIBSQLITE_VERSION
    ]
    if len(libsqlite_packages) != 1:
        raise EvidenceError("current graph lacks one exact libsqlite3-sys package")
    package = libsqlite_packages[0]
    expected_archive = parse_lock_packages(
        (repository / "kernel" / "Cargo.lock").read_text(encoding="utf-8")
    ).get(("libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION, package.get("source")))
    if (
        not expected_archive
        or native.get("libsqlite3_sys_crate_sha256") != expected_archive
        or sha256_file(archive) != expected_archive
    ):
        raise EvidenceError("retained libsqlite3-sys archive digest mismatch")
    expected_features = resolved_sqlite_features(metadata, selected_ids)
    if native.get("resolved_features") != expected_features:
        raise EvidenceError("retained bundled SQLite feature resolution mismatch")
    return SQLiteSource(
        EXPECTED_SQLITE_VERSION,
        EXPECTED_SQLITE_SOURCE_ID,
        sha256_file(sqlite_c),
    )


def _validate_rustsec_evidence(root: Path, repository: Path) -> None:
    report = load_json(_bundle_file(root, "rustsec/report.json"))
    database = load_json(_bundle_file(root, "rustsec/database.json"))
    if not isinstance(report, dict) or not isinstance(database, dict):
        raise EvidenceError("retained RustSec evidence is malformed")
    validate_audit_report(report)
    lock_count = len(
        re.findall(
            r"(?m)^\[\[package\]\]$",
            (repository / "kernel" / "Cargo.lock").read_text(encoding="utf-8"),
        )
    )
    if report["lockfile"].get("dependency-count") != lock_count:
        raise EvidenceError("retained RustSec dependency count mismatch")
    advisory_count = report["database"].get("advisory-count")
    if not isinstance(advisory_count, int) or advisory_count <= 0:
        raise EvidenceError("retained RustSec advisory count is invalid")
    expected_command = [
        "cargo",
        "audit",
        "--db",
        "<pinned-rustsec-db>",
        "--no-fetch",
        "--file",
        "kernel/Cargo.lock",
        "--json",
    ]
    if (
        database.get("schema") != "helixos.rustsec-database-evidence/1"
        or database.get("cargo_audit_version") != EXPECTED_AUDIT_VERSION
        or database.get("database_revision") != EXPECTED_RUSTSEC_REVISION
        or database.get("command") != expected_command
        or database.get("result") != "zero-vulnerabilities-warnings-retained"
    ):
        raise EvidenceError("retained RustSec database/scanner identity mismatch")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\s]+", str(database.get("database_commit_timestamp", ""))):
        raise EvidenceError("retained RustSec database timestamp is absent")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z", str(database.get("scan_timestamp", ""))):
        raise EvidenceError("retained RustSec scan timestamp is absent")
    _bundle_file(root, "rustsec/stderr.txt")


def _git_file_sha256(repository: Path, commit: str, relative: str) -> str:
    completed = subprocess.run(
        ["git", "show", "{}:{}".format(commit, relative)],
        cwd=str(repository),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise EvidenceError("protected source file is absent from exact commit")
    return hashlib.sha256(completed.stdout).hexdigest()


def _validate_removal_evidence(root: Path, repository: Path, commit: str) -> None:
    report = load_json(_bundle_file(root, "removal/report.json"))
    before = load_json(_bundle_file(root, "removal/protected-files-before.json"))
    after = load_json(_bundle_file(root, "removal/protected-files-after.json"))
    normalized = load_json(_bundle_file(root, "removal/metadata-after-removal.json"))
    if not all(isinstance(value, dict) for value in (report, before, after, normalized)):
        raise EvidenceError("retained removal evidence is malformed")
    if (
        report.get("schema") != "helixos.plan-004-removal-drill/1"
        or report.get("result") != "passing-isolated-clean-copy-removal"
        or report.get("source_commit") != commit
        or report.get("baseline_commit") != REMOVAL_BASELINE_COMMIT
        or report.get("restored_baseline_lock_sha256") != REMOVAL_BASELINE_LOCK_SHA256
        or report.get("protected_bytes_unchanged") is not True
        or report.get("removed_workspace_members")
        != ["helix-coordinator-sqlite", "helix-plan-preparation"]
        or report.get("removed_paths")
        != [
            "kernel/helix-plan-preparation",
            "kernel/helix-coordinator-sqlite",
            "contracts/fixtures/durable-preparation-v1",
            ".github/workflows/durable-preparation.yml",
        ]
    ):
        raise EvidenceError("retained removal report identity/result is invalid")
    if set(report.get("metadata_packages") or []) != EXPECTED_REMOVAL_PACKAGES:
        raise EvidenceError("retained removal package set is invalid")
    lineage = subprocess.run(
        ["git", "merge-base", "--is-ancestor", REMOVAL_BASELINE_COMMIT, commit],
        cwd=str(repository),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if lineage.returncode != 0:
        raise EvidenceError("retained removal baseline is outside source lineage")
    if before != after or report.get("protected_file_count") != len(before):
        raise EvidenceError("retained removal protected-file comparison is inconsistent")
    tracked_raw = run_checked(
        ["git", "ls-tree", "-r", "--name-only", commit, "--"]
        + list(REMOVAL_PROTECTED_PATHS),
        repository,
    )
    tracked = {line for line in tracked_raw.splitlines() if line}
    if set(before) != tracked:
        raise EvidenceError("retained removal protected-file set is incomplete")
    for relative, digest in before.items():
        if not isinstance(digest, str) or _git_file_sha256(repository, commit, relative) != digest:
            raise EvidenceError("retained removal protected-file digest mismatch")
    object_entries = report.get("protected_git_objects")
    if not isinstance(object_entries, list) or len(object_entries) != len(
        REMOVAL_PROTECTED_PATHS
    ):
        raise EvidenceError("retained removal protected-object inventory is incomplete")
    object_paths = set()
    for entry in object_entries:
        if not isinstance(entry, dict):
            raise EvidenceError("retained removal protected-object entry is malformed")
        relative = entry.get("path")
        if relative in object_paths or relative not in REMOVAL_PROTECTED_PATHS:
            raise EvidenceError("retained removal protected-object path is invalid")
        source_object = run_checked(
            ["git", "rev-parse", "{}:{}".format(commit, relative)], repository
        )
        if entry.get("source_object") != source_object:
            raise EvidenceError("retained removal protected-object identity mismatch")
        object_paths.add(relative)
    if object_paths != set(REMOVAL_PROTECTED_PATHS):
        raise EvidenceError("retained removal protected-object paths are incomplete")
    normalized_packages = normalized.get("workspace_packages")
    if (
        normalized.get("schema") != "helixos.plan-004-removal-metadata/1"
        or normalized.get("target_directory") != "<cargo-target>"
        or normalized.get("workspace_root") != "<removal-root>/kernel"
        or normalized.get("workspace_package_count") != len(EXPECTED_REMOVAL_PACKAGES)
        or not isinstance(normalized_packages, list)
        or any(not isinstance(item, dict) for item in normalized_packages)
        or {item.get("name") for item in normalized_packages}
        != EXPECTED_REMOVAL_PACKAGES
    ):
        raise EvidenceError("retained removal normalized metadata is invalid")
    structural = report.get("plan_002_structural_oracle") or {}
    if (
        structural.get("test")
        != "only_reviewed_consumers_depend_on_the_eligibility_contract"
        or structural.get("source_bytes") != "protected-and-unchanged"
        or structural.get("semantic_tests") != "executed"
    ):
        raise EvidenceError("retained PLAN-002 removal exception is invalid")
    expected_commands = {
        "metadata-after-removal",
        "plan-001-contracts",
        "plan-002-eligibility",
        "plan-003-replay",
        "legacy-mvp0",
    }
    commands = report.get("commands")
    if not isinstance(commands, list):
        raise EvidenceError("retained removal commands are absent")
    names = set()
    for command in commands:
        if not isinstance(command, dict):
            raise EvidenceError("retained removal command result is malformed")
        name = command.get("name")
        log = command.get("log")
        digest = command.get("log_sha256")
        if (
            name in names
            or name not in expected_commands
            or command.get("exit_code") != 0
            or not isinstance(log, str)
            or not log.startswith("removal/")
            or not isinstance(digest, str)
        ):
            raise EvidenceError("retained removal command result is malformed")
        if sha256_file(_bundle_file(root, log)) != digest:
            raise EvidenceError("retained removal command log digest mismatch")
        names.add(name)
    if names != expected_commands:
        raise EvidenceError("retained removal command set is incomplete")


def verify_bundle(root: Path, repository: Path, require_removal: bool) -> None:
    root = root.resolve()
    repository = repository.resolve()
    verify_sha256_manifest(root)
    required = [
        "descriptor.json",
        "sbom/plan-004-sbom.cdx.json",
        "licenses/inventory.json",
        "native/libsqlite3-sys-0.38.1.crate",
        "native/sqlite3.c",
        "native/sqlite3.h",
        "native/sqlite3-source-metadata.json",
        "rustsec/report.json",
        "rustsec/database.json",
    ]
    if require_removal:
        required.append("removal/report.json")
    for relative in required:
        if not (root / relative).is_file():
            raise EvidenceError("evidence bundle lacks {}".format(relative))
    descriptor = load_json(root / "descriptor.json")
    if not isinstance(descriptor, dict) or descriptor.get("schema") != SCHEMA:
        raise EvidenceError("release descriptor schema mismatch")
    commit = git_revision(repository)
    source = descriptor.get("source") or {}
    workflow = descriptor.get("workflow") or {}
    runner = descriptor.get("runner") or {}
    binding = descriptor.get("artifact_binding") or {}
    toolchain = descriptor.get("toolchain") or {}
    supply = descriptor.get("supply_chain") or {}
    if (
        descriptor.get("acceptance_id") != "PLAN-004"
        or descriptor.get("claim_status")
        != "pending-until-catalogued-overall-remains-pending-evidence"
        or source.get("commit") != commit
        or source.get("tracked_checkout_clean") is not True
        or not re.fullmatch(r"[^/\s]+/[^/\s]+", str(source.get("repository", "")))
        or binding.get("artifact_name") != "plan-004-release-{}".format(commit)
        or binding.get("archive_digest") != "published-after-upload"
        or binding.get("attestation_subject")
        != "actions/upload-artifact artifact-digest output"
    ):
        raise EvidenceError("release descriptor source/artifact identity mismatch")
    for label, value in (
        ("source timestamp", source.get("commit_timestamp")),
        ("workflow ref", workflow.get("ref")),
        ("runner OS", runner.get("os")),
        ("runner architecture", runner.get("arch")),
        ("runner name", runner.get("name")),
        ("runner image OS", runner.get("image_os")),
        ("runner image version", runner.get("image_version")),
    ):
        _require_provenance_value(label, value)
    if (
        workflow.get("path") != ".github/workflows/durable-preparation.yml"
        or workflow.get("sha256")
        != sha256_file(repository / ".github" / "workflows" / "durable-preparation.yml")
        or not str(workflow.get("run_id", "")).isdigit()
        or not str(workflow.get("run_attempt", "")).isdigit()
    ):
        raise EvidenceError("release descriptor workflow provenance mismatch")
    if toolchain != {
        "rust": "1.96.1",
        "cargo_cyclonedx": EXPECTED_CYCLONEDX_VERSION,
        "cargo_audit": EXPECTED_AUDIT_VERSION,
        "rustsec_database_revision": EXPECTED_RUSTSEC_REVISION,
        "spdx_license_list_revision": EXPECTED_SPDX_REVISION,
    }:
        raise EvidenceError("release descriptor toolchain identity mismatch")

    metadata, selected_ids, selected_identities = _current_metadata(repository)
    selected_adjacency = production_dependency_adjacency(metadata, selected_ids)
    _validate_toolchain_files(root)
    _validate_reviewed_inputs(root, repository, descriptor)
    inventory = load_json(_bundle_file(root, "licenses/inventory.json"))
    if not isinstance(inventory, dict):
        raise EvidenceError("retained license inventory is malformed")
    _validate_license_inventory(
        root, inventory, metadata, selected_identities, repository
    )
    native = load_json(root / "native" / "sqlite3-source-metadata.json")
    if not isinstance(native, dict):
        raise EvidenceError("retained native SQLite metadata is malformed")
    sqlite = _validate_native_evidence(
        root, native, metadata, selected_ids, repository
    )
    sbom = load_json(_bundle_file(root, "sbom/plan-004-sbom.cdx.json"))
    if not isinstance(sbom, dict):
        raise EvidenceError("retained SBOM is malformed")
    validate_retained_sbom(sbom, sqlite, selected_identities, selected_adjacency)
    _validate_rustsec_evidence(root, repository)
    if (
        supply.get("sbom") != "sbom/plan-004-sbom.cdx.json"
        or supply.get("license_inventory") != "licenses/inventory.json"
        or supply.get("production_package_count") != inventory.get("package_count")
        or supply.get("external_package_count")
        != inventory.get("external_package_count")
        or supply.get("rustsec_report") != "rustsec/report.json"
        or supply.get("rustsec_stderr") != "rustsec/stderr.txt"
        or supply.get("rustsec_result") != "zero-vulnerabilities-warnings-retained"
        or supply.get("native_sqlite") != native
    ):
        raise EvidenceError("release descriptor supply-chain summary mismatch")
    physical = descriptor.get("physical_m4_artifacts")
    if (
        not isinstance(physical, list)
        or len(physical) != len(LOCAL_M4_ARTIFACTS)
        or any(not isinstance(entry, dict) for entry in physical)
    ):
        raise EvidenceError("release descriptor local-only M4 inventory is invalid")
    physical_by_name = {Path(entry.get("path", "")).name: entry for entry in physical}
    for filename, digest in LOCAL_M4_ARTIFACTS:
        entry = physical_by_name.get(filename) or {}
        if (
            entry.get("path") != "local-only-physical-m4/{}".format(filename)
            or entry.get("sha256") != digest
            or entry.get("status") != "local-only-not-immutable-not-power-loss"
            or sha256_file(_bundle_file(root, entry.get("path", ""))) != digest
        ):
            raise EvidenceError("retained local-only M4 artifact identity mismatch")
    if require_removal:
        _validate_removal_evidence(root, repository, commit)
    forbidden = {
        str(repository),
        str(Path.home()),
        os.environ.get("GITHUB_WORKSPACE", ""),
    }
    forbidden.discard("")
    for path in _text_files(root):
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        if any(marker in lowered for marker in SECRET_MARKERS):
            raise EvidenceError("secret-like marker in {}".format(path.relative_to(root)))
        for value in forbidden:
            if value and value in text:
                raise EvidenceError("absolute machine path in {}".format(path.relative_to(root)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build a supply-chain bundle")
    build.add_argument("--repository", default=".")
    build.add_argument("--output", required=True)
    build.add_argument("--sbom", required=True)
    build.add_argument("--metadata", required=True)
    build.add_argument("--audit-report", required=True)
    build.add_argument("--audit-stderr", required=True)
    build.add_argument("--advisory-db", required=True)
    build.add_argument("--spdx-license-list", required=True)
    build.add_argument("--rustc-version", required=True)
    build.add_argument("--cargo-version", required=True)
    build.add_argument("--cargo-cyclonedx-version", required=True)
    build.add_argument("--cargo-audit-version", required=True)
    build.add_argument("--python-version", required=True)
    build.add_argument("--tool-binary-digests", required=True)
    build.add_argument("--cargo-tree", required=True)
    build.add_argument("--scan-timestamp", required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--source-timestamp", required=True)
    build.add_argument("--artifact-name", required=True)
    build.add_argument("--github-repository", required=True)
    build.add_argument("--workflow-ref", required=True)
    build.add_argument("--run-id", required=True)
    build.add_argument("--run-attempt", required=True)
    build.add_argument("--runner-os", required=True)
    build.add_argument("--runner-arch", required=True)
    build.add_argument("--runner-name", required=True)
    build.add_argument("--image-os", required=True)
    build.add_argument("--image-version", required=True)

    manifest = subparsers.add_parser("manifest", help="refresh the internal manifest")
    manifest.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify", help="verify the completed bundle")
    verify.add_argument("--repository", default=".")
    verify.add_argument("--output", required=True)
    verify.add_argument("--require-removal", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            build_bundle(args)
        elif args.command == "manifest":
            write_sha256_manifest(Path(args.output))
        else:
            verify_bundle(
                Path(args.output), Path(args.repository), args.require_removal
            )
    except EvidenceError as error:
        print("PLAN-004 supply-chain evidence failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
