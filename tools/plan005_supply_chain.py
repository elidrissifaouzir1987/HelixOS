#!/usr/bin/env python3
"""Build and independently verify PLAN-005 supply-chain evidence.

The default build is a diagnostic working-tree snapshot.  Supplying
``--source-commit`` switches to the fail-closed exact-commit mode used by the
immutable workflow; that mode requires a clean tracked checkout and complete
workflow provenance.  Neither mode changes PLAN-004 evidence.
"""

import argparse
import copy
import datetime
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, unquote

import plan004_supply_chain as plan004
import plan005_removal_drill as removal


SCHEMA = "helixos.plan-005-release-evidence/1"
GRAPH_SCHEMA = "helixos.plan-005-production-graph/1"
IDENTITY_SCHEMA = "helixos.plan-005-supply-identity/1"
LICENSE_SCHEMA = "helixos.plan-005-license-inventory/1"
NATIVE_SCHEMA = "helixos.plan-005-native-sqlite/1"
PROVENANCE_SCHEMA = "helixos.plan-005-provenance/1"
CLAIM_STATUS = "pending-evidence"
MANIFEST_NAME = plan004.MANIFEST_NAME

PRODUCTION_ROOTS = (
    "helix-dispatch-contracts",
    "helix-plan-dispatch",
    "helix-dispatch-inbox-sqlite",
    "helix-coordinator-sqlite",
)
METADATA_ROOT = "helix-coordinator-sqlite"

EXPECTED_RUST_VERSION = "1.96.1"
EXPECTED_CYCLONEDX_VERSION = plan004.EXPECTED_CYCLONEDX_VERSION
EXPECTED_AUDIT_VERSION = plan004.EXPECTED_AUDIT_VERSION
EXPECTED_RUSTSEC_REVISION = plan004.EXPECTED_RUSTSEC_REVISION
EXPECTED_SPDX_REVISION = plan004.EXPECTED_SPDX_REVISION
EXPECTED_SQLITE_VERSION = plan004.EXPECTED_SQLITE_VERSION
EXPECTED_SQLITE_SOURCE_ID = plan004.EXPECTED_SQLITE_SOURCE_ID
EXPECTED_LIBSQLITE_VERSION = plan004.EXPECTED_LIBSQLITE_VERSION
EXPECTED_RUSQLITE_VERSION = plan004.EXPECTED_RUSQLITE_VERSION
EXPECTED_FILE_ID_VERSION = plan004.EXPECTED_FILE_ID_VERSION

EXPECTED_RELEASE_ORACLE = {
    "package_count": 84,
    "dependency_edge_count": 143,
    "external_package_count": 77,
    "workspace_package_count": 7,
    "spdx_text_count": 10,
}
EXPECTED_RUSTSEC_REPORT_SHA256 = (
    "95b6445f8828c8e9a79d5ef32e225a1ff6cdbcc39d2ec1fcf24b74da2180f396"
)
EXPECTED_RUSTSEC_DATABASE_TIMESTAMP = "2026-07-12T09:10:54+02:00"
EXPECTED_RELEASE_ARTIFACT_SHA256 = {
    "graph/production-closure.json": "c5b84e89350646b19773af58f5e508c646805d28bbea28fe059d98af7d512154",
    "licenses/inventory.json": "cb648b830b004c0aafcff84b2aad852f4d4093cd3a288dcad489c6ebca275d89",
    "sbom/plan-005-sbom.cdx.json": "feedaabe86ed6f33dba025ef85edf72fd445a2925fc25ae5df1c72d867035be9",
}
EXPECTED_SPDX_TEXTS = {
    "Apache-2.0": ("text", "074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff"),
    "BSD-1-Clause": ("text", "244e17b6f02493de568a8ddfd7f4349996a6c332c0585d304ceaf5394becea52"),
    "BSD-3-Clause": ("text", "5a93d5831e1297ab10fe643e1a631e83be392896da14ee2951285a79012df69d"),
    "BSL-1.0": ("text", "84c6ef3ea9e3254a54d0acf5d3e0c61ae011b8fef7dd6940591cf060e6380a8f"),
    "LGPL-2.1-or-later": ("text", "5749785c8bdefafcb5d798270ed0a967036fe2ca63dcedade1627565dfef81d2"),
    "LLVM-exception": ("text", "e34c58338bd89d43e709e226610d8f32b3e3c47f4ad9a99a8dc1d4ac7842488e"),
    "MIT": ("text", "b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5"),
    "Unicode-3.0": ("text", "f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1"),
    "Unlicense": ("text", "0bdebfeda07d45dada625ae1317c6f833186e798b171d0db640bcf32e92a8240"),
    "Zlib": ("text", "bfb1112d49db5b1daecdfef24bd7e2f3ea0bafb33aa67aa0ab51e2bf8407c03d"),
}

RUSTSEC_URL = "https://github.com/RustSec/advisory-db.git"
SPDX_URL = "https://github.com/spdx/license-list-data.git"
WORKFLOW_PATH = ".github/workflows/durable-dispatch.yml"
SUPPLY_TOOL_PATH = "tools/plan005_supply_chain.py"
HELPER_TOOL_PATH = "tools/plan004_supply_chain.py"
REMOVAL_BASELINE = "6f8dfdd5194792e8592cd10ebaaf8828833effbe"
REMOVAL_MANIFEST_SHA256 = (
    "eb2c7133de8c321939d40810efa79150beb344564868dae78dad2b0504fd9df0"
)

NONCLAIMS = {
    "full_machine_restore": "out-of-scope",
    "hosted_or_process_kill_power_loss": "not-proven",
    "immutable_release": "requires-attested-zip-independent-verification-and-cataloguing",
    "physical_m4_performance": "not-proven-by-supply-bundle",
    "production_supervisor_or_effect": "out-of-scope",
    "secure_erasure": "not-claimed",
    "tier_1": "pending-external-evidence",
}

CORE_REVIEWED_INPUT_PATHS = (
    "kernel/Cargo.lock",
    "kernel/Cargo.toml",
    "kernel/rust-toolchain.toml",
    "kernel/helix-dispatch-contracts/Cargo.toml",
    "kernel/helix-plan-dispatch/Cargo.toml",
    "kernel/helix-dispatch-inbox-sqlite/Cargo.toml",
    "kernel/helix-coordinator-sqlite/Cargo.toml",
    "specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json",
    "specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json",
    "specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql",
    "specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql",
    "specs/005-durable-dispatch/contracts/dispatch-backup-manifest-v1.schema.json",
    "specs/005-durable-dispatch/contracts/fault-boundaries-v1.json",
    "contracts/fixtures/durable-dispatch-v1/README.md",
    "contracts/fixtures/durable-dispatch-v1/cases.json",
    "contracts/fixtures/durable-dispatch-v1/expected-outcomes.json",
    "contracts/fixtures/durable-dispatch-v1/end-to-end-cases.json",
    "contracts/fixtures/durable-dispatch-v1/fault-boundaries.json",
    "specs/005-durable-dispatch/evidence/removal-protected-files.json",
    "conformance/catalog.yaml",
    SUPPLY_TOOL_PATH,
    HELPER_TOOL_PATH,
    "tools/plan005_removal_drill.py",
    "tools/tests/test_plan005_evidence.py",
)

SECRET_PATTERNS = (
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}", re.IGNORECASE),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"x-access-token\s*:\s*[^\s\"']{12,}", re.IGNORECASE),
)
PRIVATE_PATH_PATTERNS = (
    re.compile(r"/Users/[^/<\s\"']+(?:/[^\s\"']*)?", re.IGNORECASE),
    re.compile(r"/home/[^/<\s\"']+(?:/[^\s\"']*)?"),
    re.compile(r"/private/(?:tmp|var)/[^/<\s\"']+(?:/[^\s\"']*)?", re.IGNORECASE),
    re.compile(r"/var/folders/[^/<\s\"']+(?:/[^\s\"']*)?", re.IGNORECASE),
    re.compile(
        r"[A-Za-z]:(?:\\+|%5[cC])+Users(?:\\+|%5[cC])+[^\\\s\"']+",
        re.IGNORECASE,
    ),
    re.compile(r"file://(?:/|[A-Za-z]:)", re.IGNORECASE),
)


EvidenceError = plan004.EvidenceError
SQLiteSource = plan004.SQLiteSource
sha256_file = plan004.sha256_file
canonical_json_bytes = plan004.canonical_json_bytes
write_json = plan004.write_json
load_json = plan004.load_json
production_package_identities = plan004.production_package_identities
production_dependency_adjacency = plan004.production_dependency_adjacency
resolved_sqlite_features = plan004.resolved_sqlite_features
validate_audit_report = plan004.validate_audit_report
augment_sbom = plan004.augment_sbom
validate_retained_sbom = plan004.validate_retained_sbom
parse_lock_packages = plan004.parse_lock_packages
_write_sha256_manifest = plan004.write_sha256_manifest
_verify_sha256_manifest = plan004.verify_sha256_manifest


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_regular_evidence_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise EvidenceError("evidence root is absent or unsafe")
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            mode = os.lstat(current_path / name).st_mode
            if stat.S_ISLNK(mode):
                raise EvidenceError("evidence tree contains a symlink")
            if not stat.S_ISDIR(mode):
                raise EvidenceError("evidence tree contains a non-directory node")
        for name in filenames:
            mode = os.lstat(current_path / name).st_mode
            if stat.S_ISLNK(mode):
                raise EvidenceError("evidence tree contains a symlink")
            if not stat.S_ISREG(mode):
                raise EvidenceError("evidence tree contains a non-regular file")


def write_sha256_manifest(root: Path) -> Path:
    root = root.absolute()
    if _path_has_unsafe_symlink(root) or not root.is_dir():
        raise EvidenceError("evidence root is absent or unsafe")
    _validate_regular_evidence_tree(root)
    return _write_sha256_manifest(root)


def verify_sha256_manifest(root: Path) -> None:
    _validate_regular_evidence_tree(root)
    _verify_sha256_manifest(root)


def refresh_bundle_manifest(root: Path) -> Path:
    root = root.absolute()
    if _path_has_unsafe_symlink(root) or not root.is_dir():
        raise EvidenceError("evidence bundle root is absent or unsafe")
    for relative in (
        MANIFEST_NAME,
        "descriptor.json",
        "identity.json",
        "provenance.json",
    ):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise EvidenceError("manifest refresh requires an existing PLAN-005 bundle")
    return write_sha256_manifest(root)


def _identity_record(identity: Tuple[str, str, str]) -> dict:
    return {"name": identity[0], "version": identity[1], "source": identity[2]}


def _identity_tuple(record: object) -> Tuple[str, str, str]:
    if not isinstance(record, dict):
        raise EvidenceError("production package identity is malformed")
    values = (record.get("name"), record.get("version"), record.get("source"))
    if not all(isinstance(value, str) and value for value in values):
        raise EvidenceError("production package identity is incomplete")
    return values  # type: ignore[return-value]


def _identity_sort_key(identity: Tuple[str, str, str]) -> Tuple[bytes, bytes, bytes]:
    return tuple(value.encode("utf-8") for value in identity)  # type: ignore[return-value]


def _records(identities: Iterable[Tuple[str, str, str]]) -> List[dict]:
    return [
        _identity_record(identity)
        for identity in sorted(set(identities), key=_identity_sort_key)
    ]


def union_dependency_closure(
    metadata: dict, root_names: Sequence[str] = PRODUCTION_ROOTS
) -> Tuple[Set[str], Dict[str, Set[str]]]:
    roots = tuple(root_names)
    if roots != PRODUCTION_ROOTS or len(set(roots)) != len(roots):
        raise EvidenceError("PLAN-005 production roots are not the closed reviewed set")
    per_root: Dict[str, Set[str]] = {}
    union: Set[str] = set()
    for root in roots:
        closure = plan004.dependency_closure(metadata, root)
        per_root[root] = closure
        union.update(closure)
    return union, per_root


def build_production_graph(metadata: dict, cargo_lock_text: str) -> dict:
    selected_ids, root_closures = union_dependency_closure(metadata)
    identities = production_package_identities(metadata, selected_ids)
    adjacency = production_dependency_adjacency(metadata, selected_ids)
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
    lock = parse_lock_packages(cargo_lock_text)

    package_records = []
    for identity in sorted(identities, key=_identity_sort_key):
        record = _identity_record(identity)
        if identity[2] != "workspace-path":
            checksum = lock.get(identity)
            if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise EvidenceError(
                    "Cargo.lock lacks exact checksum for {} {}".format(
                        identity[0], identity[1]
                    )
                )
            record["cargo_lock_checksum_sha256"] = checksum
        package_records.append(record)

    root_records = {}
    for root in PRODUCTION_ROOTS:
        closure_identities = {identity_by_id[item] for item in root_closures[root]}
        root_records[root] = {
            "package_count": len(closure_identities),
            "packages": _records(closure_identities),
        }

    adjacency_records = []
    for identity in sorted(adjacency, key=_identity_sort_key):
        adjacency_records.append(
            {
                "package": _identity_record(identity),
                "dependencies": _records(adjacency[identity]),
            }
        )
    return {
        "schema": GRAPH_SCHEMA,
        "roots": list(PRODUCTION_ROOTS),
        "scope": "union-normal-and-build-all-features-all-targets-dev-excluded",
        "cargo_lock": {
            "sha256": _sha256_bytes(cargo_lock_text.encode("utf-8")),
            "selected_registry_package_count": sum(
                identity[2] != "workspace-path" for identity in identities
            ),
        },
        "package_count": len(identities),
        "dependency_edge_count": sum(len(targets) for targets in adjacency.values()),
        "packages": package_records,
        "root_closures": root_records,
        "adjacency": adjacency_records,
    }


def validate_production_graph(graph: dict, metadata: dict, cargo_lock_text: str) -> None:
    if not isinstance(graph, dict) or graph.get("schema") != GRAPH_SCHEMA:
        raise EvidenceError("production graph schema mismatch")
    expected = build_production_graph(metadata, cargo_lock_text)
    if graph.get("roots") != expected["roots"]:
        raise EvidenceError("production graph roots mismatch")
    if graph.get("cargo_lock") != expected["cargo_lock"]:
        raise EvidenceError("Cargo.lock binding mismatch")
    if graph.get("packages") != expected["packages"]:
        raise EvidenceError("production package/lock identity mismatch")
    if graph.get("root_closures") != expected["root_closures"]:
        raise EvidenceError("production root closure mismatch")
    if graph.get("adjacency") != expected["adjacency"]:
        raise EvidenceError("production dependency adjacency mismatch")
    for field in ("scope", "package_count", "dependency_edge_count"):
        if graph.get(field) != expected[field]:
            raise EvidenceError("production graph {} mismatch".format(field))


def _component_identity(component: object) -> Tuple[str, str]:
    if not isinstance(component, dict):
        raise EvidenceError("CycloneDX component is malformed")
    name = component.get("name")
    version = component.get("version")
    reference = component.get("bom-ref")
    if not all(isinstance(value, str) and value for value in (name, version, reference)):
        raise EvidenceError("CycloneDX component identity/reference is incomplete")
    return name, version


def _cyclonedx_license_expression(expression: str) -> str:
    # cargo-cyclonedx 0.5.9 normalizes Cargo's legacy dual-license spelling.
    if expression == "MIT/Apache-2.0":
        return "MIT OR Apache-2.0"
    return expression


def merge_cyclonedx_sboms(sboms: Sequence[dict], metadata_root: str = METADATA_ROOT) -> dict:
    if not sboms:
        raise EvidenceError("at least one CycloneDX document is required")
    documents = []
    for sbom in sboms:
        if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
            raise EvidenceError("SBOM must be CycloneDX 1.5 JSON")
        documents.append(plan004.sanitize_sbom_workspace_paths(sbom))

    components_by_identity: Dict[Tuple[str, str], List[dict]] = {}
    reference_by_identity: Dict[Tuple[str, str], str] = {}
    document_references: List[Dict[str, Tuple[str, str]]] = []
    for document in documents:
        metadata_component = (document.get("metadata") or {}).get("component")
        components = document.get("components")
        if not isinstance(metadata_component, dict) or not isinstance(components, list):
            raise EvidenceError("CycloneDX document lacks component structure")
        local: Dict[str, Tuple[str, str]] = {}
        for component in [metadata_component] + components:
            identity = _component_identity(component)
            reference = component["bom-ref"]
            if reference in local and local[reference] != identity:
                raise EvidenceError("CycloneDX reference maps to multiple components")
            local[reference] = identity
            known = reference_by_identity.get(identity)
            if known is not None and known != reference:
                raise EvidenceError("CycloneDX component identity has conflicting references")
            reference_by_identity[identity] = reference
            components_by_identity.setdefault(identity, []).append(copy.deepcopy(component))
        document_references.append(local)

    edges: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {
        identity: set() for identity in components_by_identity
    }
    for document, local in zip(documents, document_references):
        dependencies = document.get("dependencies")
        if not isinstance(dependencies, list):
            raise EvidenceError("CycloneDX document lacks dependency graph")
        seen = set()
        for entry in dependencies:
            reference = entry.get("ref") if isinstance(entry, dict) else None
            targets = entry.get("dependsOn", []) if isinstance(entry, dict) else None
            if (
                not isinstance(reference, str)
                or reference in seen
                or reference not in local
                or not isinstance(targets, list)
                or any(not isinstance(target, str) or target not in local for target in targets)
            ):
                raise EvidenceError("CycloneDX dependency graph is malformed")
            seen.add(reference)
            edges[local[reference]].update(local[target] for target in targets)
        if seen != set(local):
            raise EvidenceError("CycloneDX dependency graph does not cover every component")

    root_matches = [identity for identity in components_by_identity if identity[0] == metadata_root]
    if len(root_matches) != 1:
        raise EvidenceError("merged CycloneDX graph lacks one metadata root")
    root_identity = root_matches[0]
    chosen = {
        identity: sorted(
            candidates,
            key=lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True),
        )[-1]
        for identity, candidates in components_by_identity.items()
    }
    root_document = next(
        document
        for document in documents
        if ((document.get("metadata") or {}).get("component") or {}).get("name")
        == metadata_root
    )
    metadata = copy.deepcopy(root_document.get("metadata") or {})
    metadata.pop("timestamp", None)
    metadata["component"] = chosen[root_identity]
    properties = metadata.get("properties", [])
    if not isinstance(properties, list) or any(
        not isinstance(entry, dict) for entry in properties
    ):
        raise EvidenceError("CycloneDX metadata properties are malformed")
    properties = [
        entry
        for entry in properties
        if entry.get("name") != "helixos:plan-005-production-root"
    ]
    present_roots = sorted(
        identity[0]
        for identity in chosen
        if identity[0] in PRODUCTION_ROOTS
    )
    properties.extend(
        {
            "name": "helixos:plan-005-production-root",
            "value": root,
        }
        for root in present_roots
    )
    metadata["properties"] = properties
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": [
            chosen[identity]
            for identity in sorted(chosen)
            if identity != root_identity
        ],
        "dependencies": [],
    }
    for identity in sorted(chosen):
        result["dependencies"].append(
            {
                "ref": reference_by_identity[identity],
                "dependsOn": sorted(reference_by_identity[target] for target in edges[identity]),
            }
        )
    result["components"].sort(
        key=lambda item: (
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("bom-ref", "")),
        )
    )
    result["dependencies"].sort(key=lambda item: item["ref"])
    encoded = json.dumps(result, sort_keys=True)
    if "path+file://" in encoded or "download_url=file://" in encoded.lower():
        raise EvidenceError("merged CycloneDX SBOM retains a machine-local path")
    return result


def validate_cargo_sbom_identities(
    sbom: dict,
    expected_identities: Set[Tuple[str, str, str]],
    metadata: dict,
    cargo_lock_text: str,
) -> None:
    metadata_component = (sbom.get("metadata") or {}).get("component")
    components = sbom.get("components")
    if not isinstance(metadata_component, dict) or not isinstance(components, list):
        raise EvidenceError("retained SBOM lacks cargo component structure")
    cargo_components = [metadata_component] + [
        component
        for component in components
        if isinstance(component, dict) and component.get("name") != "SQLite"
    ]
    expected_by_pair = {
        (name, version): (name, version, source)
        for name, version, source in expected_identities
    }
    if len(expected_by_pair) != len(expected_identities):
        raise EvidenceError("production closure has ambiguous cargo name/version pairs")
    packages_by_identity = {
        (
            package.get("name"),
            package.get("version"),
            package.get("source") or "workspace-path",
        ): package
        for package in metadata.get("packages", [])
        if isinstance(package, dict)
    }
    if not expected_identities.issubset(packages_by_identity):
        raise EvidenceError("cargo metadata lacks a production SBOM identity")
    lock_checksums = parse_lock_packages(cargo_lock_text)
    actual_by_pair = {}
    for component in cargo_components:
        pair = _component_identity(component)
        if pair in actual_by_pair or pair not in expected_by_pair:
            raise EvidenceError("retained SBOM cargo identity is unknown or duplicated")
        identity = expected_by_pair[pair]
        expected_purl = "pkg:cargo/{}@{}".format(
            quote(identity[0], safe="-._~+"), quote(identity[1], safe="-._~+")
        )
        if component.get("purl") != expected_purl:
            raise EvidenceError("retained SBOM cargo purl mismatch")
        if component.get("type") != "library":
            raise EvidenceError("retained SBOM cargo component type mismatch")
        package = packages_by_identity[identity]
        license_expression = package.get("license")
        expected_licenses = (
            [{"expression": _cyclonedx_license_expression(license_expression)}]
            if isinstance(license_expression, str) and license_expression
            else []
        )
        if component.get("licenses", []) != expected_licenses:
            raise EvidenceError("retained SBOM cargo license expression mismatch")
        reference = component.get("bom-ref")
        if identity[2] == "workspace-path":
            if component.get("hashes", []) != []:
                raise EvidenceError("retained workspace SBOM component has archive hashes")
            expected_reference = "urn:helixos:cargo-workspace:{}@{}".format(
                re.sub(r"[^A-Za-z0-9._+-]", "_", identity[0]),
                re.sub(r"[^A-Za-z0-9._+-]", "_", identity[1]),
            )
            if reference != expected_reference and not str(reference).startswith(
                expected_reference + ":"
            ):
                raise EvidenceError("retained SBOM workspace reference mismatch")
        else:
            checksum = lock_checksums.get(identity)
            if not checksum or component.get("hashes") != [
                {"alg": "SHA-256", "content": checksum}
            ]:
                raise EvidenceError("retained SBOM Cargo.lock checksum mismatch")
            if reference != "{}#{}@{}".format(identity[2], identity[0], identity[1]):
                raise EvidenceError("retained SBOM registry source reference mismatch")
        actual_by_pair[pair] = component
    if set(actual_by_pair) != set(expected_by_pair):
        raise EvidenceError("retained SBOM cargo identity closure mismatch")
    properties = (sbom.get("metadata") or {}).get("properties")
    if not isinstance(properties, list):
        raise EvidenceError("retained SBOM lacks PLAN-005 root properties")
    roots = [
        entry.get("value")
        for entry in properties
        if isinstance(entry, dict)
        and entry.get("name") == "helixos:plan-005-production-root"
    ]
    if roots != sorted(PRODUCTION_ROOTS):
        raise EvidenceError("retained SBOM production-root union mismatch")


def validate_plan005_sbom(
    sbom: dict,
    sqlite: SQLiteSource,
    expected_identities: Set[Tuple[str, str, str]],
    expected_adjacency: Dict[
        Tuple[str, str, str], Set[Tuple[str, str, str]]
    ],
    metadata: dict,
    cargo_lock_text: str,
) -> None:
    validate_retained_sbom(sbom, sqlite, expected_identities, expected_adjacency)
    validate_cargo_sbom_identities(
        sbom, expected_identities, metadata, cargo_lock_text
    )
    native_components = [
        component
        for component in sbom.get("components", [])
        if isinstance(component, dict) and component.get("name") == "SQLite"
    ]
    native_ref = "pkg:generic/sqlite@{}".format(sqlite.version)
    if len(native_components) != 1 or native_components[0] != {
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
    }:
        raise EvidenceError("retained SBOM bundled SQLite semantics mismatch")


def expected_supply_identity() -> dict:
    return {
        "schema": IDENTITY_SCHEMA,
        "production_roots": list(PRODUCTION_ROOTS),
        "release_oracle": dict(EXPECTED_RELEASE_ORACLE),
        "release_artifact_sha256": dict(EXPECTED_RELEASE_ARTIFACT_SHA256),
        "rustsec_report_sha256": EXPECTED_RUSTSEC_REPORT_SHA256,
        "toolchain": {
            "rust": EXPECTED_RUST_VERSION,
            "cargo_audit": EXPECTED_AUDIT_VERSION,
            "cargo_cyclonedx": EXPECTED_CYCLONEDX_VERSION,
            "rustsec_database_revision": EXPECTED_RUSTSEC_REVISION,
            "spdx_license_list_revision": EXPECTED_SPDX_REVISION,
        },
        "native_sqlite": {
            "rusqlite_version": EXPECTED_RUSQLITE_VERSION,
            "libsqlite3_sys_version": EXPECTED_LIBSQLITE_VERSION,
            "sqlite_version": EXPECTED_SQLITE_VERSION,
            "sqlite_source_id": EXPECTED_SQLITE_SOURCE_ID,
            "required_rusqlite_features": ["backup", "bundled", "serialize"],
            "required_libsqlite3_sys_features": ["bundled", "bundled_bindings", "cc"],
            "forbidden_features": [
                "buildtime_bindgen",
                "bundled-sqlcipher",
                "in_gecko",
                "loadable_extension",
                "sqlcipher",
                "winsqlite3",
            ],
            "link_profile": "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static",
        },
    }


def validate_supply_identity(identity: dict) -> None:
    if not isinstance(identity, dict) or identity.get("schema") != IDENTITY_SCHEMA:
        raise EvidenceError("PLAN-005 supply identity schema mismatch")
    expected = expected_supply_identity()
    if identity.get("production_roots") != expected["production_roots"]:
        raise EvidenceError("PLAN-005 production root identity mismatch")
    if identity.get("release_oracle") != expected["release_oracle"]:
        raise EvidenceError("PLAN-005 release graph/license oracle mismatch")
    if (
        identity.get("release_artifact_sha256")
        != expected["release_artifact_sha256"]
        or identity.get("rustsec_report_sha256")
        != expected["rustsec_report_sha256"]
    ):
        raise EvidenceError("PLAN-005 immutable artifact oracle mismatch")
    actual_toolchain = identity.get("toolchain") or {}
    expected_toolchain = expected["toolchain"]
    checks = (
        ("rust", "Rust"),
        ("cargo_audit", "cargo-audit"),
        ("cargo_cyclonedx", "cargo-cyclonedx"),
        ("rustsec_database_revision", "RustSec"),
        ("spdx_license_list_revision", "SPDX"),
    )
    for field, label in checks:
        if actual_toolchain.get(field) != expected_toolchain[field]:
            raise EvidenceError("{} identity/pin mismatch".format(label))
    actual_native = identity.get("native_sqlite") or {}
    expected_native = expected["native_sqlite"]
    checks = (
        ("rusqlite_version", "rusqlite"),
        ("libsqlite3_sys_version", "libsqlite3-sys"),
        ("sqlite_version", "SQLite"),
        ("sqlite_source_id", "SQLite"),
        ("required_rusqlite_features", "rusqlite"),
        ("required_libsqlite3_sys_features", "libsqlite3-sys"),
        ("forbidden_features", "SQLite"),
        ("link_profile", "SQLite"),
    )
    for field, label in checks:
        if actual_native.get(field) != expected_native[field]:
            raise EvidenceError("{} identity/profile mismatch".format(label))
    if identity != expected:
        raise EvidenceError("PLAN-005 supply identity contains unexpected fields")


def _source_binding(commit: str, tree: str) -> str:
    return _sha256_bytes((commit + "\0" + tree).encode("ascii"))


def build_provenance(
    *,
    source_commit: str,
    source_tree: str,
    source_mode: str,
    tracked_checkout_clean: bool,
    workflow_path: str,
    workflow_sha256: str,
    tool_sha256: str,
    helper_sha256: str,
    artifact_name: str,
    repository_slug: str,
    workflow_ref: str,
    run_id: str,
    run_attempt: str,
    runner_os: str,
    runner_arch: str,
    runner_name: str,
    image_os: str,
    image_version: str,
    source_timestamp: str,
    scan_timestamp: str,
) -> dict:
    return {
        "schema": PROVENANCE_SCHEMA,
        "claim_status": CLAIM_STATUS,
        "source": {
            "commit": source_commit,
            "tree": source_tree,
            "binding_sha256": _source_binding(source_commit, source_tree),
            "mode": source_mode,
            "tracked_checkout_clean": tracked_checkout_clean,
            "timestamp": source_timestamp,
        },
        "repository": repository_slug,
        "workflow": {
            "path": workflow_path,
            "sha256": workflow_sha256,
            "ref": workflow_ref,
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "runner": {
            "os": runner_os,
            "arch": runner_arch,
            "name": runner_name,
            "image_os": image_os,
            "image_version": image_version,
        },
        "builder": {
            "path": SUPPLY_TOOL_PATH,
            "sha256": tool_sha256,
            "helper_path": HELPER_TOOL_PATH,
            "helper_sha256": helper_sha256,
        },
        "artifact": {
            "name": artifact_name,
            "archive_digest": "published-after-upload",
            "attestation_subject": "actions/upload-artifact artifact-digest output",
        },
        "scan_timestamp": scan_timestamp,
    }


def _present(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip() or value.strip().lower() in {
        "none",
        "null",
        "unknown",
        "unset",
    }:
        raise EvidenceError("{} provenance is unavailable".format(label))
    return value


def validate_provenance(
    provenance: dict,
    expected_commit: Optional[str] = None,
    expected_tree: Optional[str] = None,
    expected_source_timestamp: Optional[str] = None,
    expected_checkout_clean: Optional[bool] = None,
    require_exact: bool = False,
) -> None:
    if not isinstance(provenance, dict) or provenance.get("schema") != PROVENANCE_SCHEMA:
        raise EvidenceError("release provenance schema mismatch")
    if set(provenance) != {
        "schema",
        "claim_status",
        "source",
        "repository",
        "workflow",
        "runner",
        "builder",
        "artifact",
        "scan_timestamp",
    }:
        raise EvidenceError("release provenance contains unexpected fields")
    if provenance.get("claim_status") != CLAIM_STATUS:
        raise EvidenceError("release provenance claim status was promoted")
    source = provenance.get("source") or {}
    if set(source) != {
        "commit",
        "tree",
        "binding_sha256",
        "mode",
        "tracked_checkout_clean",
        "timestamp",
    }:
        raise EvidenceError("source provenance contains unexpected fields")
    commit = source.get("commit")
    tree = source.get("tree")
    if not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
        raise EvidenceError("source commit provenance is malformed")
    if not re.fullmatch(r"[0-9a-f]{40}", str(tree)):
        raise EvidenceError("source tree provenance is malformed")
    if source.get("binding_sha256") != _source_binding(commit, tree):
        raise EvidenceError("source tree binding mismatch")
    if expected_commit is not None and commit != expected_commit:
        raise EvidenceError("source commit provenance mismatch")
    if expected_tree is not None and tree != expected_tree:
        raise EvidenceError("source tree provenance mismatch")
    mode = source.get("mode")
    if mode not in {"diagnostic-working-tree", "exact-commit"}:
        raise EvidenceError("source provenance mode is invalid")
    if require_exact and mode != "exact-commit":
        raise EvidenceError("diagnostic evidence cannot be promoted to exact-commit")
    if mode == "exact-commit" and source.get("tracked_checkout_clean") is not True:
        raise EvidenceError("exact-commit provenance requires a clean tracked checkout")
    if (
        expected_checkout_clean is not None
        and source.get("tracked_checkout_clean") is not expected_checkout_clean
    ):
        raise EvidenceError("source checkout cleanliness provenance mismatch")
    source_timestamp = _present("source timestamp", source.get("timestamp"))
    if (
        expected_source_timestamp is not None
        and source_timestamp != expected_source_timestamp
    ):
        raise EvidenceError("source commit timestamp provenance mismatch")
    builder = provenance.get("builder") or {}
    if set(builder) != {"path", "sha256", "helper_path", "helper_sha256"}:
        raise EvidenceError("builder provenance contains unexpected fields")
    if (
        builder.get("path") != SUPPLY_TOOL_PATH
        or builder.get("helper_path") != HELPER_TOOL_PATH
        or not re.fullmatch(r"[0-9a-f]{64}", str(builder.get("sha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(builder.get("helper_sha256", "")))
    ):
        raise EvidenceError("supply builder provenance mismatch")
    artifact = provenance.get("artifact") or {}
    if set(artifact) != {"name", "archive_digest", "attestation_subject"}:
        raise EvidenceError("artifact provenance contains unexpected fields")
    if (
        artifact.get("archive_digest") != "published-after-upload"
        or artifact.get("attestation_subject")
        != "actions/upload-artifact artifact-digest output"
    ):
        raise EvidenceError("artifact provenance binding mismatch")
    workflow = provenance.get("workflow") or {}
    runner = provenance.get("runner") or {}
    if set(workflow) != {"path", "sha256", "ref", "run_id", "run_attempt"}:
        raise EvidenceError("workflow provenance contains unexpected fields")
    if set(runner) != {"os", "arch", "name", "image_os", "image_version"}:
        raise EvidenceError("runner provenance contains unexpected fields")
    for label, value in (
        ("runner OS", runner.get("os")),
        ("runner architecture", runner.get("arch")),
        ("runner name", runner.get("name")),
        ("runner image OS", runner.get("image_os")),
        ("runner image version", runner.get("image_version")),
        ("scan timestamp", provenance.get("scan_timestamp")),
    ):
        _present(label, value)
    if mode == "exact-commit":
        if workflow.get("path") != WORKFLOW_PATH or not re.fullmatch(
            r"[0-9a-f]{64}", str(workflow.get("sha256", ""))
        ):
            raise EvidenceError("workflow provenance mismatch")
        if artifact.get("name") != "plan-005-release-{}".format(commit):
            raise EvidenceError("artifact name is not bound to the exact commit")
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", str(provenance.get("repository", ""))):
            raise EvidenceError("GitHub repository provenance is malformed")
        _present("workflow ref", workflow.get("ref"))
        if not str(workflow.get("run_id", "")).isdigit() or not str(
            workflow.get("run_attempt", "")
        ).isdigit():
            raise EvidenceError("workflow run provenance is malformed")
    else:
        expected_runner = {
            "os": platform.system(),
            "arch": platform.machine(),
            "name": "diagnostic-local",
            "image_os": platform.platform(),
            "image_version": "diagnostic-local",
        }
        if provenance.get("repository") != "diagnostic/local":
            raise EvidenceError("diagnostic repository provenance mismatch")
        if workflow.get("ref") != "diagnostic-not-a-workflow-run" or (
            workflow.get("run_id"), workflow.get("run_attempt")
        ) != ("0", "0"):
            raise EvidenceError("diagnostic workflow provenance mismatch")
        if workflow.get("path") == "pending-T089":
            if workflow.get("sha256") != "0" * 64:
                raise EvidenceError("diagnostic pending-workflow provenance mismatch")
        elif workflow.get("path") != WORKFLOW_PATH or not re.fullmatch(
            r"[0-9a-f]{64}", str(workflow.get("sha256", ""))
        ):
            raise EvidenceError("diagnostic workflow provenance mismatch")
        if runner != expected_runner:
            raise EvidenceError("diagnostic runner provenance mismatch")
        if artifact.get("name") != "plan-005-supply-diagnostic":
            raise EvidenceError("diagnostic artifact provenance mismatch")


def _json_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _json_strings(item)


def _scan_fragments(path: Path, text: str) -> Iterable[str]:
    fragments = [text]
    if path.suffix.lower() == ".json":
        try:
            fragments.extend(_json_strings(json.loads(text)))
        except json.JSONDecodeError:
            # Semantic validators report malformed JSON. The raw representation is
            # still scanned here so this pass cannot become a parser oracle.
            pass
    seen = set()
    for fragment in fragments:
        decoded = fragment
        for _ in range(17):
            if decoded not in seen:
                seen.add(decoded)
                yield decoded
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        else:
            raise EvidenceError("excessively nested URL encoding in evidence")


def scan_text_paths(
    paths: Iterable[Path], allowed_private_markers: Sequence[str] = ()
) -> None:
    for path in paths:
        if path.is_symlink():
            raise EvidenceError("evidence scan encountered a symlink")
        if not path.is_file():
            raise EvidenceError("evidence scan path is not a regular file")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise EvidenceError("oversized text evidence in {}".format(path.name))
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        for fragment in _scan_fragments(path, text):
            for marker in allowed_private_markers:
                fragment = fragment.replace(marker, "<synthetic-private-path>")
                fragment = fragment.replace(
                    marker.replace("/", "\\"), "<synthetic-private-path>"
                )
            if any(pattern.search(fragment) for pattern in SECRET_PATTERNS):
                raise EvidenceError("secret-like material in {}".format(path.name))
            if any(pattern.search(fragment) for pattern in PRIVATE_PATH_PATTERNS):
                raise EvidenceError("private path in {}".format(path.name))


def _clean_environment(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    allowed = {
        "CARGO_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "RUSTUP_HOME",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
    }
    result = {key: value for key, value in os.environ.items() if key in allowed}
    result.update(
        {
            "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "credential.helper",
            "GIT_CONFIG_VALUE_0": "",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    if extra:
        result.update(extra)
    return result


def _redact_message(
    message: str,
    repository: Optional[Path] = None,
    private_replacements: Sequence[Tuple[str, str]] = (),
) -> str:
    result = message
    replacements = [(str(Path.home()), "<home>")]
    if repository is not None:
        replacements.append((str(repository), "<repo>"))
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        replacements.append((workspace, "<workspace>"))
    replacements.extend(private_replacements)
    for raw, replacement in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        result = result.replace(raw, replacement)
        result = result.replace(raw.replace("/", "\\"), replacement)
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("<redacted-secret>", result)
    for pattern in PRIVATE_PATH_PATTERNS:
        result = pattern.sub("<redacted-private-path>", result)
    return result.strip()[:2000]


def _run_checked(
    argv: Sequence[str],
    cwd: Path,
    *,
    extra_environment: Optional[Dict[str, str]] = None,
) -> str:
    completed = subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=_clean_environment(extra_environment),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        detail = _redact_message(completed.stderr or completed.stdout, cwd)
        command = " ".join(Path(item).name if "/" in item else item for item in argv[:3])
        raise EvidenceError("command failed ({}): {}".format(command, detail))
    return completed.stdout.strip()


def _git_revision(repository: Path, revision: str = "HEAD") -> str:
    return _run_checked(
        ["git", "rev-parse", "{}^{{commit}}".format(revision)], repository
    )


def _git_tree(repository: Path, revision: str = "HEAD") -> str:
    return _run_checked(
        ["git", "rev-parse", "{}^{{tree}}".format(revision)], repository
    )


def _git_timestamp(repository: Path, revision: str = "HEAD") -> str:
    return _run_checked(
        ["git", "show", "-s", "--format=%cI", "{}^{{commit}}".format(revision)],
        repository,
    )


def _tracked_checkout_clean(repository: Path) -> bool:
    for relative in (
        ".cargo/config",
        ".cargo/config.toml",
        "kernel/.cargo/config",
        "kernel/.cargo/config.toml",
    ):
        if (repository / relative).exists():
            return False
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=str(repository),
        env=_clean_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0 and not completed.stdout


def _validate_repository(repository: Path) -> Path:
    repository = repository.resolve()
    if not (repository / ".git").exists() or not (repository / "kernel" / "Cargo.toml").is_file():
        raise EvidenceError("repository is not a HelixOS Git checkout")
    return repository


def _path_has_unsafe_symlink(path: Path) -> bool:
    unresolved = path.absolute()
    allowed_system_aliases = {Path("/tmp"), Path("/var")}
    return any(
        candidate.is_symlink() and candidate not in allowed_system_aliases
        for candidate in [unresolved] + list(unresolved.parents)
    )


def _validate_output_location(repository: Path, output: Path) -> Path:
    unresolved = output.absolute()
    if _path_has_unsafe_symlink(unresolved):
        raise EvidenceError("output path or parent is a symlink")
    output = unresolved.resolve()
    if output == repository or output == repository / ".git":
        raise EvidenceError("output overlaps the repository control root")
    try:
        relative = output.relative_to(repository)
    except ValueError:
        relative = None
    if relative is not None and (
        not relative.parts or relative.parts[0] != "plan-005-release-evidence"
    ):
        raise EvidenceError(
            "repository-local output must be under plan-005-release-evidence"
        )
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise EvidenceError("output directory must be absent or empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def _verify_pinned_checkout(path: Path, revision: str, label: str) -> Path:
    unresolved = path.absolute()
    if _path_has_unsafe_symlink(unresolved):
        raise EvidenceError("{} pinned checkout is absent or unsafe".format(label))
    path = unresolved.resolve()
    if not (path / ".git").is_dir() or (path / ".git").is_symlink():
        raise EvidenceError("{} pinned checkout is absent or unsafe".format(label))
    if _git_revision(path) != revision:
        raise EvidenceError("{} pinned revision mismatch".format(label))
    status = _run_checked(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], path
    )
    if status:
        raise EvidenceError("{} pinned checkout has tracked modifications".format(label))
    return path


def _ensure_pinned_checkout(
    supplied: Optional[str],
    *,
    label: str,
    url: str,
    revision: str,
    cache_name: str,
) -> Path:
    if supplied:
        return _verify_pinned_checkout(Path(supplied), revision, label)
    cache_root = Path.home() / ".cache" / "helixos" / "plan005-supply-inputs"
    destination = cache_root / "{}-{}".format(cache_name, revision)
    if destination.exists():
        return _verify_pinned_checkout(destination, revision, label)
    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=".{}-".format(cache_name), dir=str(cache_root))
    )
    try:
        _run_checked(["git", "init", "--quiet"], temporary)
        _run_checked(["git", "remote", "add", "origin", url], temporary)
        _run_checked(
            ["git", "fetch", "--quiet", "--depth=1", "origin", revision],
            temporary,
        )
        _run_checked(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], temporary)
        _verify_pinned_checkout(temporary, revision, label)
        try:
            temporary.rename(destination)
        except FileExistsError:
            shutil.rmtree(str(temporary), ignore_errors=True)
        return _verify_pinned_checkout(destination, revision, label)
    except Exception:
        shutil.rmtree(str(temporary), ignore_errors=True)
        raise


def _load_metadata(repository: Path) -> dict:
    raw = _run_checked(
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
        raise EvidenceError("cargo metadata JSON is invalid: {}".format(error))
    if not isinstance(metadata, dict):
        raise EvidenceError("cargo metadata is not an object")
    return metadata


def _collect_cyclonedx_sboms(repository: Path, source_epoch: str) -> List[dict]:
    token = secrets.token_hex(8)
    filename = ".plan005-{}-{}".format(os.getpid(), token)
    member_directories = sorted(
        path.parent
        for path in (repository / "kernel").glob("*/Cargo.toml")
        if path.is_file() and not path.is_symlink()
    )
    generated = [directory / "{}.json".format(filename) for directory in member_directories]
    try:
        for destination in generated:
            if destination.exists() or destination.is_symlink():
                raise EvidenceError("temporary CycloneDX output already exists")
        _run_checked(
            [
                "cargo",
                "cyclonedx",
                "--manifest-path",
                "kernel/Cargo.toml",
                "--format",
                "json",
                "--all-features",
                "--target",
                "all",
                "--spec-version",
                "1.5",
                "--override-filename",
                filename,
            ],
            repository,
            extra_environment={"SOURCE_DATE_EPOCH": source_epoch},
        )
        documents = []
        for root in PRODUCTION_ROOTS:
            destination = repository / "kernel" / root / "{}.json".format(filename)
            if not destination.is_file() or destination.is_symlink():
                raise EvidenceError(
                    "cargo-cyclonedx did not produce the expected {} JSON".format(root)
                )
            document = load_json(destination)
            if not isinstance(document, dict):
                raise EvidenceError("cargo-cyclonedx output is not a JSON object")
            documents.append(document)
        return documents
    finally:
        for path in generated:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _copy_reviewed_inputs(
    repository: Path, bundle: Path, include_workflow: bool
) -> List[dict]:
    paths = list(CORE_REVIEWED_INPUT_PATHS)
    if include_workflow:
        paths.append(WORKFLOW_PATH)
    entries = []
    for relative in paths:
        source = repository / relative
        if not source.is_file() or source.is_symlink():
            raise EvidenceError("reviewed input is missing or unsafe: {}".format(relative))
        destination = bundle / "reviewed-inputs" / relative
        plan004._copy_file(source, destination)
        entries.append({"path": relative, "sha256": sha256_file(destination)})
    return entries


def _git_file_sha256(repository: Path, commit: str, relative: str) -> str:
    completed = subprocess.run(
        ["git", "show", "{}:{}".format(commit, relative)],
        cwd=str(repository),
        env=_clean_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise EvidenceError("reviewed input is absent from exact commit: {}".format(relative))
    return _sha256_bytes(completed.stdout)


def _validate_reviewed_inputs(
    root: Path,
    repository: Path,
    entries: object,
    commit: str,
    exact_mode: bool,
) -> None:
    if not isinstance(entries, list):
        raise EvidenceError("release descriptor lacks reviewed inputs")
    indexed = {}
    for entry in entries:
        relative = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(relative, str)
            or relative in indexed
            or set(entry) != {"path", "sha256"}
            or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
        ):
            raise EvidenceError("reviewed input inventory is malformed")
        indexed[relative] = digest
    expected = set(CORE_REVIEWED_INPUT_PATHS)
    workflow_exists = (repository / WORKFLOW_PATH).is_file()
    if exact_mode and not workflow_exists:
        raise EvidenceError("exact-commit bundle requires the PLAN-005 workflow")
    if workflow_exists:
        expected.add(WORKFLOW_PATH)
    if set(indexed) != expected:
        raise EvidenceError("reviewed input set is incomplete")
    for relative, digest in indexed.items():
        retained = plan004._bundle_file(root, "reviewed-inputs/{}".format(relative))
        current = repository / relative
        if sha256_file(retained) != digest or sha256_file(current) != digest:
            raise EvidenceError("reviewed input digest mismatch: {}".format(relative))
        if exact_mode and _git_file_sha256(repository, commit, relative) != digest:
            raise EvidenceError("reviewed input differs from exact commit: {}".format(relative))


def _build_license_inventory(
    metadata: dict,
    selected_ids: Set[str],
    cargo_lock: Path,
    spdx_root: Path,
    bundle: Path,
) -> dict:
    inventory = plan004._copy_license_evidence(
        metadata, selected_ids, cargo_lock, spdx_root, bundle
    )
    inventory.pop("root_package", None)
    inventory["schema"] = LICENSE_SCHEMA
    inventory["root_packages"] = list(PRODUCTION_ROOTS)
    inventory[
        "scope"
    ] = "union-normal-and-build-dependency-closure-with-all-features-and-targets"
    write_json(bundle / "licenses" / "inventory.json", inventory)
    return inventory


def _validate_license_inventory(
    root: Path,
    inventory: dict,
    metadata: dict,
    identities: Set[Tuple[str, str, str]],
    repository: Path,
) -> None:
    if (
        inventory.get("schema") != LICENSE_SCHEMA
        or inventory.get("root_packages") != list(PRODUCTION_ROOTS)
        or inventory.get("spdx_license_list_revision") != EXPECTED_SPDX_REVISION
        or inventory.get("scope")
        != "union-normal-and-build-dependency-closure-with-all-features-and-targets"
    ):
        raise EvidenceError("PLAN-005 license/SPDX inventory identity mismatch")
    compatible = copy.deepcopy(inventory)
    compatible["schema"] = "helixos.plan-004-license-inventory/1"
    compatible["root_package"] = METADATA_ROOT
    compatible.pop("root_packages", None)
    compatible[
        "scope"
    ] = "normal-and-build-dependency-closure-with-all-targets"
    plan004._validate_license_inventory(
        root, compatible, metadata, identities, repository
    )
    metadata_packages = {
        (
            package.get("name"),
            package.get("version"),
            package.get("source") or "workspace-path",
        ): package
        for package in metadata.get("packages", [])
        if isinstance(package, dict)
    }
    inventory_packages = {
        (entry.get("name"), entry.get("version"), entry.get("source")): entry
        for entry in inventory.get("packages", [])
        if isinstance(entry, dict)
    }
    lock_checksums = parse_lock_packages(
        (repository / "kernel" / "Cargo.lock").read_text(encoding="utf-8")
    )
    for package_identity in identities:
        package = metadata_packages[package_identity]
        entry = inventory_packages[package_identity]
        expected_expression = package.get("license") or "NOASSERTION"
        if entry.get("license_expression") != expected_expression:
            raise EvidenceError("license inventory expression differs from cargo metadata")
        if package_identity[2] == "workspace-path":
            continue
        archive = plan004._find_crate_archive(
            Path(package["manifest_path"]), package_identity[0], package_identity[1]
        )
        expected_archive_digest = lock_checksums.get(package_identity)
        if not expected_archive_digest or sha256_file(archive) != expected_archive_digest:
            raise EvidenceError("registry crate archive differs from Cargo.lock checksum")
        archive_prefix = "{}-{}/".format(package_identity[0], package_identity[1])
        retained_prefix = "licenses/packages/{}-{}/".format(
            re.sub(r"[^A-Za-z0-9._+-]", "_", package_identity[0]),
            re.sub(r"[^A-Za-z0-9._+-]", "_", package_identity[1]),
        )
        with tarfile.open(archive, "r:gz") as crate:
            for retained in entry.get("retained_files", []):
                relative = retained.get("path") if isinstance(retained, dict) else None
                if not isinstance(relative, str) or not relative.startswith(retained_prefix):
                    raise EvidenceError("retained registry license path is not package-bound")
                archive_member = archive_prefix + relative[len(retained_prefix) :]
                try:
                    member = crate.getmember(archive_member)
                except KeyError:
                    raise EvidenceError(
                        "retained registry license file is absent from locked crate"
                    )
                extracted = crate.extractfile(member) if member.isfile() else None
                if extracted is None:
                    raise EvidenceError("retained registry license source is not a file")
                digest = _sha256_bytes(extracted.read())
                if digest != retained.get("sha256"):
                    raise EvidenceError(
                        "retained registry license source differs from locked crate"
                    )


def validate_release_oracle(graph: dict, inventory: dict) -> None:
    actual = {
        "package_count": graph.get("package_count"),
        "dependency_edge_count": graph.get("dependency_edge_count"),
        "external_package_count": inventory.get("external_package_count"),
        "workspace_package_count": inventory.get("workspace_package_count"),
        "spdx_text_count": len(inventory.get("spdx_texts", []))
        if isinstance(inventory.get("spdx_texts"), list)
        else None,
    }
    if actual != EXPECTED_RELEASE_ORACLE:
        raise EvidenceError("PLAN-005 release graph/license oracle mismatch")
    if inventory.get("package_count") != EXPECTED_RELEASE_ORACLE["package_count"]:
        raise EvidenceError("PLAN-005 license package-count oracle mismatch")
    spdx = {
        entry.get("identifier"): (entry.get("kind"), entry.get("sha256"))
        for entry in inventory.get("spdx_texts", [])
        if isinstance(entry, dict)
    }
    if spdx != EXPECTED_SPDX_TEXTS:
        raise EvidenceError("PLAN-005 pinned SPDX text oracle mismatch")


def validate_release_artifact_oracles(root: Path) -> None:
    for relative, expected in EXPECTED_RELEASE_ARTIFACT_SHA256.items():
        if sha256_file(root / relative) != expected:
            raise EvidenceError(
                "PLAN-005 immutable release artifact oracle mismatch: {}".format(
                    relative
                )
            )


def _build_native_evidence(
    metadata: dict,
    selected_ids: Set[str],
    repository: Path,
    bundle: Path,
) -> Tuple[dict, SQLiteSource]:
    package, sqlite_c, sqlite_h, archive = plan004._sqlite_source(metadata, selected_ids)
    lock_checksums = parse_lock_packages(
        (repository / "kernel" / "Cargo.lock").read_text(encoding="utf-8")
    )
    archive_checksum = lock_checksums.get(
        ("libsqlite3-sys", EXPECTED_LIBSQLITE_VERSION, package.get("source"))
    )
    if not archive_checksum or sha256_file(archive) != archive_checksum:
        raise EvidenceError("libsqlite3-sys archive does not match Cargo.lock")
    for source, destination in (
        (archive, bundle / "native" / archive.name),
        (sqlite_c, bundle / "native" / "sqlite3.c"),
        (sqlite_h, bundle / "native" / "sqlite3.h"),
    ):
        plan004._copy_file(source, destination)
    features = resolved_sqlite_features(metadata, selected_ids)
    forbidden = set(expected_supply_identity()["native_sqlite"]["forbidden_features"])
    enabled = set(features["rusqlite"]) | set(features["libsqlite3-sys"])
    if forbidden.intersection(enabled):
        raise EvidenceError("resolved SQLite graph enables a forbidden feature")
    source = SQLiteSource(
        EXPECTED_SQLITE_VERSION, EXPECTED_SQLITE_SOURCE_ID, sha256_file(sqlite_c)
    )
    native = {
        "schema": NATIVE_SCHEMA,
        "libsqlite3_sys_version": EXPECTED_LIBSQLITE_VERSION,
        "libsqlite3_sys_crate_sha256": archive_checksum,
        "rusqlite_version": EXPECTED_RUSQLITE_VERSION,
        "sqlite_version": EXPECTED_SQLITE_VERSION,
        "sqlite_source_id": EXPECTED_SQLITE_SOURCE_ID,
        "sqlite3_c_sha256": source.source_sha256,
        "sqlite3_h_sha256": sha256_file(sqlite_h),
        "link_profile": expected_supply_identity()["native_sqlite"]["link_profile"],
        "resolved_features": features,
        "forbidden_features_absent": sorted(forbidden),
        "license": "Public Domain notice embedded in retained sqlite3.c/sqlite3.h",
    }
    write_json(bundle / "native" / "sqlite3-source-metadata.json", native)
    return native, source


def _validate_native_evidence(
    root: Path,
    native: dict,
    metadata: dict,
    selected_ids: Set[str],
    repository: Path,
) -> SQLiteSource:
    identity = expected_supply_identity()["native_sqlite"]
    expected_keys = {
        "schema",
        "libsqlite3_sys_version",
        "libsqlite3_sys_crate_sha256",
        "rusqlite_version",
        "sqlite_version",
        "sqlite_source_id",
        "sqlite3_c_sha256",
        "sqlite3_h_sha256",
        "link_profile",
        "resolved_features",
        "forbidden_features_absent",
        "license",
    }
    if (
        set(native) != expected_keys
        or native.get("schema") != NATIVE_SCHEMA
        or native.get("rusqlite_version") != EXPECTED_RUSQLITE_VERSION
        or native.get("forbidden_features_absent")
        != sorted(identity["forbidden_features"])
        or native.get("license")
        != "Public Domain notice embedded in retained sqlite3.c/sqlite3.h"
    ):
        raise EvidenceError("retained PLAN-005 SQLite identity is invalid")
    compatible = copy.deepcopy(native)
    compatible["schema"] = "helixos.plan-004-native-sqlite/1"
    compatible.pop("rusqlite_version", None)
    compatible.pop("forbidden_features_absent", None)
    sqlite = plan004._validate_native_evidence(
        root, compatible, metadata, selected_ids, repository
    )
    enabled = set(native.get("resolved_features", {}).get("rusqlite", [])) | set(
        native.get("resolved_features", {}).get("libsqlite3-sys", [])
    )
    if set(identity["forbidden_features"]).intersection(enabled):
        raise EvidenceError("retained SQLite evidence enables a forbidden feature")
    return sqlite


def _copy_tool_text(
    text: str, destination: Path, repository: Path
) -> str:
    normalized = _normalize_tool_text(text, repository)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(normalized + "\n", encoding="utf-8")
    return normalized


def _normalize_tool_text(text: str, repository: Path) -> str:
    normalized = text.replace("\r\n", "\n")
    for raw, replacement in (
        (str(repository), "<repo>"),
        (str(Path.home()), "<home>"),
    ):
        normalized = normalized.replace(raw, replacement)
        normalized = normalized.replace(raw.replace("/", "\\"), replacement)
    return normalized.strip()


def _collect_toolchain(repository: Path, bundle: Path) -> Dict[str, str]:
    outputs = {
        "rustc-version.txt": _run_checked(["rustc", "--version", "--verbose"], repository),
        "cargo-version.txt": _run_checked(["cargo", "--version", "--verbose"], repository),
        "cargo-cyclonedx-version.txt": _run_checked(
            ["cargo", "cyclonedx", "--version"], repository
        ),
        "cargo-audit-version.txt": _run_checked(["cargo", "audit", "--version"], repository),
        "python-version.txt": platform.python_version(),
    }
    tree_sections = []
    for root in PRODUCTION_ROOTS:
        tree = _run_checked(
            [
                "cargo",
                "tree",
                "--locked",
                "--manifest-path",
                "kernel/Cargo.toml",
                "--package",
                root,
                "--edges",
                "features",
                "--target",
                "all",
            ],
            repository,
        )
        tree_sections.append("[{}]\n{}".format(root, tree))
    outputs["cargo-tree.txt"] = "\n\n".join(tree_sections)
    for filename, text in outputs.items():
        outputs[filename] = _copy_tool_text(
            text, bundle / "toolchain" / filename, repository
        )
    if "rustc {} ".format(EXPECTED_RUST_VERSION) not in outputs["rustc-version.txt"]:
        raise EvidenceError("Rust compiler is not pinned to {}".format(EXPECTED_RUST_VERSION))
    if "cargo {} ".format(EXPECTED_RUST_VERSION) not in outputs["cargo-version.txt"]:
        raise EvidenceError("Cargo is not pinned to {}".format(EXPECTED_RUST_VERSION))
    plan004._require_tool_version(
        outputs["cargo-cyclonedx-version.txt"],
        "cargo-cyclonedx",
        EXPECTED_CYCLONEDX_VERSION,
    )
    plan004._require_tool_version(
        outputs["cargo-audit-version.txt"], "cargo-audit", EXPECTED_AUDIT_VERSION
    )
    digests = []
    for executable in ("cargo-cyclonedx", "cargo-audit"):
        path = shutil.which(executable, path=_clean_environment().get("PATH"))
        if not path:
            raise EvidenceError("pinned evidence tool is not installed: {}".format(executable))
        digests.append("{}  {}".format(sha256_file(Path(path)), executable))
    _copy_tool_text(
        "\n".join(digests),
        bundle / "toolchain" / "tool-binary-digests.txt",
        repository,
    )
    return outputs


def _validate_toolchain_files(root: Path, repository: Path) -> None:
    plan004._validate_toolchain_files(root)
    expected = {
        "rustc-version.txt": _run_checked(
            ["rustc", "--version", "--verbose"], repository
        ),
        "cargo-version.txt": _run_checked(
            ["cargo", "--version", "--verbose"], repository
        ),
        "cargo-cyclonedx-version.txt": _run_checked(
            ["cargo", "cyclonedx", "--version"], repository
        ),
        "cargo-audit-version.txt": _run_checked(
            ["cargo", "audit", "--version"], repository
        ),
        "python-version.txt": platform.python_version(),
    }
    tree_sections = []
    for package in PRODUCTION_ROOTS:
        tree_sections.append(
            "[{}]\n{}".format(
                package,
                _run_checked(
                    [
                        "cargo",
                        "tree",
                        "--locked",
                        "--manifest-path",
                        "kernel/Cargo.toml",
                        "--package",
                        package,
                        "--edges",
                        "features",
                        "--target",
                        "all",
                    ],
                    repository,
                ),
            )
        )
    expected["cargo-tree.txt"] = "\n\n".join(tree_sections)
    for filename, live in expected.items():
        retained = (root / "toolchain" / filename).read_text(encoding="utf-8")
        if retained != _normalize_tool_text(live, repository) + "\n":
            raise EvidenceError("retained toolchain output differs from live pinned tool")
    live_digests = []
    for executable in ("cargo-cyclonedx", "cargo-audit"):
        path = shutil.which(executable, path=_clean_environment().get("PATH"))
        if not path:
            raise EvidenceError("pinned evidence tool is unavailable during verification")
        live_digests.append("{}  {}".format(sha256_file(Path(path)), executable))
    retained_digests = (
        root / "toolchain" / "tool-binary-digests.txt"
    ).read_text(encoding="utf-8")
    if retained_digests != "\n".join(live_digests) + "\n":
        raise EvidenceError("retained evidence-tool binary digest mismatch")


def _run_rustsec_scan(
    repository: Path,
    advisory_db: Path,
    bundle: Path,
    scan_timestamp: str,
) -> dict:
    argv = [
        "cargo",
        "audit",
        "--db",
        str(advisory_db),
        "--no-fetch",
        "--file",
        "kernel/Cargo.lock",
        "--json",
    ]
    completed = subprocess.run(
        argv,
        cwd=str(repository),
        env=_clean_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        detail = _redact_message(completed.stderr or completed.stdout, repository)
        raise EvidenceError("cargo-audit JSON is invalid: {}: {}".format(error, detail))
    if not isinstance(report, dict):
        raise EvidenceError("cargo-audit report is not a JSON object")
    validate_audit_report(report)
    if completed.returncode != 0:
        raise EvidenceError("cargo-audit returned a failing status")
    write_json(bundle / "rustsec" / "report.json", report)
    validate_rustsec_report_oracle(bundle / "rustsec" / "report.json")
    _copy_tool_text(
        completed.stderr,
        bundle / "rustsec" / "stderr.txt",
        repository,
    )
    advisory_revision = _git_revision(advisory_db)
    if advisory_revision != EXPECTED_RUSTSEC_REVISION:
        raise EvidenceError("RustSec advisory database revision mismatch")
    database = {
        "schema": "helixos.rustsec-database-evidence/1",
        "cargo_audit_version": EXPECTED_AUDIT_VERSION,
        "database_revision": advisory_revision,
        "database_commit_timestamp": _git_timestamp(advisory_db),
        "scan_timestamp": scan_timestamp,
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
    }
    write_json(bundle / "rustsec" / "database.json", database)
    return report


def validate_rustsec_report_oracle(path: Path) -> None:
    if sha256_file(path) != EXPECTED_RUSTSEC_REPORT_SHA256:
        raise EvidenceError("RustSec report differs from pinned PLAN-005 oracle")


def _text_bundle_files(root: Path) -> List[Path]:
    result = []
    for path in plan004._manifest_files(root):
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > 16 * 1024 * 1024:
            if relative == "native/libsqlite3-sys-0.38.1.crate":
                continue
            raise EvidenceError("oversized retained evidence file: {}".format(relative))
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue
        result.append(path)
    return result


def _scan_bundle(root: Path, repository: Path) -> None:
    text_files = _text_bundle_files(root)
    exact_private_values = {
        str(repository),
        str(Path.home()),
        os.environ.get("GITHUB_WORKSPACE", ""),
    }
    exact_private_values.discard("")
    for path in text_files:
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        fragments = list(_scan_fragments(path, text))
        if any(
            pattern.search(fragment)
            for fragment in fragments
            for pattern in SECRET_PATTERNS
        ):
            raise EvidenceError("secret-like material in retained {}".format(relative))
        for private in exact_private_values:
            variants = {
                private,
                private.replace("/", "\\"),
                json.dumps(private)[1:-1],
                json.dumps(private.replace("/", "\\"))[1:-1],
            }
            if any(
                value and value in fragment
                for fragment in fragments
                for value in variants
            ):
                raise EvidenceError("machine-local path in retained {}".format(relative))

        third_party = relative.startswith(
            ("licenses/packages/", "licenses/spdx/", "native/sqlite3.")
        )
        if third_party:
            continue
        if relative in {
            "reviewed-inputs/tools/plan005_supply_chain.py",
            "reviewed-inputs/tools/tests/test_plan005_evidence.py",
        }:
            # These retained first-party files define and exercise the generic path
            # regexes being executed here. Exact current-machine values and secrets
            # were still checked above; re-running the generic regex over its own
            # pattern/fixture source would be a guaranteed self-match.
            continue
        scan_text_paths([path])


def _expected_removal_commands() -> List[Tuple[str, List[str], str]]:
    common = [
        "--locked",
        "--offline",
        "--manifest-path",
        "kernel/Cargo.toml",
        "--all-targets",
        "--all-features",
    ]
    return [
        (
            "metadata-after-removal",
            [
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
                "kernel/Cargo.toml",
            ],
            "metadata-after-removal.json",
        ),
        (
            "plan-001-contracts",
            ["cargo", "test", *common, "--package", "helix-contracts", "--", "--test-threads=1"],
            "logs/plan-001-contracts.txt",
        ),
        (
            "plan-002-eligibility",
            [
                "cargo",
                "test",
                *common,
                "--package",
                "helix-plan-eligibility",
                "--",
                "--test-threads=1",
            ],
            "logs/plan-002-eligibility.txt",
        ),
        (
            "plan-003-replay",
            ["cargo", "test", *common, "--package", "helix-replay-sqlite", "--", "--test-threads=1"],
            "logs/plan-003-replay.txt",
        ),
        (
            "plan-004-preparation",
            [
                "cargo",
                "test",
                *common,
                "--package",
                "helix-plan-preparation",
                "--package",
                "helix-coordinator-sqlite",
                "--",
                "--test-threads=1",
            ],
            "logs/plan-004-preparation.txt",
        ),
        (
            "legacy-mvp0",
            [
                "cargo",
                "test",
                *common,
                "--package",
                "helixos-kernel",
                "--package",
                "helixos-mcp-shim",
                "--package",
                "helixos-provision",
                "--",
                "--test-threads=1",
            ],
            "logs/legacy-mvp0.txt",
        ),
    ]


def _validate_removal_protected_record(
    record: object, expected_mode: str, expected_digest: str
) -> str:
    if not isinstance(record, dict) or set(record) != {
        "expected_mode",
        "expected_sha256",
        "observed_mode",
        "observed_sha256",
        "mode_verification",
        "matches_baseline",
    }:
        raise EvidenceError("retained removal protected-file record mismatch")
    verification = record.get("mode_verification")
    observed_mode = record.get("observed_mode")
    if (
        verification not in {"filesystem-and-git-index", "git-index"}
        or record.get("expected_mode") != expected_mode
        or record.get("expected_sha256") != expected_digest
        or observed_mode not in {"100644", "100755"}
        or (
            verification == "filesystem-and-git-index"
            and observed_mode != expected_mode
        )
        or record.get("observed_sha256") != expected_digest
        or record.get("matches_baseline") is not True
    ):
        raise EvidenceError("retained removal protected-file record mismatch")
    return verification


def _validate_removal_evidence(root: Path, repository: Path, commit: str, tree: str) -> None:
    report = load_json(plan004._bundle_file(root, "removal/report.json"))
    before = load_json(plan004._bundle_file(root, "removal/protected-files-before.json"))
    after = load_json(plan004._bundle_file(root, "removal/protected-files-after.json"))
    inventory = load_json(plan004._bundle_file(root, "removal/removal-inventory.json"))
    metadata = load_json(plan004._bundle_file(root, "removal/metadata-after-removal.json"))
    if not all(isinstance(value, dict) for value in (report, before, after, inventory, metadata)):
        raise EvidenceError("retained PLAN-005 removal evidence is malformed")
    if (
        report.get("schema") != "helixos.plan-005-removal-drill/1"
        or report.get("acceptance_id") != "PLAN-005"
        or report.get("result") != "passing-isolated-exact-commit-removal"
        or report.get("evidence_scope") != "exact-commit"
        or report.get("source_mode") != "exact-commit"
        or report.get("source_commit") != commit
        or report.get("source_head_commit") != commit
        or report.get("source_commit_tree") != tree
        or report.get("baseline_commit") != REMOVAL_BASELINE
        or report.get("protected_manifest_sha256") != REMOVAL_MANIFEST_SHA256
        or report.get("protected_file_count") != 495
        or report.get("protected_baseline_restored_exactly") is not True
        or report.get("tests_skipped") is not False
        or report.get("sc009_exact_commit_eligible") is not True
        or report.get("immutable_release_evidence_eligible") is not True
    ):
        raise EvidenceError("retained PLAN-005 removal identity/result is invalid")
    if before != after or len(before) != 495:
        raise EvidenceError("retained removal protected-file comparison is inconsistent")
    protected_manifest_path = (
        repository
        / "specs"
        / "005-durable-dispatch"
        / "evidence"
        / "removal-protected-files.json"
    )
    try:
        protected_manifest = removal.load_and_validate_manifest(
            repository, protected_manifest_path, REMOVAL_BASELINE
        )
    except removal.EvidenceError as error:
        raise EvidenceError("current protected removal manifest is invalid: {}".format(error))
    manifest_baseline = protected_manifest.get("baseline") or {}
    if (
        manifest_baseline.get("commit") != REMOVAL_BASELINE
        or report.get("baseline_tree") != manifest_baseline.get("tree")
        or report.get("post_removal_index_tree") != manifest_baseline.get("tree")
        or report.get("ignored_user_owned_working_tree_paths") != []
    ):
        raise EvidenceError("retained removal baseline/exclusion binding mismatch")
    expected_entries = {
        entry["path"]: (entry["mode"], entry["content_sha256"])
        for entry in protected_manifest.get("entries", [])
    }
    if set(before) != set(expected_entries):
        raise EvidenceError("retained removal protected-file set is incomplete")
    verification_profiles = set()
    for relative, record in before.items():
        mode, digest = expected_entries[relative]
        verification_profiles.add(
            _validate_removal_protected_record(record, mode, digest)
        )
    if len(verification_profiles) != 1:
        raise EvidenceError("retained removal mode-verification profile is inconsistent")
    baseline_entries = {
        entry["path"]: entry for entry in protected_manifest.get("entries", [])
    }
    try:
        source_entries = removal._source_tree(repository, commit)
        actions = removal._classify_source_delta(
            protected_manifest, baseline_entries, source_entries
        )
        source_delta_sha256 = removal._delta_digest(source_entries, actions)
    except removal.EvidenceError as error:
        raise EvidenceError("exact removal delta cannot be recomputed: {}".format(error))
    expected_inventory = {
        "schema": "helixos.plan-005-removal-inventory/1",
        "source_mode": "exact-commit",
        "source_commit": commit,
        "source_commit_tree": tree,
        "source_delta_sha256": source_delta_sha256,
        **actions,
    }
    if inventory != expected_inventory:
        raise EvidenceError("retained removal inventory identity mismatch")
    expected_packages = {
        "helix-contracts",
        "helix-coordinator-sqlite",
        "helix-plan-eligibility",
        "helix-plan-preparation",
        "helix-replay-sqlite",
        "helixos-kernel",
        "helixos-mcp-shim",
        "helixos-provision",
    }
    if set(report.get("metadata_packages") or []) != expected_packages:
        raise EvidenceError("retained removal package set is invalid")
    expected_metadata = {
        "schema": "helixos.plan-005-removal-metadata/1",
        "workspace_package_count": 8,
        "workspace_packages": [
            {"name": name, "version": version, "source": "workspace-path"}
            for name, version in (
                ("helix-contracts", "0.1.0"),
                ("helix-coordinator-sqlite", "0.1.0"),
                ("helix-plan-eligibility", "0.1.0"),
                ("helix-plan-preparation", "0.1.0"),
                ("helix-replay-sqlite", "0.1.0"),
                ("helixos-kernel", "0.0.1"),
                ("helixos-mcp-shim", "0.0.1"),
                ("helixos-provision", "0.0.1"),
            )
        ],
        "workspace_root": "<removal-root>/kernel",
        "target_directory": "<cargo-target>",
    }
    if metadata != expected_metadata:
        raise EvidenceError("retained removal metadata is invalid")
    expected_commands = _expected_removal_commands()
    commands = report.get("commands")
    if not isinstance(commands, list) or len(commands) != len(expected_commands):
        raise EvidenceError("retained removal command inventory is absent")
    for command, (expected_name, expected_argv, expected_log) in zip(
        commands, expected_commands
    ):
        if not isinstance(command, dict):
            raise EvidenceError("retained removal command entry is malformed")
        name = command.get("name")
        log = command.get("log")
        digest = command.get("log_sha256")
        expected_keys = {"name", "argv", "exit_code", "log", "log_sha256"}
        if expected_name != "metadata-after-removal":
            expected_keys.add("duration_ms")
        if (
            set(command) != expected_keys
            or name != expected_name
            or command.get("argv") != expected_argv
            or log != expected_log
            or command.get("exit_code") != 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
            or (
                "duration_ms" in expected_keys
                and (
                    not isinstance(command.get("duration_ms"), int)
                    or command.get("duration_ms") < 0
                )
            )
        ):
            raise EvidenceError("retained removal command entry is invalid")
        if sha256_file(plan004._bundle_file(root, "removal/{}".format(log))) != digest:
            raise EvidenceError("retained removal command log digest mismatch")
    expected_report_values = {
        "schema": "helixos.plan-005-removal-drill/1",
        "acceptance_id": "PLAN-005",
        "result": "passing-isolated-exact-commit-removal",
        "evidence_scope": "exact-commit",
        "source_commit": commit,
        "source_commit_tree": tree,
        "source_head_commit": commit,
        "source_mode": "exact-commit",
        "source_delta_sha256": source_delta_sha256,
        "driver_sha256": sha256_file(repository / "tools" / "plan005_removal_drill.py"),
        "baseline_commit": REMOVAL_BASELINE,
        "baseline_tree": manifest_baseline.get("tree"),
        "post_removal_index_tree": manifest_baseline.get("tree"),
        "protected_manifest_sha256": REMOVAL_MANIFEST_SHA256,
        "protected_file_count": 495,
        "protected_baseline_restored_exactly": True,
        "original_working_tree_status_shape_unchanged": True,
        "original_working_tree_content_equality": "not-content-hashed",
        "ignored_user_owned_working_tree_paths": [],
        "removed_added_file_count": len(actions["removed_added_paths"]),
        "restored_baseline_file_count": len(actions["restored_baseline_paths"]),
        "retained_audit_file_count": len(actions["retained_audit_paths"]),
        "post_removal_file_count": 495 + len(actions["retained_audit_paths"]),
        "metadata_packages": sorted(expected_packages),
        "sc009_exact_commit_eligible": True,
        "immutable_release_evidence_eligible": True,
        "source_dispatch_executable_surface_after_removal": "absent-by-closed-file-and-package-inventory",
        "retained_state_authority": "not-assessed-by-source-removal-driver; combined T082 evidence required",
        "source_boundary_proof": [
            "all 495 baseline runtime and prerequisite blobs/modes are exact",
            "post-removal Cargo metadata contains only the eight PLAN-001 through PLAN-004 and legacy packages",
            "every PLAN-005 executable/derived added file matched the closed allowlist and was removed",
            "only allowlisted specifications, historical evidence, and verification tools remain outside the baseline source tree",
        ],
        "tests_skipped": False,
        "limits": protected_manifest.get("nonclaims"),
    }
    if set(report) != set(expected_report_values) | {"commands"} or any(
        report.get(key) != value for key, value in expected_report_values.items()
    ):
        raise EvidenceError("retained removal report semantics mismatch")
    if report.get("driver_sha256") != sha256_file(
        repository / "tools" / "plan005_removal_drill.py"
    ):
        raise EvidenceError("retained removal driver digest mismatch")


def _validate_closed_bundle_file_set(
    root: Path,
    descriptor: dict,
    inventory: dict,
    require_removal: bool,
) -> None:
    expected = {
        "descriptor.json",
        "identity.json",
        "provenance.json",
        "graph/production-closure.json",
        "sbom/plan-005-sbom.cdx.json",
        "licenses/inventory.json",
        "native/libsqlite3-sys-0.38.1.crate",
        "native/sqlite3.c",
        "native/sqlite3.h",
        "native/sqlite3-source-metadata.json",
        "rustsec/report.json",
        "rustsec/stderr.txt",
        "rustsec/database.json",
        "toolchain/rustc-version.txt",
        "toolchain/cargo-version.txt",
        "toolchain/cargo-cyclonedx-version.txt",
        "toolchain/cargo-audit-version.txt",
        "toolchain/python-version.txt",
        "toolchain/tool-binary-digests.txt",
        "toolchain/cargo-tree.txt",
    }
    for entry in descriptor.get("reviewed_inputs", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise EvidenceError("reviewed input file-set entry is malformed")
        expected.add("reviewed-inputs/{}".format(entry["path"]))
    for package in inventory.get("packages", []):
        if not isinstance(package, dict):
            raise EvidenceError("license package file-set entry is malformed")
        for entry in package.get("retained_files", []):
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise EvidenceError("retained license file-set entry is malformed")
            expected.add(entry["path"])
    for entry in inventory.get("spdx_texts", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise EvidenceError("retained SPDX file-set entry is malformed")
        expected.add(entry["path"])
    if require_removal:
        report = load_json(root / "removal" / "report.json")
        if not isinstance(report, dict):
            raise EvidenceError("removal report file-set source is malformed")
        expected.update(
            {
                "removal/report.json",
                "removal/protected-files-before.json",
                "removal/protected-files-after.json",
                "removal/removal-inventory.json",
                "removal/metadata-after-removal.json",
            }
        )
        for command in report.get("commands", []):
            if not isinstance(command, dict) or not isinstance(command.get("log"), str):
                raise EvidenceError("removal command file-set entry is malformed")
            expected.add("removal/{}".format(command["log"]))
    actual = {
        path.relative_to(root).as_posix() for path in plan004._manifest_files(root)
    }
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceError(
            "closed evidence bundle file set mismatch (missing={}, extra={})".format(
                missing, extra
            )
        )


def _exact_argument(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name)
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError("exact-commit build requires --{}".format(name.replace("_", "-")))
    return value


def _build_descriptor(
    provenance: dict,
    reviewed_inputs: List[dict],
    graph: dict,
    inventory: dict,
    native: dict,
    cargo_lock_sha256: str,
) -> dict:
    return {
        "schema": SCHEMA,
        "acceptance_id": "PLAN-005",
        "claim_status": CLAIM_STATUS,
        "provenance": {
            "path": "provenance.json",
            "sha256": None,
        },
        "artifact_binding": provenance["artifact"],
        "supply_chain": {
            "identity": "identity.json",
            "production_graph": "graph/production-closure.json",
            "sbom": "sbom/plan-005-sbom.cdx.json",
            "sbom_format": "CycloneDX 1.5 JSON; four-root union; bundled SQLite leaf",
            "license_inventory": "licenses/inventory.json",
            "native_sqlite": "native/sqlite3-source-metadata.json",
            "rustsec_report": "rustsec/report.json",
            "rustsec_database": "rustsec/database.json",
            "cargo_lock_sha256": cargo_lock_sha256,
            "production_package_count": graph["package_count"],
            "dependency_edge_count": graph["dependency_edge_count"],
            "external_package_count": inventory["external_package_count"],
            "workspace_package_count": inventory["workspace_package_count"],
            "spdx_text_count": len(inventory["spdx_texts"]),
            "native_sqlite_summary": native,
            "removal": "required-at-final-exact-commit-verification",
        },
        "reviewed_inputs": reviewed_inputs,
        "nonclaims": NONCLAIMS,
    }


def build_bundle(args: argparse.Namespace) -> None:
    repository = _validate_repository(Path(args.repository))
    output = _validate_output_location(repository, Path(args.output))
    head = _git_revision(repository)
    tree = _git_tree(repository)
    exact_mode = bool(args.source_commit)
    if exact_mode:
        if args.source_commit != head:
            raise EvidenceError("source commit does not equal checkout HEAD")
        if not _tracked_checkout_clean(repository):
            raise EvidenceError("exact-commit build requires a clean tracked checkout")
        if not (repository / WORKFLOW_PATH).is_file():
            raise EvidenceError("exact-commit build requires the PLAN-005 workflow")
    source_timestamp = args.source_timestamp or _git_timestamp(repository)
    scan_timestamp = args.scan_timestamp or datetime.datetime.now(
        datetime.timezone.utc
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    source_epoch = _run_checked(
        ["git", "show", "-s", "--format=%ct", head], repository
    )

    advisory_db = _ensure_pinned_checkout(
        args.advisory_db,
        label="RustSec",
        url=RUSTSEC_URL,
        revision=EXPECTED_RUSTSEC_REVISION,
        cache_name="rustsec-db",
    )
    spdx_root = _ensure_pinned_checkout(
        args.spdx_license_list,
        label="SPDX",
        url=SPDX_URL,
        revision=EXPECTED_SPDX_REVISION,
        cache_name="spdx-license-list",
    )

    temporary = Path(
        tempfile.mkdtemp(prefix=".plan005-supply-", dir=str(output.parent))
    )
    try:
        _run_checked(
            ["cargo", "fetch", "--locked", "--manifest-path", "kernel/Cargo.toml"],
            repository,
        )
        metadata = _load_metadata(repository)
        selected_ids, _root_closures = union_dependency_closure(metadata)
        identities = production_package_identities(metadata, selected_ids)
        adjacency = production_dependency_adjacency(metadata, selected_ids)
        cargo_lock = repository / "kernel" / "Cargo.lock"
        lock_text = cargo_lock.read_text(encoding="utf-8")
        graph = build_production_graph(metadata, lock_text)
        validate_production_graph(graph, metadata, lock_text)
        write_json(temporary / "graph" / "production-closure.json", graph)

        _collect_toolchain(repository, temporary)
        native, sqlite = _build_native_evidence(
            metadata, selected_ids, repository, temporary
        )
        sbom = augment_sbom(
            merge_cyclonedx_sboms(
                _collect_cyclonedx_sboms(repository, source_epoch),
                metadata_root=METADATA_ROOT,
            ),
            sqlite,
        )
        validate_plan005_sbom(
            sbom, sqlite, identities, adjacency, metadata, lock_text
        )
        write_json(temporary / "sbom" / "plan-005-sbom.cdx.json", sbom)
        inventory = _build_license_inventory(
            metadata, selected_ids, cargo_lock, spdx_root, temporary
        )
        validate_release_oracle(graph, inventory)
        _run_rustsec_scan(repository, advisory_db, temporary, scan_timestamp)

        workflow_exists = (repository / WORKFLOW_PATH).is_file()
        reviewed_inputs = _copy_reviewed_inputs(
            repository, temporary, include_workflow=workflow_exists
        )
        identity = expected_supply_identity()
        validate_supply_identity(identity)
        write_json(temporary / "identity.json", identity)

        if exact_mode:
            repository_slug = _exact_argument(args, "github_repository")
            workflow_ref = _exact_argument(args, "workflow_ref")
            run_id = _exact_argument(args, "run_id")
            run_attempt = _exact_argument(args, "run_attempt")
            runner_os = _exact_argument(args, "runner_os")
            runner_arch = _exact_argument(args, "runner_arch")
            runner_name = _exact_argument(args, "runner_name")
            image_os = _exact_argument(args, "image_os")
            image_version = _exact_argument(args, "image_version")
            artifact_name = args.artifact_name or "plan-005-release-{}".format(head)
        else:
            repository_slug = args.github_repository or "diagnostic/local"
            workflow_ref = args.workflow_ref or "diagnostic-not-a-workflow-run"
            run_id = args.run_id or "0"
            run_attempt = args.run_attempt or "0"
            runner_os = args.runner_os or platform.system()
            runner_arch = args.runner_arch or platform.machine()
            runner_name = args.runner_name or "diagnostic-local"
            image_os = args.image_os or platform.platform()
            image_version = args.image_version or "diagnostic-local"
            artifact_name = args.artifact_name or "plan-005-supply-diagnostic"
        workflow_sha256 = (
            sha256_file(repository / WORKFLOW_PATH) if workflow_exists else "0" * 64
        )
        provenance = build_provenance(
            source_commit=head,
            source_tree=tree,
            source_mode="exact-commit" if exact_mode else "diagnostic-working-tree",
            tracked_checkout_clean=_tracked_checkout_clean(repository),
            workflow_path=WORKFLOW_PATH if workflow_exists else "pending-T089",
            workflow_sha256=workflow_sha256,
            tool_sha256=sha256_file(repository / SUPPLY_TOOL_PATH),
            helper_sha256=sha256_file(repository / HELPER_TOOL_PATH),
            artifact_name=artifact_name,
            repository_slug=repository_slug,
            workflow_ref=workflow_ref,
            run_id=run_id,
            run_attempt=run_attempt,
            runner_os=runner_os,
            runner_arch=runner_arch,
            runner_name=runner_name,
            image_os=image_os,
            image_version=image_version,
            source_timestamp=source_timestamp,
            scan_timestamp=scan_timestamp,
        )
        validate_provenance(
            provenance,
            expected_commit=head,
            expected_tree=tree,
            expected_source_timestamp=_git_timestamp(repository),
            expected_checkout_clean=_tracked_checkout_clean(repository),
            require_exact=exact_mode,
        )
        write_json(temporary / "provenance.json", provenance)
        descriptor = _build_descriptor(
            provenance,
            reviewed_inputs,
            graph,
            inventory,
            native,
            sha256_file(cargo_lock),
        )
        descriptor["provenance"]["sha256"] = sha256_file(
            temporary / "provenance.json"
        )
        write_json(temporary / "descriptor.json", descriptor)
        write_sha256_manifest(temporary)
        verify_bundle(
            temporary,
            repository,
            require_removal=False,
            require_exact=exact_mode,
        )
        if output.exists():
            output.rmdir()
        temporary.rename(output)
    except Exception:
        shutil.rmtree(str(temporary), ignore_errors=True)
        raise


def verify_bundle(
    root: Path,
    repository: Path,
    *,
    require_removal: bool = False,
    require_exact: bool = False,
) -> None:
    repository = _validate_repository(repository)
    unresolved_root = root.absolute()
    if _path_has_unsafe_symlink(unresolved_root):
        raise EvidenceError("evidence bundle root is absent or unsafe")
    root = unresolved_root.resolve()
    if not root.is_dir():
        raise EvidenceError("evidence bundle root is absent or unsafe")
    verify_sha256_manifest(root)
    required = [
        "descriptor.json",
        "identity.json",
        "provenance.json",
        "graph/production-closure.json",
        "sbom/plan-005-sbom.cdx.json",
        "licenses/inventory.json",
        "native/libsqlite3-sys-0.38.1.crate",
        "native/sqlite3.c",
        "native/sqlite3.h",
        "native/sqlite3-source-metadata.json",
        "rustsec/report.json",
        "rustsec/stderr.txt",
        "rustsec/database.json",
    ]
    if require_removal:
        required.extend(
            [
                "removal/report.json",
                "removal/protected-files-before.json",
                "removal/protected-files-after.json",
                "removal/removal-inventory.json",
                "removal/metadata-after-removal.json",
            ]
        )
    for relative in required:
        plan004._bundle_file(root, relative)

    descriptor = load_json(root / "descriptor.json")
    identity = load_json(root / "identity.json")
    provenance = load_json(root / "provenance.json")
    if not all(isinstance(value, dict) for value in (descriptor, identity, provenance)):
        raise EvidenceError("release descriptor/identity/provenance is malformed")
    if (
        descriptor.get("schema") != SCHEMA
        or descriptor.get("acceptance_id") != "PLAN-005"
        or descriptor.get("claim_status") != CLAIM_STATUS
        or descriptor.get("nonclaims") != NONCLAIMS
    ):
        raise EvidenceError("release descriptor identity or nonclaims mismatch")
    provenance_entry = descriptor.get("provenance") or {}
    if (
        provenance_entry.get("path") != "provenance.json"
        or provenance_entry.get("sha256") != sha256_file(root / "provenance.json")
    ):
        raise EvidenceError("release descriptor provenance binding mismatch")

    commit = _git_revision(repository)
    tree = _git_tree(repository)
    exact_mode = (provenance.get("source") or {}).get("mode") == "exact-commit"
    validate_provenance(
        provenance,
        expected_commit=commit,
        expected_tree=tree,
        expected_source_timestamp=_git_timestamp(repository),
        expected_checkout_clean=_tracked_checkout_clean(repository),
        require_exact=require_exact,
    )
    if exact_mode and not _tracked_checkout_clean(repository):
        raise EvidenceError("exact-commit verification requires a clean tracked checkout")
    if (provenance.get("builder") or {}).get("sha256") != sha256_file(
        repository / SUPPLY_TOOL_PATH
    ) or (provenance.get("builder") or {}).get("helper_sha256") != sha256_file(
        repository / HELPER_TOOL_PATH
    ):
        raise EvidenceError("supply builder/helper bytes differ from provenance")
    if exact_mode and (provenance.get("workflow") or {}).get("sha256") != sha256_file(
        repository / WORKFLOW_PATH
    ):
        raise EvidenceError("workflow bytes differ from exact provenance")
    if not exact_mode:
        workflow = provenance.get("workflow") or {}
        workflow_exists = (repository / WORKFLOW_PATH).is_file()
        if workflow_exists != (workflow.get("path") == WORKFLOW_PATH):
            raise EvidenceError("diagnostic workflow presence provenance mismatch")
        if workflow_exists and workflow.get("sha256") != sha256_file(
            repository / WORKFLOW_PATH
        ):
            raise EvidenceError("diagnostic workflow bytes differ from provenance")
    if descriptor.get("artifact_binding") != provenance.get("artifact"):
        raise EvidenceError("release descriptor artifact binding mismatch")

    validate_supply_identity(identity)
    metadata = _load_metadata(repository)
    selected_ids, _root_closures = union_dependency_closure(metadata)
    identities = production_package_identities(metadata, selected_ids)
    adjacency = production_dependency_adjacency(metadata, selected_ids)
    cargo_lock = repository / "kernel" / "Cargo.lock"
    lock_text = cargo_lock.read_text(encoding="utf-8")
    graph = load_json(root / "graph" / "production-closure.json")
    if not isinstance(graph, dict):
        raise EvidenceError("retained production graph is malformed")
    validate_production_graph(graph, metadata, lock_text)
    _validate_toolchain_files(root, repository)
    _validate_reviewed_inputs(
        root,
        repository,
        descriptor.get("reviewed_inputs"),
        commit,
        exact_mode,
    )

    inventory = load_json(root / "licenses" / "inventory.json")
    native = load_json(root / "native" / "sqlite3-source-metadata.json")
    sbom = load_json(root / "sbom" / "plan-005-sbom.cdx.json")
    if not all(isinstance(value, dict) for value in (inventory, native, sbom)):
        raise EvidenceError("retained supply-chain semantic evidence is malformed")
    _validate_license_inventory(root, inventory, metadata, identities, repository)
    sqlite = _validate_native_evidence(
        root, native, metadata, selected_ids, repository
    )
    validate_plan005_sbom(sbom, sqlite, identities, adjacency, metadata, lock_text)
    validate_release_oracle(graph, inventory)
    validate_release_artifact_oracles(root)
    plan004._validate_rustsec_evidence(root, repository)
    validate_rustsec_report_oracle(root / "rustsec" / "report.json")
    rustsec_database = load_json(root / "rustsec" / "database.json")
    expected_rustsec_database = {
        "schema": "helixos.rustsec-database-evidence/1",
        "cargo_audit_version": EXPECTED_AUDIT_VERSION,
        "database_revision": EXPECTED_RUSTSEC_REVISION,
        "database_commit_timestamp": EXPECTED_RUSTSEC_DATABASE_TIMESTAMP,
        "scan_timestamp": provenance.get("scan_timestamp"),
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
    }
    if rustsec_database != expected_rustsec_database:
        raise EvidenceError("RustSec scan timestamp/provenance mismatch")
    if (root / "rustsec" / "stderr.txt").read_text(encoding="utf-8") != "\n":
        raise EvidenceError("RustSec stderr evidence is not the expected empty output")

    supply = descriptor.get("supply_chain") or {}
    expected_summary = {
        "identity": "identity.json",
        "production_graph": "graph/production-closure.json",
        "sbom": "sbom/plan-005-sbom.cdx.json",
        "sbom_format": "CycloneDX 1.5 JSON; four-root union; bundled SQLite leaf",
        "license_inventory": "licenses/inventory.json",
        "native_sqlite": "native/sqlite3-source-metadata.json",
        "rustsec_report": "rustsec/report.json",
        "rustsec_database": "rustsec/database.json",
        "cargo_lock_sha256": sha256_file(cargo_lock),
        "production_package_count": graph["package_count"],
        "dependency_edge_count": graph["dependency_edge_count"],
        "external_package_count": inventory.get("external_package_count"),
        "workspace_package_count": inventory.get("workspace_package_count"),
        "spdx_text_count": len(inventory.get("spdx_texts", [])),
        "native_sqlite_summary": native,
        "removal": "required-at-final-exact-commit-verification",
    }
    if supply != expected_summary:
        raise EvidenceError("release descriptor supply-chain summary mismatch")
    expected_descriptor = _build_descriptor(
        provenance,
        descriptor.get("reviewed_inputs"),
        graph,
        inventory,
        native,
        sha256_file(cargo_lock),
    )
    expected_descriptor["provenance"]["sha256"] = sha256_file(
        root / "provenance.json"
    )
    if descriptor != expected_descriptor:
        raise EvidenceError("release descriptor contains unexpected fields")
    if require_removal:
        if not exact_mode:
            raise EvidenceError("diagnostic bundle cannot satisfy removal release evidence")
        _validate_removal_evidence(root, repository, commit, tree)
    _validate_closed_bundle_file_set(root, descriptor, inventory, require_removal)
    _scan_bundle(root, repository)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build and self-verify a PLAN-005 bundle")
    build.add_argument("--repository", default=".")
    build.add_argument("--output", required=True)
    build.add_argument("--advisory-db")
    build.add_argument("--spdx-license-list")
    build.add_argument("--source-commit")
    build.add_argument("--source-timestamp")
    build.add_argument("--scan-timestamp")
    build.add_argument("--artifact-name")
    build.add_argument("--github-repository")
    build.add_argument("--workflow-ref")
    build.add_argument("--run-id")
    build.add_argument("--run-attempt")
    build.add_argument("--runner-os")
    build.add_argument("--runner-arch")
    build.add_argument("--runner-name")
    build.add_argument("--image-os")
    build.add_argument("--image-version")

    manifest = subparsers.add_parser(
        "manifest", help="refresh MANIFEST.sha256 after adding removal evidence"
    )
    manifest.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify", help="independently verify a PLAN-005 bundle")
    verify.add_argument("--repository", default=".")
    verify.add_argument("--output", required=True)
    verify.add_argument("--require-removal", action="store_true")
    verify.add_argument("--require-exact", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            build_bundle(args)
        elif args.command == "manifest":
            refresh_bundle_manifest(Path(args.output))
        else:
            verify_bundle(
                Path(args.output),
                Path(args.repository),
                require_removal=args.require_removal,
                require_exact=args.require_exact,
            )
    except EvidenceError as error:
        repository = Path(getattr(args, "repository", ".")).resolve()
        private_replacements = []
        for attribute, replacement in (
            ("output", "<evidence-output>"),
            ("advisory_db", "<pinned-rustsec-db>"),
            ("spdx_license_list", "<pinned-spdx-list>"),
        ):
            value = getattr(args, attribute, None)
            if isinstance(value, str) and value:
                path = Path(value).absolute()
                private_replacements.append((str(path), replacement))
                private_replacements.append((str(path.resolve()), replacement))
        print(
            "PLAN-005 supply-chain evidence failed: {}".format(
                _redact_message(str(error), repository, private_replacements)
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
