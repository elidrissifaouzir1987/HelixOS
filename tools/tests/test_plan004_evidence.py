import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from plan004_removal_drill import (  # noqa: E402
    EvidenceError as RemovalEvidenceError,
    _clean_environment,
    _normalized_metadata,
    redact_output,
    remove_catalog_entry,
    remove_plan004_attributes,
    remove_workspace_members,
)
from plan004_supply_chain import (  # noqa: E402
    EvidenceError as SupplyEvidenceError,
    SQLiteSource,
    _require_tool_version,
    augment_sbom,
    dependency_closure,
    validate_audit_report,
    validate_retained_sbom,
    verify_sha256_manifest,
    write_sha256_manifest,
)


class SupplyChainEvidenceTests(unittest.TestCase):
    def base_sbom(self):
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "name": name, "version": version}
                for name, version in (
                    ("helix-coordinator-sqlite", "0.1.0"),
                    ("file-id", "0.2.3"),
                    ("windows-sys", "0.61.2"),
                    ("rusqlite", "0.40.1"),
                    ("libsqlite3-sys", "0.38.1"),
                )
            ],
        }

    def test_cargo_subcommand_version_banner_is_pinned_exactly(self):
        _require_tool_version(
            "cargo-cyclonedx-cyclonedx 0.5.9", "cargo-cyclonedx", "0.5.9"
        )
        with self.assertRaisesRegex(SupplyEvidenceError, "pinned"):
            _require_tool_version(
                "cargo-cyclonedx-cyclonedx 0.5.8", "cargo-cyclonedx", "0.5.9"
            )

    def test_release_upload_retains_hidden_reviewed_workflow(self):
        workflow = (TOOLS.parent / ".github" / "workflows" / "durable-preparation.yml")
        text = workflow.read_text(encoding="utf-8")
        block = re.search(
            r"(?ms)^      - name: Upload release evidence bundle\n.*?"
            r"(?=^      - name: |^  [a-z])",
            text,
        )

        self.assertIsNotNone(block)
        self.assertIn("include-hidden-files: true", block.group(0))

    def test_hosted_scope_excludes_only_plan005_release_contention_oracles(self):
        workflow = TOOLS.parent / ".github" / "workflows" / "durable-preparation.yml"
        text = workflow.read_text(encoding="utf-8")
        block = re.search(
            r"(?ms)^      - name: Test hosted coordinator surfaces outside the controlled timing oracle\n.*?"
            r"(?=^      - name: )",
            text,
        )
        self.assertIsNotNone(block)
        release_oracles = (
            "exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption",
            "exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round",
            "exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round",
        )
        self.assertEqual(
            tuple(re.findall(r"(?m)^\s+--skip (\S+)\s*$", block.group(0))),
            (
                "held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later",
            )
            + release_oracles,
        )
        descriptor = re.search(
            r"(?ms)^\s+excluded_downstream_release_oracles = @\(\n(?P<values>.*?)^\s+\)$",
            text,
        )
        self.assertIsNotNone(descriptor)
        self.assertEqual(
            tuple(re.findall(r"'([^']+)'", descriptor.group("values"))),
            release_oracles,
        )
        summary = re.search(
            r"(?m)^\s+'excluded_downstream_release_oracles=([^']+)'", text
        )
        self.assertIsNotNone(summary)
        self.assertEqual(tuple(summary.group(1).split(",")), release_oracles)
        owner = (
            ".github/workflows/durable-dispatch.yml#plan005-release-contention-gates"
        )
        self.assertEqual(text.count(owner), 2)

    def test_sbom_is_extended_with_exact_bundled_sqlite_source(self):
        sqlite = SQLiteSource(
            version="3.53.2",
            source_id=(
                "2026-06-03 19:12:13 "
                "d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
            ),
            source_sha256="a" * 64,
        )

        result = augment_sbom(self.base_sbom(), sqlite)

        native = next(item for item in result["components"] if item["name"] == "SQLite")
        self.assertEqual(native["version"], "3.53.2")
        self.assertEqual(native["hashes"], [{"alg": "SHA-256", "content": "a" * 64}])
        self.assertIn(
            {"name": "helixos:sqlite-source-id", "value": sqlite.source_id},
            native["properties"],
        )

    def test_sbom_rejects_missing_windows_target_component(self):
        sbom = self.base_sbom()
        sbom["components"] = [
            item for item in sbom["components"] if item["name"] != "file-id"
        ]
        sqlite = SQLiteSource("3.53.2", "source-id", "b" * 64)

        with self.assertRaisesRegex(SupplyEvidenceError, "file-id"):
            augment_sbom(sbom, sqlite)

    def test_final_verifier_rejects_rehashed_empty_sbom(self):
        with self.assertRaisesRegex(SupplyEvidenceError, "CycloneDX"):
            validate_retained_sbom(
                {}, SQLiteSource("3.53.2", "source-id", "d" * 64), set(), {}
            )

    def test_sbom_removes_volatile_fields_and_rejects_edge_tampering(self):
        identities = {
            ("helix-coordinator-sqlite", "0.1.0", "workspace-path"),
            ("file-id", "0.2.3", "registry"),
            ("windows-sys", "0.61.2", "registry"),
            ("rusqlite", "0.40.1", "registry"),
            ("libsqlite3-sys", "0.38.1", "registry"),
        }
        root = ("helix-coordinator-sqlite", "0.1.0", "workspace-path")
        leaves = identities - {root}
        adjacency = {identity: set() for identity in identities}
        adjacency[root] = leaves
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:volatile",
            "metadata": {
                "timestamp": "2099-01-01T00:00:00Z",
                "component": {
                    "type": "library",
                    "bom-ref": "ref:root",
                    "name": root[0],
                    "version": root[1],
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "ref:{}".format(name),
                    "name": name,
                    "version": version,
                }
                for name, version, _source in sorted(leaves)
            ],
            "dependencies": [
                {
                    "ref": "ref:root",
                    "dependsOn": ["ref:{}".format(name) for name, _version, _ in leaves],
                }
            ]
            + [{"ref": "ref:{}".format(name)} for name, _version, _ in leaves],
        }
        sqlite = SQLiteSource("3.53.2", "source-id", "e" * 64)

        retained = augment_sbom(sbom, sqlite)

        self.assertNotIn("serialNumber", retained)
        self.assertNotIn("timestamp", retained["metadata"])
        validate_retained_sbom(retained, sqlite, identities, adjacency)
        tampered = json.loads(json.dumps(retained))
        root_node = next(
            item for item in tampered["dependencies"] if item["ref"] == "ref:root"
        )
        root_node["dependsOn"] = []
        with self.assertRaisesRegex(SupplyEvidenceError, "adjacency mismatch"):
            validate_retained_sbom(tampered, sqlite, identities, adjacency)

    def test_sbom_rekeys_workspace_paths_and_dependency_edges(self):
        sbom = self.base_sbom()
        old_ref = "path+file:///Users/alice/HelixOS/kernel/helix-contracts#0.1.0"
        root_ref = (
            "path+file:///Users/alice/HelixOS/kernel/helix-coordinator-sqlite#0.1.0"
        )
        sbom["metadata"] = {
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": "helix-coordinator-sqlite",
                "version": "0.1.0",
                "purl": "pkg:cargo/helix-coordinator-sqlite@0.1.0?download_url=file://.",
            }
        }
        sbom["components"].append(
            {
                "type": "library",
                "bom-ref": old_ref,
                "name": "helix-contracts",
                "version": "0.1.0",
                "purl": "pkg:cargo/helix-contracts@0.1.0?download_url=file://../helix-contracts",
            }
        )
        sbom["dependencies"] = [
            {"ref": root_ref, "dependsOn": [old_ref]},
            {"ref": old_ref, "dependsOn": []},
        ]

        result = augment_sbom(
            sbom, SQLiteSource("3.53.2", "source-id", "c" * 64)
        )
        encoded = json.dumps(result, sort_keys=True)

        self.assertNotIn("/Users/alice", encoded)
        self.assertNotIn("file://", encoded)
        rewritten = next(
            item["bom-ref"]
            for item in result["components"]
            if item.get("name") == "helix-contracts"
        )
        root_dependency = next(
            item
            for item in result["dependencies"]
            if item["ref"].startswith("urn:helixos:cargo-workspace:helix-coordinator")
        )
        self.assertIn(rewritten, root_dependency["dependsOn"])

    def test_dependency_closure_excludes_unreachable_workspace_packages(self):
        metadata = {
            "packages": [
                {"id": "root", "name": "helix-coordinator-sqlite"},
                {"id": "dep", "name": "rusqlite"},
                {"id": "unrelated", "name": "helixos-kernel"},
            ],
            "resolve": {
                "nodes": [
                    {"id": "root", "dependencies": ["dep"]},
                    {"id": "dep", "dependencies": []},
                    {"id": "unrelated", "dependencies": []},
                ]
            },
        }

        self.assertEqual(
            dependency_closure(metadata, "helix-coordinator-sqlite"),
            {"root", "dep"},
        )

    def test_audit_report_fails_closed_on_vulnerability(self):
        clean = {
            "database": {"advisory-count": 900},
            "lockfile": {"dependency-count": 73},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {"unmaintained": []},
        }
        validate_audit_report(clean)
        compromised = json.loads(json.dumps(clean))
        compromised["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [{"advisory": {"id": "RUSTSEC-2099-0001"}}],
        }

        with self.assertRaisesRegex(SupplyEvidenceError, "vulnerabilit"):
            validate_audit_report(compromised)

    def test_audit_report_rejects_untriaged_warning(self):
        report = {
            "database": {"advisory-count": 900},
            "lockfile": {"dependency-count": 73},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {
                "unmaintained": [
                    {"advisory": {"id": "RUSTSEC-2099-0002"}, "package": {}}
                ]
            },
        }

        with self.assertRaisesRegex(SupplyEvidenceError, "untriaged"):
            validate_audit_report(report)

    def test_audit_report_rejects_idless_warning_beside_triaged_warning(self):
        report = {
            "database": {"advisory-count": 900},
            "lockfile": {"dependency-count": 73},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {
                "unmaintained": [
                    {"advisory": {"id": "RUSTSEC-2025-0134"}, "package": {}}
                ],
                "yanked": [{"package": {"name": "surprise", "version": "1.0.0"}}],
            },
        }

        with self.assertRaisesRegex(SupplyEvidenceError, "untriaged"):
            validate_audit_report(report)

    def test_internal_manifest_is_sorted_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z.txt").write_text("z\n", encoding="utf-8")
            (root / "nested").mkdir()
            (root / "nested" / "a.txt").write_text("a\n", encoding="utf-8")

            manifest = write_sha256_manifest(root)
            lines = manifest.read_text(encoding="utf-8").splitlines()
            self.assertEqual([line.split("  ", 1)[1] for line in lines], ["nested/a.txt", "z.txt"])
            verify_sha256_manifest(root)

            (root / "z.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(SupplyEvidenceError, "digest mismatch"):
                verify_sha256_manifest(root)


class RemovalEvidenceTests(unittest.TestCase):
    def test_removal_subprocess_environment_drops_credentials_and_proxies(self):
        cleaned = _clean_environment(
            {
                "PATH": "/usr/bin",
                "HOME": "/Users/alice",
                "LANG": "en_US.UTF-8",
                "GH_TOKEN": "secret-value",
                "CARGO_REGISTRIES_CRATES_IO_TOKEN": "secret-value",
                "HTTPS_PROXY": "https://user:password@example.invalid",
            }
        )

        self.assertEqual(cleaned["PATH"], "/usr/bin")
        self.assertEqual(cleaned["HOME"], "/Users/alice")
        self.assertNotIn("GH_TOKEN", cleaned)
        self.assertNotIn("CARGO_REGISTRIES_CRATES_IO_TOKEN", cleaned)
        self.assertNotIn("HTTPS_PROXY", cleaned)

    def test_catalog_removal_preserves_adjacent_claims(self):
        catalog = """conformance:
  - acceptance_id: PLAN-003
    title: replay
  - acceptance_id: PLAN-004
    title: preparation
    evidence:
      immutable: pending
  - acceptance_id: PLAN-005
    title: activation
"""

        result = remove_catalog_entry(catalog, "PLAN-004")

        self.assertIn("PLAN-003", result)
        self.assertNotIn("PLAN-004", result)
        self.assertIn("PLAN-005", result)

    def test_catalog_removal_requires_exactly_one_entry(self):
        with self.assertRaisesRegex(RemovalEvidenceError, "exactly one"):
            remove_catalog_entry("conformance:\n", "PLAN-004")

    def test_workspace_removal_is_exact_and_keeps_legacy_members(self):
        manifest = """[workspace]
members = [
    "helix-plan-preparation",
    "helix-coordinator-sqlite",
    "helixos-kernel",
]
resolver = "2"
"""

        result = remove_workspace_members(
            manifest,
            {"helix-plan-preparation", "helix-coordinator-sqlite"},
        )

        self.assertNotIn("helix-plan-preparation", result)
        self.assertNotIn("helix-coordinator-sqlite", result)
        self.assertIn("helixos-kernel", result)

    def test_attributes_removal_drops_the_complete_plan004_block(self):
        attributes = """# previous
/kernel/Cargo.lock text eol=lf

# PLAN-004 SQL, canonical JSON, fixtures and retained evidence are digest-sensitive.
/specs/004-durable-preparation/contracts/*.json text eol=lf
/specs/004-durable-preparation/contracts/*.sql text eol=lf
/specs/004-durable-preparation/evidence/* text eol=lf whitespace=-blank-at-eof
/contracts/fixtures/durable-preparation-v1/* text eol=lf
/.github/workflows/durable-preparation.yml text eol=lf

# after
"""

        result = remove_plan004_attributes(attributes)

        self.assertNotIn("PLAN-004", result)
        self.assertNotIn("durable-preparation", result)
        self.assertIn("/kernel/Cargo.lock", result)
        self.assertIn("# after", result)

    def test_redaction_removes_machine_paths(self):
        text = (
            "/private/tmp/drill/kernel and /Users/alice/project plus /Users/alice "
            "and /dedicated/cargo-target/debug"
        )
        result = redact_output(
            text,
            removal_root=Path("/private/tmp/drill"),
            repository_root=Path("/Users/alice/project"),
            home=Path("/Users/alice"),
            extra_paths=((Path("/dedicated/cargo-target"), "<cargo-target>"),),
        )

        self.assertEqual(
            result,
            "<removal-root>/kernel and <repo> plus <home> and <cargo-target>/debug",
        )

    def test_removal_metadata_drops_all_cargo_absolute_paths(self):
        raw = json.dumps(
            {
                "packages": [
                    {
                        "name": "helix-contracts",
                        "version": "0.1.0",
                        "source": None,
                        "manifest_path": "C:\\Users\\alice\\source\\Cargo.toml",
                    }
                ],
                "workspace_root": "C:\\Users\\alice\\source\\kernel",
                "target_directory": "D:\\cargo-target",
            }
        )

        result = _normalized_metadata(raw)
        encoded = json.dumps(result, sort_keys=True)

        self.assertNotIn("alice", encoded)
        self.assertNotIn("D:", encoded)
        self.assertEqual(result["target_directory"], "<cargo-target>")


if __name__ == "__main__":
    unittest.main()
