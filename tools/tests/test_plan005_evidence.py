import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
REPOSITORY = TOOLS.parent
MANIFEST_PATH = (
    REPOSITORY
    / "specs"
    / "005-durable-dispatch"
    / "evidence"
    / "removal-protected-files.json"
)
DRIVER_PATH = TOOLS / "plan005_removal_drill.py"
WORKFLOW_PATH = REPOSITORY / ".github" / "workflows" / "durable-dispatch.yml"
QUICKSTART_PATH = REPOSITORY / "specs" / "005-durable-dispatch" / "quickstart.md"
sys.path.insert(0, str(TOOLS))

import plan005_removal_drill as removal  # noqa: E402
import plan005_supply_chain as supply  # noqa: E402


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _bytewise_sorted(values):
    return sorted(values, key=lambda value: value.encode("utf-8"))


def _toml_table(path, table):
    result = {}
    active = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        section = re.fullmatch(r"\[([^]]+)\]", line)
        if section:
            active = section.group(1) == table
            continue
        if active and line and not line.startswith("#"):
            name, separator, value = line.partition("=")
            if not separator:
                raise AssertionError("malformed TOML member in {}: {}".format(path, line))
            result[name.strip()] = value.strip()
    return result


def _rust_sources(root):
    return [
        path
        for path in sorted(root.rglob("*.rs"))
        if path.is_file() and not path.is_symlink()
    ]


def _minimal_delta_fixture():
    original = {"mode": "100644", "type": "blob", "git_blob_oid": "1" * 40}
    changed = {"mode": "100644", "type": "blob", "git_blob_oid": "2" * 40}
    added = {"mode": "100644", "type": "blob", "git_blob_oid": "3" * 40}
    manifest = {
        "removal_policy": {
            "baseline_paths_restored": ["base.txt"],
            "added_paths_removed": ["known.rs"],
            "added_prefixes_removed": [],
            "added_paths_retained_for_audit": [],
            "added_prefixes_retained_for_audit": [],
        }
    }
    return manifest, {"base.txt": original}, {"base.txt": changed, "known.rs": added}


def _synthetic_supply_metadata():
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    packages = [
        {"id": name, "name": name, "version": "0.1.0", "source": None}
        for name in supply.PRODUCTION_ROOTS
    ]
    packages.extend(
        [
            {"id": "shared", "name": "shared", "version": "1.0.0", "source": registry},
            {
                "id": "build-helper",
                "name": "build-helper",
                "version": "2.0.0",
                "source": registry,
            },
            {"id": "sqlite", "name": "sqlite-wrapper", "version": "3.0.0", "source": registry},
            {
                "id": "preparation",
                "name": "helix-plan-preparation",
                "version": "0.1.0",
                "source": None,
            },
            {"id": "dev-only", "name": "dev-only", "version": "9.0.0", "source": registry},
        ]
    )

    def dependency(package, kind):
        return {"pkg": package, "dep_kinds": [{"kind": kind, "target": None}]}

    contracts, dispatch, inbox, coordinator = supply.PRODUCTION_ROOTS
    nodes = [
        {
            "id": contracts,
            "deps": [dependency("shared", "normal"), dependency("dev-only", "dev")],
        },
        {
            "id": dispatch,
            "deps": [dependency(contracts, "normal"), dependency("build-helper", "build")],
        },
        {
            "id": inbox,
            "deps": [dependency(dispatch, "normal"), dependency("sqlite", "normal")],
        },
        {
            "id": coordinator,
            "deps": [dependency(inbox, "normal"), dependency("preparation", "normal")],
        },
    ]
    nodes.extend(
        {"id": package, "deps": []}
        for package in ("shared", "build-helper", "sqlite", "preparation", "dev-only")
    )
    return {"packages": packages, "resolve": {"nodes": nodes}}


def _synthetic_supply_lock():
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    records = []
    for name, version, digest in (
        ("shared", "1.0.0", "1" * 64),
        ("build-helper", "2.0.0", "2" * 64),
        ("sqlite-wrapper", "3.0.0", "3" * 64),
        ("dev-only", "9.0.0", "9" * 64),
    ):
        records.append(
            "\n".join(
                [
                    "[[package]]",
                    'name = "{}"'.format(name),
                    'version = "{}"'.format(version),
                    'source = "{}"'.format(registry),
                    'checksum = "{}"'.format(digest),
                ]
            )
        )
    return "version = 4\n\n" + "\n\n".join(records) + "\n"


class Plan005RemovalManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = removal.load_and_validate_manifest(
            REPOSITORY, MANIFEST_PATH, removal.BASELINE_COMMIT
        )
        cls.entries = cls.manifest["entries"]
        cls.baseline_entries = {entry["path"]: dict(entry) for entry in cls.entries}

    def test_frozen_manifest_hash_schema_baseline_and_nonclaims_are_exact(self):
        self.assertEqual(
            removal.sha256_file(MANIFEST_PATH), removal.PROTECTED_MANIFEST_SHA256
        )
        self.assertEqual(
            removal.PROTECTED_MANIFEST_SHA256,
            "6c9422f47fd65ba7866750666a3f0e4c4c1e35944b8a1506c4a6ffa34ab2edf2",
        )
        self.assertEqual(
            supply.REMOVAL_MANIFEST_SHA256,
            removal.PROTECTED_MANIFEST_SHA256,
        )
        self.assertEqual(self.manifest["schema"], removal.MANIFEST_SCHEMA)
        self.assertEqual(self.manifest["acceptance_id"], "PLAN-005")
        self.assertEqual(self.manifest["nonclaims"], removal.EXPECTED_NONCLAIMS)
        self.assertEqual(
            self.manifest["expected_post_removal_workspace_packages"],
            sorted(removal.EXPECTED_PACKAGES),
        )
        self.assertEqual(
            self.manifest["baseline"],
            {
                "cargo_lock_sha256": "ede1e9ac8e936efc4c65cf99a2fc79ca037934b5aabeac783b1ba265b1c6687f",
                "commit": removal.BASELINE_COMMIT,
                "full_inventory_sha256": removal.BASELINE_FULL_INVENTORY_SHA256,
                "leaf_blob_count": removal.BASELINE_LEAF_COUNT,
                "mode_counts": {"100644": 490, "100755": 5},
                "path_inventory_sha256": removal.BASELINE_PATH_INVENTORY_SHA256,
                "tree": removal.BASELINE_TREE,
                "workspace_manifest_sha256": "7bd7e2477f521d10547b87f5fc2437582553bf45bdae3f0ce81af5695ab0b423",
            },
        )

    def test_all_495_baseline_entries_bind_path_mode_oid_and_content(self):
        self.assertEqual(len(self.entries), 495)
        self.assertEqual(
            [entry["path"] for entry in self.entries],
            _bytewise_sorted(entry["path"] for entry in self.entries),
        )
        self.assertEqual(
            Counter(entry["mode"] for entry in self.entries),
            Counter({"100644": 490, "100755": 5}),
        )
        for entry in self.entries:
            self.assertEqual(set(entry), {"path", "mode", "type", "git_blob_oid", "content_sha256"})
            self.assertEqual(entry["type"], "blob")
            self.assertRegex(entry["git_blob_oid"], r"^[0-9a-f]{40}$")
            self.assertRegex(entry["content_sha256"], r"^[0-9a-f]{64}$")

        self.assertEqual(
            _sha256(removal._entry_stream(self.entries)),
            removal.BASELINE_FULL_INVENTORY_SHA256,
        )
        self.assertEqual(
            _sha256(removal._path_stream(self.entries)),
            removal.BASELINE_PATH_INVENTORY_SHA256,
        )
        self.assertEqual(
            removal._run_git_text(REPOSITORY, ["rev-parse", "{}^{{tree}}".format(removal.BASELINE_COMMIT)]),
            removal.BASELINE_TREE,
        )
        # setUpClass calls the production validator, which additionally reads and hashes
        # every one of the 495 Git blobs against content_sha256.

    def test_27_working_tree_exclusions_are_exact_sorted_and_baseline_owned(self):
        exclusions = self.manifest["working_tree_exclusions"]
        paths = exclusions["paths"]
        self.assertEqual(exclusions["count"], 27)
        self.assertEqual(len(paths), 27)
        self.assertEqual(paths, _bytewise_sorted(paths))
        self.assertEqual(
            _sha256("".join(path + "\n" for path in paths).encode("utf-8")),
            removal.EXCLUSION_LIST_SHA256,
        )
        self.assertTrue(set(paths).issubset(self.baseline_entries))
        self.assertTrue(
            all(
                path.startswith(
                    (
                        "kernel/helixos-kernel/",
                        "kernel/helixos-mcp-shim/",
                        "kernel/helixos-provision/",
                    )
                )
                for path in paths
            )
        )

    def test_removal_policy_is_closed_sorted_and_non_overlapping(self):
        policy = self.manifest["removal_policy"]
        expected_counts = {
            "baseline_paths_restored": 32,
            "added_paths_removed": 29,
            "added_prefixes_removed": 10,
            "added_paths_retained_for_audit": 3,
            "added_prefixes_retained_for_audit": 2,
        }
        for name, count in expected_counts.items():
            self.assertEqual(len(policy[name]), count)
            self.assertEqual(policy[name], _bytewise_sorted(policy[name]))
            self.assertEqual(len(policy[name]), len(set(policy[name])))

        self.assertEqual(
            policy["added_prefixes_removed"],
            [
                "contracts/fixtures/durable-dispatch-v1/",
                "contracts/fixtures/durable-signed-task-authority-v1/",
                "graphify-out/memory/",
                "kernel/helix-dispatch-contracts/",
                "kernel/helix-dispatch-inbox-sqlite/",
                "kernel/helix-plan-dispatch/",
                "kernel/helix-task-authority-contracts/",
                "kernel/helix-task-authority-projections/",
                "kernel/helix-task-authority-sqlite/",
                "kernel/helix-task-authority/",
            ],
        )
        self.assertEqual(
            policy["added_prefixes_retained_for_audit"],
            [
                "specs/005-durable-dispatch/",
                "specs/006-durable-signed-task-authority/",
            ],
        )
        self.assertEqual(
            policy["added_paths_retained_for_audit"],
            [
                "tools/plan005_removal_drill.py",
                "tools/plan005_supply_chain.py",
                "tools/tests/test_plan005_evidence.py",
            ],
        )
        self.assertTrue(set(policy["baseline_paths_restored"]).issubset(self.baseline_entries))
        added_exact = policy["added_paths_removed"] + policy["added_paths_retained_for_audit"]
        self.assertFalse(set(added_exact).intersection(self.baseline_entries))
        for path in added_exact:
            self.assertEqual(
                len(
                    removal._class_matches(
                        path,
                        policy["added_paths_removed"],
                        policy["added_prefixes_removed"],
                        policy["added_paths_retained_for_audit"],
                        policy["added_prefixes_retained_for_audit"],
                    )
                ),
                1,
            )
        for removed in policy["added_prefixes_removed"]:
            for retained in policy["added_prefixes_retained_for_audit"]:
                self.assertFalse(removed.startswith(retained) or retained.startswith(removed))

    def test_current_filtered_source_delta_matches_exactly_one_policy_class(self):
        head = removal._run_git_text(REPOSITORY, ["rev-parse", "HEAD^{commit}"])
        source_entries, overlays, ignored, _untracked = removal._working_source_snapshot(
            REPOSITORY,
            head,
            set(self.manifest["working_tree_exclusions"]["paths"]),
        )
        actions = removal._classify_source_delta(
            self.manifest, self.baseline_entries, source_entries
        )
        self.assertTrue(actions["restored_baseline_paths"])
        self.assertTrue(actions["removed_added_paths"])
        self.assertTrue(
            set(actions["restored_baseline_paths"]).issubset(
                self.manifest["removal_policy"]["baseline_paths_restored"]
            )
        )
        self.assertTrue(
            set(ignored).issubset(self.manifest["working_tree_exclusions"]["paths"])
        )
        self.assertFalse(
            {path for _status, path in overlays}.intersection(
                self.manifest["working_tree_exclusions"]["paths"]
            )
        )
        self.assertIn("tools/tests/test_plan005_evidence.py", actions["retained_audit_paths"])
        digest = removal._delta_digest(source_entries, actions)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, removal._delta_digest(source_entries, actions))

    def test_unknown_delta_and_overlapping_classification_fail_closed(self):
        manifest, baseline, source = _minimal_delta_fixture()
        unknown = dict(source)
        unknown["surprise.sh"] = {
            "mode": "100755",
            "type": "blob",
            "git_blob_oid": "4" * 40,
        }
        with self.assertRaisesRegex(removal.EvidenceError, "exactly one"):
            removal._classify_source_delta(manifest, baseline, unknown)

        overlapping = copy.deepcopy(manifest)
        overlapping["removal_policy"]["added_prefixes_retained_for_audit"] = [""]
        with self.assertRaisesRegex(removal.EvidenceError, "exactly one"):
            removal._classify_source_delta(overlapping, baseline, source)

    def test_manifest_tamper_and_symlink_oracles_fail_before_git_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "manifest.json"
            candidate.write_bytes(MANIFEST_PATH.read_bytes() + b" ")
            with self.assertRaisesRegex(removal.EvidenceError, "digest mismatch"):
                removal.load_and_validate_manifest(
                    REPOSITORY, candidate, removal.BASELINE_COMMIT
                )

            with mock.patch.object(
                Path, "is_symlink", autospec=True, side_effect=lambda path: path == candidate
            ):
                with self.assertRaisesRegex(removal.EvidenceError, "non-symlink"):
                    removal.load_and_validate_manifest(
                        REPOSITORY, candidate, removal.BASELINE_COMMIT
                    )


class Plan005RemovalSafetyTests(unittest.TestCase):
    def test_relative_path_name_status_and_safe_target_reject_traversal(self):
        for unsafe in ("", "..", "./member", "../escape", "nested/../escape", "/absolute", "C:\\escape", "bad\x00name"):
            with self.subTest(path=unsafe):
                with self.assertRaises(removal.EvidenceError):
                    removal._validate_relative_path(unsafe)
        with self.assertRaisesRegex(removal.EvidenceError, "unsupported"):
            removal._parse_name_status(b"R100\x00old\x00")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linked_parent = root / "linked"
            linked_parent.mkdir()
            original = Path.is_symlink

            def symlink_oracle(path):
                return path == linked_parent or original(path)

            with mock.patch.object(Path, "is_symlink", autospec=True, side_effect=symlink_oracle):
                with self.assertRaisesRegex(removal.EvidenceError, "parent is a symlink"):
                    removal._safe_target(root, "linked/member")

    def test_output_and_cargo_target_must_be_fresh_disjoint_and_non_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            worktree = root / "isolated"
            output = root / "evidence"
            for path in (repository, worktree, output):
                path.mkdir()

            fresh_target = root / "fresh-target"
            removal._validate_cargo_target(fresh_target, repository, worktree, output)
            fresh_target.mkdir()
            with self.assertRaisesRegex(removal.EvidenceError, "fresh absent"):
                removal._validate_cargo_target(fresh_target, repository, worktree, output)
            for overlapping in (repository / "target", worktree / "target", output / "target"):
                with self.assertRaisesRegex(removal.EvidenceError, "overlaps"):
                    removal._validate_cargo_target(overlapping, repository, worktree, output)

            (output / "existing.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(removal.EvidenceError, "absent or empty"):
                removal._validate_output_location(repository, output)
            with mock.patch.object(
                Path, "is_symlink", autospec=True, side_effect=lambda path: path == output
            ):
                with self.assertRaisesRegex(removal.EvidenceError, "symlink"):
                    removal._validate_output_location(repository, output)

    def test_exact_commit_provenance_binds_head_manifest_and_driver_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            manifest = repository / removal.DEFAULT_MANIFEST
            driver = repository / "tools" / "plan005_removal_drill.py"
            manifest.parent.mkdir(parents=True)
            driver.parent.mkdir(parents=True, exist_ok=True)
            manifest_bytes = b'{"manifest":"exact"}\n'
            driver_bytes = b"# exact driver\n"
            manifest.write_bytes(manifest_bytes)
            driver.write_bytes(driver_bytes)

            blobs = {"manifest-oid": manifest_bytes, "driver-oid": driver_bytes}

            def fake_rev_parse(_repository, argv):
                target = argv[1]
                if target.endswith(":" + removal.DEFAULT_MANIFEST):
                    return "manifest-oid"
                if target.endswith(":tools/plan005_removal_drill.py"):
                    return "driver-oid"
                raise AssertionError(target)

            with mock.patch.object(removal, "__file__", str(driver)), mock.patch.object(
                removal, "_run_git_text", side_effect=fake_rev_parse
            ), mock.patch.object(removal, "_git_blob", side_effect=lambda _repo, oid: blobs[oid]):
                self.assertEqual(
                    removal._verify_exact_commit_tooling(
                        repository, "source", "source", manifest.resolve()
                    ),
                    _sha256(driver_bytes),
                )
                manifest.write_bytes(b"tampered\n")
                with self.assertRaisesRegex(removal.EvidenceError, "differs"):
                    removal._verify_exact_commit_tooling(
                        repository, "source", "source", manifest.resolve()
                    )

        with self.assertRaisesRegex(removal.EvidenceError, "equal HEAD"):
            removal._verify_exact_commit_tooling(
                REPOSITORY, "source", "different-head", MANIFEST_PATH
            )

    def test_driver_uses_no_checkout_and_cleanup_is_owned_and_bounded(self):
        source = DRIVER_PATH.read_text(encoding="utf-8")
        self.assertIn('"worktree",\n                "add",', source)
        self.assertIn('"--no-checkout",', source)
        self.assertIn("_materialize_git_tree(repository, worktree", source)
        self.assertIn('["git", "worktree", "remove", "--force", str(worktree)]', source)
        self.assertIn("shutil.rmtree(str(temporary), ignore_errors=True)", source)
        self.assertIn("shutil.rmtree(str(worktree_admin))", source)
        for forbidden in (
            '["git", "clean"',
            '["git", "reset"',
            '["git", "checkout"',
            "shutil.rmtree(str(repository)",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("status_after != status_before", source)
        execute_source = source[
            source.index("def execute_drill(") : source.index("\ndef build_parser(")
        ]
        restore_position = execute_source.index(
            'for path in actions["restored_baseline_paths"]:'
        )
        protected_before_position = execute_source.index(
            "protected_before = _protected_snapshot(worktree, manifest)"
        )
        test_position = execute_source.index("if not args.skip_tests:")
        protected_after_position = execute_source.index(
            "protected_after = _protected_snapshot(worktree, manifest)"
        )
        self.assertLess(
            restore_position,
            protected_before_position,
            "the before snapshot must observe the restored baseline",
        )
        self.assertLess(protected_before_position, test_position)
        self.assertLess(test_position, protected_after_position)

        with tempfile.TemporaryDirectory() as directory:
            isolated = Path(directory) / "isolated"
            removal_target = isolated / "owned" / "nested" / "plan005.rs"
            retained_sibling = isolated / "retained.txt"
            removal_target.parent.mkdir(parents=True)
            removal_target.write_text("remove\n", encoding="utf-8")
            retained_sibling.write_text("retain\n", encoding="utf-8")
            removal._delete_added_path(isolated, "owned/nested/plan005.rs")
            self.assertFalse(removal_target.exists())
            self.assertFalse((isolated / "owned").exists())
            self.assertEqual(retained_sibling.read_text(encoding="utf-8"), "retain\n")

    def test_only_exact_commit_with_tests_is_immutable_eligible(self):
        tree = ast.parse(DRIVER_PATH.read_text(encoding="utf-8"))
        assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "immutable_eligible" for target in node.targets)
        )
        expression = assignment.value
        self.assertIsInstance(expression, ast.BoolOp)
        self.assertIsInstance(expression.op, ast.And)
        self.assertEqual(len(expression.values), 2)
        exact_commit, tests_not_skipped = expression.values
        self.assertIsInstance(exact_commit, ast.Compare)
        self.assertEqual(exact_commit.left.id, "source_mode")
        self.assertEqual(exact_commit.comparators[0].value, "exact-commit")
        self.assertIsInstance(tests_not_skipped, ast.UnaryOp)
        self.assertIsInstance(tests_not_skipped.op, ast.Not)
        self.assertEqual(tests_not_skipped.operand.value.id, "args")
        self.assertEqual(tests_not_skipped.operand.attr, "skip_tests")

        source = DRIVER_PATH.read_text(encoding="utf-8")
        self.assertIn('"sc009_exact_commit_eligible": immutable_eligible', source)
        self.assertIn('"immutable_release_evidence_eligible": immutable_eligible', source)
        self.assertIn('"diagnostic-uncommitted-working-tree-snapshot"', source)

    def test_environment_and_public_output_redact_credentials_and_machine_paths(self):
        cleaned = removal._clean_environment(
            {
                "PATH": "/usr/bin",
                "HOME": "/Users/alice",
                "LANG": "en_US.UTF-8",
                "GH_TOKEN": "secret-value",
                "GITHUB_TOKEN": "secret-value",
                "CARGO_REGISTRIES_CRATES_IO_TOKEN": "secret-value",
                "HTTPS_PROXY": "https://user:password@example.invalid",
            }
        )
        self.assertEqual(cleaned["PATH"], "/usr/bin")
        for forbidden in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "CARGO_REGISTRIES_CRATES_IO_TOKEN",
            "HTTPS_PROXY",
        ):
            self.assertNotIn(forbidden, cleaned)

        text = (
            "/private/tmp/isolated/kernel /Users/alice/project/file "
            "/Users/alice/project/evidence/report /Users/alice "
            "/dedicated/cargo-target/debug C:\\Users\\alice\\project"
        )
        with mock.patch.object(Path, "home", return_value=Path("/Users/alice")):
            redacted = removal.redact_output(
                text,
                Path("/Users/alice/project"),
                Path("/private/tmp/isolated"),
                Path("/Users/alice/project/evidence"),
                Path("/dedicated/cargo-target"),
            )
        for private in (
            "/private/tmp/isolated",
            "/Users/alice",
            "/dedicated/cargo-target",
            "C:\\Users\\alice",
        ):
            self.assertNotIn(private, redacted)
        self.assertIn("<removal-root>/kernel", redacted)
        self.assertIn("<repo>/file", redacted)
        self.assertIn("<evidence-output>/report", redacted)
        self.assertIn("<cargo-target>/debug", redacted)

        args = argparse.Namespace(
            repository="/Users/alice/project",
            output="/Users/alice/project/evidence",
            manifest=str(MANIFEST_PATH),
            cargo_target_dir="/dedicated/cargo-target",
        )
        with mock.patch.object(Path, "home", return_value=Path("/Users/alice")):
            failure = removal._redact_failure_message(
                "/Users/alice/project helixos-plan005-removal-123/source", args
            )
        self.assertNotIn("/Users/alice", failure)
        self.assertNotIn("helixos-plan005-removal-123", failure)


class Plan005SupplyChainTests(unittest.TestCase):
    def test_current_locked_graph_matches_reviewed_plan005_oracle(self):
        self.assertEqual(
            supply.NONCLAIMS["immutable_release"],
            "requires-attested-zip-independent-verification-and-cataloguing",
        )
        self.assertEqual(
            supply.NONCLAIMS["physical_m4_performance"],
            "not-proven-by-supply-bundle",
        )
        self.assertNotRegex(json.dumps(supply.NONCLAIMS, sort_keys=True), r"T\d{3}")

        metadata = supply._load_metadata(REPOSITORY)
        lock_text = (REPOSITORY / "kernel" / "Cargo.lock").read_text(encoding="utf-8")
        graph = supply.build_production_graph(metadata, lock_text)

        supply.validate_production_graph(graph, metadata, lock_text)
        self.assertEqual(graph["package_count"], 84)
        self.assertEqual(graph["dependency_edge_count"], 143)
        self.assertEqual(
            graph["cargo_lock"]["sha256"],
            "1ee27ea28ed2c51167acb180f79bf5f3722ca26a1c775013c6f7ce3082d87d3c",
        )
        frozen_graph = copy.deepcopy(graph)
        frozen_graph["cargo_lock"]["sha256"] = (
            "f18941ac90749f8eb9adffc2e4e9b91e1d9705da8c0cad0c9fe53b451759ff4d"
        )
        self.assertEqual(
            _sha256(supply.canonical_json_bytes(frozen_graph)),
            supply.EXPECTED_RELEASE_ARTIFACT_SHA256[
                "graph/production-closure.json"
            ],
        )
        self.assertEqual(graph["cargo_lock"]["selected_registry_package_count"], 77)
        self.assertEqual(
            sum(package["source"] == "workspace-path" for package in graph["packages"]),
            7,
        )
        self.assertNotIn("helix-replay-sqlite", {item["name"] for item in graph["packages"]})
        selected, _closures = supply.union_dependency_closure(metadata)
        self.assertEqual(
            supply.resolved_sqlite_features(metadata, selected),
            {
                "libsqlite3-sys": [
                    "bundled",
                    "bundled_bindings",
                    "cc",
                    "default",
                    "min_sqlite_version_3_34_1",
                    "pkg-config",
                    "vcpkg",
                ],
                "rusqlite": ["backup", "bundled", "modern_sqlite", "serialize"],
            },
        )
        missing_required = copy.deepcopy(metadata)
        rusqlite_id = next(
            package["id"]
            for package in missing_required["packages"]
            if package["name"] == "rusqlite"
            and package["version"] == supply.EXPECTED_RUSQLITE_VERSION
        )
        rusqlite_node = next(
            node
            for node in missing_required["resolve"]["nodes"]
            if node["id"] == rusqlite_id
        )
        rusqlite_node["features"].remove("bundled")
        with self.assertRaisesRegex(supply.EvidenceError, "resolved rusqlite features lack"):
            supply.resolved_sqlite_features(missing_required, selected)

    def test_union_closure_keeps_all_roots_normal_and_build_edges_only(self):
        metadata = _synthetic_supply_metadata()

        selected, root_closures = supply.union_dependency_closure(metadata)
        adjacency = supply.production_dependency_adjacency(metadata, selected)
        identities = supply.production_package_identities(metadata, selected)

        self.assertEqual(set(root_closures), set(supply.PRODUCTION_ROOTS))
        self.assertEqual(
            {name: len(package_ids) for name, package_ids in root_closures.items()},
            {
                "helix-dispatch-contracts": 2,
                "helix-plan-dispatch": 4,
                "helix-dispatch-inbox-sqlite": 6,
                "helix-coordinator-sqlite": 8,
            },
        )
        self.assertEqual(len(selected), 8)
        self.assertNotIn("dev-only", selected)
        self.assertFalse(any(identity[0] == "dev-only" for identity in identities))
        self.assertEqual(sum(len(targets) for targets in adjacency.values()), 7)
        self.assertEqual(set(adjacency), identities)

        missing_root = copy.deepcopy(metadata)
        missing_root["packages"] = [
            package
            for package in missing_root["packages"]
            if package["name"] != "helix-dispatch-inbox-sqlite"
        ]
        with self.assertRaisesRegex(supply.EvidenceError, "exactly one.*helix-dispatch-inbox"):
            supply.union_dependency_closure(missing_root)

    def test_graph_manifest_binds_union_full_adjacency_and_exact_lock(self):
        metadata = _synthetic_supply_metadata()
        lock_text = _synthetic_supply_lock()
        graph = supply.build_production_graph(metadata, lock_text)

        supply.validate_production_graph(graph, metadata, lock_text)
        self.assertEqual(graph["package_count"], 8)
        self.assertEqual(graph["dependency_edge_count"], 7)
        self.assertEqual(graph["roots"], list(supply.PRODUCTION_ROOTS))

        missing_edge = copy.deepcopy(graph)
        coordinator = next(
            entry
            for entry in missing_edge["adjacency"]
            if entry["package"]["name"] == "helix-coordinator-sqlite"
        )
        coordinator["dependencies"].pop()
        with self.assertRaisesRegex(supply.EvidenceError, "adjacency"):
            supply.validate_production_graph(missing_edge, metadata, lock_text)

        changed_lock = lock_text.replace("1" * 64, "a" * 64)
        with self.assertRaisesRegex(supply.EvidenceError, "lock"):
            supply.validate_production_graph(graph, metadata, changed_lock)

    def test_semantic_tamper_still_fails_after_manifest_is_rehashed(self):
        metadata = _synthetic_supply_metadata()
        lock_text = _synthetic_supply_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph" / "production-closure.json"
            supply.write_json(graph_path, supply.build_production_graph(metadata, lock_text))
            supply.write_sha256_manifest(root)
            supply.verify_sha256_manifest(root)

            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            graph["root_closures"]["helix-plan-dispatch"]["packages"].pop()
            supply.write_json(graph_path, graph)
            supply.write_sha256_manifest(root)
            supply.verify_sha256_manifest(root)
            with self.assertRaisesRegex(supply.EvidenceError, "root closure"):
                supply.validate_production_graph(graph, metadata, lock_text)

    def test_cyclonedx_union_merge_rekeys_paths_and_preserves_edges(self):
        def sbom(root_name, dependency_name):
            root_ref = "path+file:///Users/private/HelixOS/kernel/{}#0.1.0".format(root_name)
            dependency_ref = "pkg:cargo/{}@1.0.0".format(dependency_name)
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:volatile",
                "metadata": {
                    "timestamp": "2099-01-01T00:00:00Z",
                    "component": {
                        "type": "library",
                        "bom-ref": root_ref,
                        "name": root_name,
                        "version": "0.1.0",
                        "purl": "pkg:cargo/{}@0.1.0?download_url=file://.".format(root_name),
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": dependency_ref,
                        "name": dependency_name,
                        "version": "1.0.0",
                    }
                ],
                "dependencies": [
                    {"ref": root_ref, "dependsOn": [dependency_ref]},
                    {"ref": dependency_ref, "dependsOn": []},
                ],
            }

        merged = supply.merge_cyclonedx_sboms(
            [
                sbom("helix-dispatch-contracts", "shared"),
                sbom("helix-coordinator-sqlite", "shared"),
            ],
            metadata_root="helix-coordinator-sqlite",
        )
        encoded = json.dumps(merged, sort_keys=True)
        self.assertNotIn("serialNumber", merged)
        self.assertNotIn("timestamp", merged["metadata"])
        self.assertNotIn("/Users/private", encoded)
        self.assertNotIn("file://", encoded)
        refs = {
            merged["metadata"]["component"]["bom-ref"],
            *(component["bom-ref"] for component in merged["components"]),
        }
        self.assertEqual({entry["ref"] for entry in merged["dependencies"]}, refs)
        self.assertTrue(
            all(set(entry.get("dependsOn", [])).issubset(refs) for entry in merged["dependencies"])
        )

    def test_cargo_sbom_binds_plus_purl_lock_checksum_and_metadata_license(self):
        source = "registry+https://github.com/rust-lang/crates.io-index"
        identity = ("wasi", "0.11.1+wasi-snapshot-preview1", source)
        checksum = "a" * 64
        component = {
            "type": "library",
            "bom-ref": "{}#{}@{}".format(source, identity[0], identity[1]),
            "name": identity[0],
            "version": identity[1],
            "purl": "pkg:cargo/wasi@0.11.1+wasi-snapshot-preview1",
            "hashes": [{"alg": "SHA-256", "content": checksum}],
            "licenses": [{"expression": "MIT OR Apache-2.0"}],
        }
        sbom = {
            "metadata": {
                "component": component,
                "properties": [
                    {
                        "name": "helixos:plan-005-production-root",
                        "value": root,
                    }
                    for root in sorted(supply.PRODUCTION_ROOTS)
                ],
            },
            "components": [],
        }
        metadata = {
            "packages": [
                {
                    "name": identity[0],
                    "version": identity[1],
                    "source": source,
                    "license": "MIT/Apache-2.0",
                }
            ]
        }
        lock_text = "\n".join(
            (
                "version = 4",
                "",
                "[[package]]",
                'name = "{}"'.format(identity[0]),
                'version = "{}"'.format(identity[1]),
                'source = "{}"'.format(source),
                'checksum = "{}"'.format(checksum),
                "",
            )
        )

        supply.validate_cargo_sbom_identities(sbom, {identity}, metadata, lock_text)
        for field, value, pattern in (
            ("purl", "pkg:cargo/wasi@0.11.1%2Bwasi-snapshot-preview1", "purl"),
            ("hashes", [{"alg": "SHA-256", "content": "0" * 64}], "Cargo.lock"),
            ("licenses", [{"expression": "MIT"}], "license"),
        ):
            tampered = copy.deepcopy(sbom)
            tampered["metadata"]["component"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                supply.EvidenceError, pattern
            ):
                supply.validate_cargo_sbom_identities(
                    tampered, {identity}, metadata, lock_text
                )

    def test_native_sbom_and_native_inventory_semantics_are_closed(self):
        sqlite = supply.SQLiteSource("3.53.2", "source-id", "a" * 64)
        native_component = {
            "bom-ref": "pkg:generic/sqlite@3.53.2",
            "type": "library",
            "name": "SQLite",
            "version": "3.53.2",
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            "licenses": [{"license": {"name": "Public Domain"}}],
            "purl": "pkg:generic/sqlite@3.53.2",
            "properties": [
                {"name": "helixos:bundled-by", "value": "libsqlite3-sys-0.38.1"},
                {"name": "helixos:sqlite-source-id", "value": "source-id"},
            ],
        }
        with mock.patch.object(supply, "validate_retained_sbom"), mock.patch.object(
            supply, "validate_cargo_sbom_identities"
        ):
            supply.validate_plan005_sbom(
                {"components": [native_component]}, sqlite, set(), {}, {}, ""
            )
            tampered = copy.deepcopy(native_component)
            tampered["properties"][0]["value"] = "some-other-wrapper"
            with self.assertRaisesRegex(supply.EvidenceError, "SQLite semantics"):
                supply.validate_plan005_sbom(
                    {"components": [tampered]}, sqlite, set(), {}, {}, ""
                )

        identity = supply.expected_supply_identity()["native_sqlite"]
        native = {
            "schema": supply.NATIVE_SCHEMA,
            "libsqlite3_sys_version": supply.EXPECTED_LIBSQLITE_VERSION,
            "libsqlite3_sys_crate_sha256": "b" * 64,
            "rusqlite_version": supply.EXPECTED_RUSQLITE_VERSION,
            "sqlite_version": supply.EXPECTED_SQLITE_VERSION,
            "sqlite_source_id": supply.EXPECTED_SQLITE_SOURCE_ID,
            "sqlite3_c_sha256": "c" * 64,
            "sqlite3_h_sha256": "d" * 64,
            "link_profile": identity["link_profile"],
            "resolved_features": {"rusqlite": [], "libsqlite3-sys": []},
            "forbidden_features_absent": sorted(identity["forbidden_features"]),
            "license": "Public Domain notice embedded in retained sqlite3.c/sqlite3.h",
        }
        with mock.patch.object(
            supply.plan004,
            "_validate_native_evidence",
            return_value=sqlite,
        ):
            supply._validate_native_evidence(Path("."), native, {}, set(), REPOSITORY)
            native["license"] = "MIT"
            with self.assertRaisesRegex(supply.EvidenceError, "SQLite identity"):
                supply._validate_native_evidence(
                    Path("."), native, {}, set(), REPOSITORY
                )

    def test_release_oracle_and_license_expression_are_exact(self):
        graph = {
            "package_count": 84,
            "dependency_edge_count": 143,
        }
        inventory = {
            "package_count": 84,
            "external_package_count": 77,
            "workspace_package_count": 7,
            "spdx_texts": [
                {"identifier": identifier, "kind": kind, "sha256": digest}
                for identifier, (kind, digest) in supply.EXPECTED_SPDX_TEXTS.items()
            ],
        }
        supply.validate_release_oracle(graph, inventory)
        tampered = copy.deepcopy(inventory)
        tampered["spdx_texts"].pop()
        with self.assertRaisesRegex(supply.EvidenceError, "oracle"):
            supply.validate_release_oracle(graph, tampered)

        source = "registry+https://github.com/rust-lang/crates.io-index"
        identity = ("base64", "0.22.1", source)
        metadata = {
            "packages": [
                {
                    "name": identity[0],
                    "version": identity[1],
                    "source": identity[2],
                    "license": "MIT OR Apache-2.0",
                    "manifest_path": "/unused/Cargo.toml",
                }
            ]
        }
        license_inventory = {
            "schema": supply.LICENSE_SCHEMA,
            "root_packages": list(supply.PRODUCTION_ROOTS),
            "spdx_license_list_revision": supply.EXPECTED_SPDX_REVISION,
            "scope": "union-normal-and-build-dependency-closure-with-all-features-and-targets",
            "packages": [
                {
                    "name": identity[0],
                    "version": identity[1],
                    "source": identity[2],
                    "license_expression": "MIT",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "kernel").mkdir()
            (repository / "kernel" / "Cargo.lock").write_text(
                "version = 4\n", encoding="utf-8"
            )
            with mock.patch.object(supply.plan004, "_validate_license_inventory"):
                with self.assertRaisesRegex(supply.EvidenceError, "cargo metadata"):
                    supply._validate_license_inventory(
                        repository,
                        license_inventory,
                        metadata,
                        {identity},
                        repository,
                    )

    def test_removal_protected_modes_support_closed_posix_and_windows_profiles(self):
        digest = "a" * 64
        windows = {
            "expected_mode": "100755",
            "expected_sha256": digest,
            "observed_mode": "100644",
            "observed_sha256": digest,
            "mode_verification": "git-index",
            "matches_baseline": True,
        }
        self.assertEqual(
            supply._validate_removal_protected_record(windows, "100755", digest),
            "git-index",
        )
        posix = copy.deepcopy(windows)
        posix["mode_verification"] = "filesystem-and-git-index"
        posix["observed_mode"] = "100755"
        self.assertEqual(
            supply._validate_removal_protected_record(posix, "100755", digest),
            "filesystem-and-git-index",
        )
        posix["observed_mode"] = "100644"
        with self.assertRaisesRegex(supply.EvidenceError, "record mismatch"):
            supply._validate_removal_protected_record(posix, "100755", digest)

    def test_exact_checkout_rejects_untracked_and_repository_cargo_config(self):
        completed = mock.Mock(returncode=0, stdout=b"")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            supply.subprocess, "run", return_value=completed
        ):
            repository = Path(directory)
            self.assertTrue(supply._tracked_checkout_clean(repository))
            (repository / ".cargo").mkdir()
            (repository / ".cargo" / "config.toml").write_text(
                "[build]\n", encoding="utf-8"
            )
            self.assertFalse(supply._tracked_checkout_clean(repository))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            supply.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout=b"?? surprise\n"),
        ):
            self.assertFalse(supply._tracked_checkout_clean(Path(directory)))

    def test_pinned_identity_rejects_rustsec_spdx_sqlite_and_provenance_tamper(self):
        identity = supply.expected_supply_identity()
        supply.validate_supply_identity(identity)
        for path, replacement, pattern in (
            (("toolchain", "rustsec_database_revision"), "0" * 40, "RustSec"),
            (("toolchain", "spdx_license_list_revision"), "f" * 40, "SPDX"),
            (("native_sqlite", "sqlite_version"), "3.0.0", "SQLite"),
            (("native_sqlite", "rusqlite_version"), "0.1.0", "rusqlite"),
        ):
            tampered = copy.deepcopy(identity)
            tampered[path[0]][path[1]] = replacement
            with self.assertRaisesRegex(supply.EvidenceError, pattern):
                supply.validate_supply_identity(tampered)
        tampered = copy.deepcopy(identity)
        tampered["release_artifact_sha256"]["sbom/plan-005-sbom.cdx.json"] = "0" * 64
        with self.assertRaisesRegex(supply.EvidenceError, "artifact oracle"):
            supply.validate_supply_identity(tampered)
        tampered = copy.deepcopy(identity)
        tampered["immutable_release"] = True
        with self.assertRaisesRegex(supply.EvidenceError, "unexpected fields"):
            supply.validate_supply_identity(tampered)

        exact = supply.build_provenance(
            source_commit="a" * 40,
            source_tree="b" * 40,
            source_mode="exact-commit",
            tracked_checkout_clean=True,
            workflow_path=".github/workflows/durable-dispatch.yml",
            workflow_sha256="c" * 64,
            tool_sha256="d" * 64,
            helper_sha256="e" * 64,
            artifact_name="plan-005-release-{}".format("a" * 40),
            repository_slug="owner/repository",
            workflow_ref="owner/repository/.github/workflows/durable-dispatch.yml@refs/heads/main",
            run_id="123",
            run_attempt="1",
            runner_os="macOS",
            runner_arch="ARM64",
            runner_name="runner",
            image_os="macos26",
            image_version="20260701.1",
            source_timestamp="2026-07-14T00:00:00Z",
            scan_timestamp="2026-07-14T00:00:01Z",
        )
        supply.validate_provenance(exact, expected_commit="a" * 40, require_exact=True)
        exact["source"]["tree"] = "0" * 40
        with self.assertRaisesRegex(supply.EvidenceError, "tree"):
            supply.validate_provenance(exact, expected_commit="a" * 40, require_exact=True)

    def test_bundle_scan_rejects_secret_and_posix_windows_or_file_paths(self):
        samples = (
            ("secret.txt", "github_pat_" + "A" * 32, "secret"),
            (
                "escaped-secret.json",
                '{"value":"github\\u005fpat_' + "A" * 32 + '"}',
                "secret",
            ),
            (
                "nested-encoded-secret.txt",
                "github%2525255fpat_" + "A" * 32,
                "secret",
            ),
            ("posix.txt", "/Users/private-owner/project", "private path"),
            ("posix-case.txt", "/users/private-owner/project", "private path"),
            ("private-tmp.json", '{"path":"/private/tmp/private-owner/project"}', "private path"),
            ("encoded-path.txt", "%2Fvar%2Ffolders%2Fprivate-owner%2Fproject", "private path"),
            (
                "nested-encoded-path.txt",
                "%2525252FUsers%2525252Fprivate-owner%2525252Fproject",
                "private path",
            ),
            ("windows.txt", r"C:\\Users\\private-owner\\project", "private path"),
            ("windows-case.txt", r"c:\\users\\private-owner\\project", "private path"),
            ("uri.txt", "file:///home/private-owner/project", "private path"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content, expected in samples:
                path = root / name
                path.write_text(content + "\n", encoding="utf-8")
                with self.subTest(name=name), self.assertRaisesRegex(supply.EvidenceError, expected):
                    supply.scan_text_paths([path])
                path.unlink()
            deeply_encoded = "/Users/private-owner/project"
            for _ in range(20):
                deeply_encoded = deeply_encoded.replace("%", "%25").replace(
                    "/", "%2F"
                )
            path = root / "excessive-encoding.txt"
            path.write_text(deeply_encoded + "\n", encoding="utf-8")
            with self.assertRaisesRegex(supply.EvidenceError, "nested URL encoding"):
                supply.scan_text_paths([path])
            boundary_encoded = "/Users/private-owner/project"
            for _ in range(16):
                boundary_encoded = boundary_encoded.replace("%", "%25").replace(
                    "/", "%2F"
                )
            path.write_text(boundary_encoded + "\n", encoding="utf-8")
            with self.assertRaisesRegex(supply.EvidenceError, "private path"):
                supply.scan_text_paths([path])

    def test_manifest_rejects_symlinks_traversal_extra_and_digest_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("a\n", encoding="utf-8")
            supply.write_sha256_manifest(root)
            supply.verify_sha256_manifest(root)

            (root / "a.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(supply.EvidenceError, "digest mismatch"):
                supply.verify_sha256_manifest(root)

            (root / "a.txt").write_text("a\n", encoding="utf-8")
            (root / supply.MANIFEST_NAME).write_text("{}  ../escape\n".format("0" * 64), encoding="utf-8")
            with self.assertRaisesRegex(supply.EvidenceError, "unsafe"):
                supply.verify_sha256_manifest(root)

            (root / supply.MANIFEST_NAME).unlink()
            (root / "link").symlink_to(root / "a.txt")
            with self.assertRaisesRegex(supply.EvidenceError, "symlink"):
                supply.write_sha256_manifest(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            checkout_link = root / "checkout-link"
            checkout_link.symlink_to(checkout)
            with self.assertRaisesRegex(supply.EvidenceError, "unsafe"):
                supply._verify_pinned_checkout(checkout_link, "a" * 40, "test")
            bundle = root / "bundle"
            bundle.mkdir()
            bundle_link = root / "bundle-link"
            bundle_link.symlink_to(bundle)
            with self.assertRaisesRegex(supply.EvidenceError, "unsafe"):
                supply.verify_bundle(bundle_link, REPOSITORY)
            parent_link = root / "parent-link"
            parent_link.symlink_to(root)
            with self.assertRaisesRegex(supply.EvidenceError, "unsafe"):
                supply.verify_bundle(parent_link / "bundle", REPOSITORY)

        if hasattr(os, "mkfifo"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.mkfifo(root / "unmanifested-fifo")
                with self.assertRaisesRegex(supply.EvidenceError, "non-regular"):
                    supply.write_sha256_manifest(root)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(supply.EvidenceError, "existing PLAN-005 bundle"):
                supply.refresh_bundle_manifest(Path(directory))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("descriptor.json", "identity.json", "provenance.json"):
                supply.write_json(root / name, {})
            supply.write_sha256_manifest(root)
            supply.refresh_bundle_manifest(root)
            supply.verify_sha256_manifest(root)

    def test_rustsec_fail_closed_rules_and_simple_quickstart_cli(self):
        clean = {
            "database": {"advisory-count": 900},
            "lockfile": {"dependency-count": 216},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {
                "unmaintained": [
                    {"advisory": {"id": "RUSTSEC-2025-0134"}, "package": {}}
                ]
            },
        }
        supply.validate_audit_report(clean)
        vulnerable = copy.deepcopy(clean)
        vulnerable["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [{"advisory": {"id": "RUSTSEC-2099-0001"}}],
        }
        with self.assertRaisesRegex(supply.EvidenceError, "vulnerabilit"):
            supply.validate_audit_report(vulnerable)
        idless = copy.deepcopy(clean)
        idless["warnings"]["yanked"] = [{"package": {"name": "surprise"}}]
        with self.assertRaisesRegex(supply.EvidenceError, "untriaged"):
            supply.validate_audit_report(idless)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            supply.write_json(report, clean)
            with self.assertRaisesRegex(supply.EvidenceError, "pinned PLAN-005 oracle"):
                supply.validate_rustsec_report_oracle(report)

        parser = supply.build_parser()
        build = parser.parse_args(
            ["build", "--repository", ".", "--output", "/tmp/plan005-supply"]
        )
        self.assertEqual(build.command, "build")
        self.assertIsNone(build.source_commit)
        verify = parser.parse_args(
            ["verify", "--repository", ".", "--output", "/tmp/plan005-supply"]
        )
        self.assertEqual(verify.command, "verify")
        self.assertFalse(verify.require_exact)

        diagnostic = supply.build_provenance(
            source_commit="a" * 40,
            source_tree="b" * 40,
            source_mode="diagnostic-working-tree",
            tracked_checkout_clean=False,
            workflow_path="pending-T089",
            workflow_sha256="0" * 64,
            tool_sha256="d" * 64,
            helper_sha256="e" * 64,
            artifact_name="plan-005-supply-diagnostic",
            repository_slug="diagnostic/local",
            workflow_ref="diagnostic-not-a-workflow-run",
            run_id="0",
            run_attempt="0",
            runner_os=supply.platform.system(),
            runner_arch=supply.platform.machine(),
            runner_name="diagnostic-local",
            image_os=supply.platform.platform(),
            image_version="diagnostic-local",
            source_timestamp="2026-07-14T00:00:00Z",
            scan_timestamp="2026-07-14T00:00:01Z",
        )
        supply.validate_provenance(diagnostic)
        with self.assertRaisesRegex(supply.EvidenceError, "cannot be promoted"):
            supply.validate_provenance(diagnostic, require_exact=True)
        changed_artifact = copy.deepcopy(diagnostic)
        changed_artifact["artifact"]["attestation_subject"] = "unbound"
        with self.assertRaisesRegex(supply.EvidenceError, "artifact provenance binding"):
            supply.validate_provenance(changed_artifact)
        with self.assertRaisesRegex(supply.EvidenceError, "cleanliness"):
            supply.validate_provenance(diagnostic, expected_checkout_clean=True)
        diagnostic["immutable_release"] = True
        with self.assertRaisesRegex(supply.EvidenceError, "unexpected fields"):
            supply.validate_provenance(diagnostic)

        private_output = "/private/tmp/private-owner/evidence"
        stderr = io.StringIO()
        with mock.patch.object(
            supply,
            "verify_bundle",
            side_effect=supply.EvidenceError(
                "invalid JSON evidence: {}/descriptor.json".format(private_output)
            ),
        ), contextlib.redirect_stderr(stderr):
            result = supply.main(
                ["verify", "--repository", str(REPOSITORY), "--output", private_output]
            )
        self.assertEqual(result, 1)
        self.assertNotIn(private_output, stderr.getvalue())
        self.assertIn("<evidence-output>", stderr.getvalue())


class Plan005PortabilityAndBoundaryTests(unittest.TestCase):
    CRATES = {
        "helix-dispatch-contracts": {
            "base64",
            "ed25519-dalek",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
            "sha2",
            "unicode-normalization",
        },
        "helix-plan-dispatch": {"getrandom", "helix-dispatch-contracts"},
        "helix-dispatch-inbox-sqlite": {
            "helix-dispatch-contracts",
            "helix-plan-dispatch",
            "rusqlite",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
            "sha2",
        },
    }

    def test_plan005_crates_have_closed_exact_pinned_dependency_boundaries(self):
        workspace = (REPOSITORY / "kernel" / "Cargo.toml").read_text(encoding="utf-8")
        members_block = re.search(r"(?ms)^members\s*=\s*\[(.*?)^\]", workspace)
        self.assertIsNotNone(members_block)
        members = re.findall(r'"([^"]+)"', members_block.group(1))
        for crate in self.CRATES:
            self.assertEqual(members.count(crate), 1)

        for crate, expected in self.CRATES.items():
            manifest = REPOSITORY / "kernel" / crate / "Cargo.toml"
            dependencies = _toml_table(manifest, "dependencies")
            self.assertEqual(set(dependencies), expected)
            text = manifest.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?m)^\s*(git|workspace)\s*=")
            self.assertNotIn("http://", text)
            self.assertNotIn("https://", text)
            for name, value in dependencies.items():
                if "path" in value:
                    self.assertRegex(value, r'^\{\s*path\s*=\s*"\.\./[a-z0-9-]+"\s*\}$')
                else:
                    self.assertTrue(
                        value.startswith('"=')
                        or re.search(r'\bversion\s*=\s*"=', value),
                        "{} dependency {} is not exactly pinned: {}".format(crate, name, value),
                    )
            self.assertTrue(
                (REPOSITORY / "kernel" / crate / "src" / "lib.rs")
                .read_text(encoding="utf-8")
                .startswith("//!"),
            )
            self.assertIn(
                "#![forbid(unsafe_code)]",
                (REPOSITORY / "kernel" / crate / "src" / "lib.rs").read_text(encoding="utf-8"),
            )
        for forbidden in ("helixos-kernel", "helix-plan-preparation", "helix-contracts"):
            self.assertNotIn(
                forbidden,
                set(_toml_table(REPOSITORY / "kernel" / "helix-plan-dispatch" / "Cargo.toml", "dependencies")),
            )
        windows_dependencies = _toml_table(
            REPOSITORY / "kernel" / "helix-dispatch-inbox-sqlite" / "Cargo.toml",
            "target.'cfg(windows)'.dependencies",
        )
        self.assertEqual(set(windows_dependencies), {"fs-id"})
        self.assertRegex(
            windows_dependencies["fs-id"],
            r'^\{\s*version\s*=\s*"=0\.2\.0",\s*default-features\s*=\s*false\s*\}$',
        )

    def test_production_sources_expose_no_direct_egress_ambient_secret_or_execution_token(self):
        roots = [REPOSITORY / "kernel" / crate / "src" for crate in self.CRATES]
        forbidden = [
            r"\bstd::net\b",
            r"\bTcpStream\b",
            r"\bUdpSocket\b",
            r"\bCommand::new\b",
            r"\bstd::process::Command\b",
            r"\bstd::env::var(?:_os)?\b",
            r"\breqwest\b",
            r"\bhyper::",
            r"\bureq\b",
            r"\btonic::",
            r"\bExecutionToken\b",
            r"\bExecutionPermit\b",
            r"\bPreparedOperationV1\b",
            r"\bhelixos_kernel\b",
        ]
        for root in roots:
            for path in _rust_sources(root):
                source = path.read_text(encoding="utf-8")
                for pattern in forbidden:
                    self.assertIsNone(re.search(pattern, source), "{} contains {}".format(path, pattern))

        portable = "\n".join(
            path.read_text(encoding="utf-8")
            for path in _rust_sources(REPOSITORY / "kernel" / "helix-plan-dispatch" / "src")
        )
        for forbidden in ("std::fs", "std::path", "rusqlite", "OpenOptions", "File::open"):
            self.assertNotIn(forbidden, portable)

    def test_committed_plan005_text_has_no_high_confidence_secret_or_native_private_path(self):
        roots = [
            REPOSITORY / "specs" / "005-durable-dispatch",
            REPOSITORY / "contracts" / "fixtures" / "durable-dispatch-v1",
            REPOSITORY / "kernel" / "helix-dispatch-contracts" / "src",
            REPOSITORY / "kernel" / "helix-plan-dispatch" / "src",
            REPOSITORY / "kernel" / "helix-dispatch-inbox-sqlite" / "src",
        ]
        secret_patterns = [
            rb"github_pat_[A-Za-z0-9_]{20,}",
            rb"ghp_[A-Za-z0-9]{20,}",
            rb"AKIA[0-9A-Z]{16}",
            rb"xox[baprs]-[A-Za-z0-9-]{10,}",
            rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ]
        private_path_patterns = [
            rb"/Users/[^<\s]+",
            rb"/home/[^<\s]+",
            rb"[A-Za-z]:\\Users\\[^<\s]+",
            rb"file://(?:/|[A-Za-z]:)",
        ]
        for root in roots:
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                content = path.read_bytes()
                for pattern in secret_patterns + private_path_patterns:
                    self.assertIsNone(re.search(pattern, content), "{} contains sensitive material".format(path))

        backup_schema = json.loads(
            (
                REPOSITORY
                / "specs"
                / "005-durable-dispatch"
                / "contracts"
                / "dispatch-backup-manifest-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        property_names = set()

        def collect(value):
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    property_names.update(properties)
                for member in value.values():
                    collect(member)
            elif isinstance(value, list):
                for member in value:
                    collect(member)

        collect(backup_schema)
        for forbidden in (
            "private_key",
            "secret",
            "secret_key",
            "signing_key",
            "seed",
            "key_material",
            "key_bytes",
            "mnemonic",
            "password",
            "token",
        ):
            self.assertFalse(
                any(forbidden in name.lower() for name in property_names),
                "backup schema exposes {}".format(forbidden),
            )

    def test_fault_registry_is_frozen_closed_and_preserves_plan004_bytes(self):
        authoritative_path = (
            REPOSITORY
            / "specs"
            / "005-durable-dispatch"
            / "contracts"
            / "fault-boundaries-v1.json"
        )
        fixture_path = (
            REPOSITORY / "contracts" / "fixtures" / "durable-dispatch-v1" / "fault-boundaries.json"
        )
        authoritative_bytes = authoritative_path.read_bytes()
        fixture_bytes = fixture_path.read_bytes()
        authoritative = json.loads(authoritative_bytes)
        fixture = json.loads(fixture_bytes)
        self.assertEqual(
            _sha256(authoritative_bytes),
            "afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26",
        )
        self.assertEqual(fixture["authoritative_sha256"], _sha256(authoritative_bytes))
        self.assertEqual(authoritative["boundary_count"], 90)
        self.assertEqual(authoritative["required_case_count"], 180)
        self.assertEqual(fixture["boundary_count"], 90)
        self.assertEqual(fixture["declared_case_count"], 180)
        self.assertEqual(fixture["boundaries"], authoritative["boundaries"])

        boundaries = authoritative["boundaries"]
        self.assertEqual([item["ordinal"] for item in boundaries], list(range(1, 91)))
        self.assertEqual(
            [item["id"] for item in boundaries],
            ["PLAN005-FB-{:03d}".format(index) for index in range(1, 91)],
        )
        self.assertEqual(
            Counter(item["category"] for item in boundaries),
            Counter(authoritative["category_counts"]),
        )
        self.assertTrue(
            all(item["coverage"] == ["in-process", "process-kill"] for item in boundaries)
        )
        by_id = {item["id"]: item for item in boundaries}
        self.assertEqual(len(by_id), 90)
        self.assertEqual([item["case_ordinal"] for item in fixture["cases"]], list(range(1, 181)))
        for boundary_id, cases in {
            boundary_id: [case for case in fixture["cases"] if case["boundary_id"] == boundary_id]
            for boundary_id in by_id
        }.items():
            self.assertEqual([case["mode"] for case in cases], ["in-process", "process-kill"])
            for case in cases:
                self.assertEqual(case["selected_boundary_ids"], [boundary_id])
                self.assertEqual(case["expected_reach_count"], 1)
                self.assertEqual(case["expected_injection_count"], 1)
                self.assertEqual(case["expected_class"], by_id[boundary_id]["expected_class"])

        plan004 = authoritative["plan004_registry"]
        self.assertEqual(plan004["boundary_count"], 123)
        self.assertEqual(plan004["declared_fault_case_count"], 167)
        self.assertEqual(plan004["fixture_total_case_count"], 335)
        for path_key, digest_key in (
            ("source_path", "source_sha256"),
            ("fixture_path", "fixture_sha256"),
        ):
            self.assertEqual(
                removal.sha256_file(REPOSITORY / plan004[path_key]), plan004[digest_key]
            )


class Plan005WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not WORKFLOW_PATH.is_file():
            raise AssertionError("T089 workflow is absent")
        cls.raw = WORKFLOW_PATH.read_bytes()
        cls.workflow = cls.raw.decode("utf-8")

    @classmethod
    def job(cls, name):
        match = re.search(r"(?m)^  {}:\s*$".format(re.escape(name)), cls.workflow)
        if match is None:
            raise AssertionError("missing workflow job {}".format(name))
        following = re.search(r"(?m)^  [a-z0-9-]+:\s*$", cls.workflow[match.end() :])
        end = match.end() + following.start() if following else len(cls.workflow)
        return cls.workflow[match.start() : end]

    @staticmethod
    def step(job, name):
        match = re.search(r"(?m)^      - name: {}\s*$".format(re.escape(name)), job)
        if match is None:
            raise AssertionError("missing workflow step {}".format(name))
        following = re.search(r"(?m)^      - name: .+$", job[match.end() :])
        end = match.end() + following.start() if following else len(job)
        return job[match.start() : end]

    def test_workflow_is_lf_only_and_all_actions_are_immutable_exact_pins(self):
        self.assertEqual(
            _sha256(self.raw),
            "638b484082d82b9a740675050babc602610580bf908030263b616396c3b66dfa",
        )
        self.assertNotIn(b"\r", self.raw)
        self.assertNotIn(b"\t", self.raw)
        supply.scan_text_paths([WORKFLOW_PATH])
        self.assertNotIn("secrets.", self.workflow)
        self.assertIn(
            "physical_m4_performance=passing-controlled-physical-local-working-tree-not-immutable",
            self.workflow,
        )
        self.assertEqual(self.workflow.count("${{ github.token }}"), 1)
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*([^@\s]+)@([^\s]+)", self.workflow)
        self.assertTrue(uses)
        expected = {
            "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
            "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/attest": "a1948c3f048ba23858d222213b7c278aabede763",
        }
        self.assertEqual(set(action for action, _revision in uses), set(expected))
        for action, revision in uses:
            self.assertEqual(revision, expected[action])
            self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_path_policy_checkout_contains_the_frozen_baseline_history(self):
        path_policy = self.job("path-policy")
        checkout = self.step(path_policy, "Check out repository")
        self.assertIn("fetch-depth: 0", checkout)
        self.assertIn("persist-credentials: false", checkout)

    def test_historical_workflows_exclude_plan005_release_contention_oracles(self):
        release_oracles = (
            "exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption",
            "exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round",
            "exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round",
        )
        owner = (
            ".github/workflows/durable-dispatch.yml#plan005-release-contention-gates"
        )
        self.assertEqual(
            self.workflow.count("        id: plan005-release-contention-gates"), 1
        )
        historical_steps = (
            (
                REPOSITORY / ".github" / "workflows" / "contracts.yml",
                "Test workspace",
            ),
            (
                REPOSITORY / ".github" / "workflows" / "durable-preparation.yml",
                "Test hosted coordinator surfaces outside the controlled timing oracle",
            ),
        )
        for workflow_path, step_name in historical_steps:
            text = workflow_path.read_text(encoding="utf-8")
            match = re.search(
                r"(?ms)^      - name: {}\s*$.*?(?=^      - name: )".format(
                    re.escape(step_name)
                ),
                text,
            )
            self.assertIsNotNone(match, str(workflow_path))
            self.assertEqual(
                tuple(re.findall(r"(?m)^\s+--skip (\S+)\s*$", match.group(0))),
                (
                    "held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later",
                )
                + release_oracles,
            )
            descriptor = re.search(
                r"(?ms)^\s+excluded_downstream_release_oracles = @\(\n(?P<values>.*?)^\s+\)$",
                text,
            )
            self.assertIsNotNone(descriptor, str(workflow_path))
            self.assertEqual(
                tuple(re.findall(r"'([^']+)'", descriptor.group("values"))),
                release_oracles,
            )
            summary = re.search(
                r"(?m)^\s+'excluded_downstream_release_oracles=([^']+)'", text
            )
            self.assertIsNotNone(summary, str(workflow_path))
            self.assertEqual(tuple(summary.group(1).split(",")), release_oracles)
            self.assertEqual(text.count(owner), 2)
        for workflow_path in (
            ".github/workflows/contracts.yml",
            ".github/workflows/durable-preparation.yml",
        ):
            self.assertEqual(self.workflow.count('- "{}"'.format(workflow_path)), 2)

    def test_matrix_has_exact_three_hosts_and_fails_closed_on_actual_identity(self):
        conformance = self.job("conformance")
        self.assertIn("- codex/plan-005-durable-dispatch", self.workflow)
        for prerequisite_path in (
            '"kernel/helixos-kernel/**"',
            '"kernel/helixos-mcp-shim/**"',
            '"kernel/helixos-provision/**"',
        ):
            self.assertEqual(self.workflow.count(prerequisite_path), 2)
        matrix = conformance[
            conformance.index("      matrix:\n") : conformance.index("\n\n    steps:")
        ]
        self.assertEqual(re.findall(r"(?m)^        ([a-z0-9_-]+):", matrix), ["include"])
        self.assertEqual(len(re.findall(r"(?m)^          - ", matrix)), 3)
        self.assertNotIn("exclude:", matrix)
        hosts = re.findall(
            r"(?m)^\s{10}- platform: (\S+)\n"
            r"\s{12}runner: (\S+)\n"
            r"\s{12}expected_host: (\S+)\n"
            r"\s{12}expected_runner_os: (\S+)\n"
            r"\s{12}expected_runner_arch: (\S+)$",
            conformance,
        )
        self.assertEqual(
            hosts,
            [
                (
                    "linux-x86_64",
                    "ubuntu-24.04",
                    "x86_64-unknown-linux-gnu",
                    "Linux",
                    "X64",
                ),
                (
                    "macos-arm64",
                    "macos-26",
                    "aarch64-apple-darwin",
                    "macOS",
                    "ARM64",
                ),
                (
                    "windows-x64",
                    "windows-2022",
                    "x86_64-pc-windows-msvc",
                    "Windows",
                    "X64",
                ),
            ],
        )
        for required in (
            "runner host mismatch",
            "runner OS mismatch",
            "runner architecture mismatch",
            "hosted runner image provenance is unavailable",
            "${{ matrix.expected_host }}",
            "${{ matrix.expected_runner_os }}",
            "${{ matrix.expected_runner_arch }}",
        ):
            self.assertIn(required, conformance)

    def test_prerequisite_contract_fault_migration_restore_and_overload_gates_are_explicit(self):
        path_policy = self.job("path-policy")
        conformance = self.job("conformance")
        self.assertNotRegex(path_policy, r"(?m)^    if\s*:")
        self.assertNotRegex(conformance, r"(?m)^    if\s*:")
        critical_steps = (
            "Install pinned Rust and assert exact hosted identity",
            "Check format, locked workspace and strict Clippy",
            "Test unchanged PLAN-001 through PLAN-004 prerequisite chain",
            "Prove canonical contracts, portable corpus and 100,000 mutations",
            "Prove exact end-to-end one-shot contention cardinalities",
            "Prove migration, clean restore, corruption and permanent retention",
            "Prove all 180 in-process and process-kill fault cases",
            "Prove overload backpressure and reserved control lane",
            "Capture exact hosted evidence descriptor",
            "Assert validation did not rewrite tracked bytes",
            "Upload retained hosted evidence",
        )
        for name in critical_steps:
            self.assertNotRegex(self.step(conformance, name), r"(?m)^        if\s*:")
        gate_condition_counts = {
            "Check format, locked workspace and strict Clippy": 3,
            "Test unchanged PLAN-001 through PLAN-004 prerequisite chain": 2,
            "Prove canonical contracts, portable corpus and 100,000 mutations": 3,
            "Prove exact end-to-end one-shot contention cardinalities": 3,
            "Prove migration, clean restore, corruption and permanent retention": 2,
            "Prove all 180 in-process and process-kill fault cases": 6,
            "Prove overload backpressure and reserved control lane": 2,
        }
        for name, expected_count in gate_condition_counts.items():
            conditions = re.findall(
                r"(?m)^\s+if \(([^)]+)\) \{$", self.step(conformance, name)
            )
            self.assertEqual(conditions, ["$LASTEXITCODE -ne 0"] * expected_count)
        contention = self.step(
            conformance, "Prove exact end-to-end one-shot contention cardinalities"
        )
        self.assertEqual(contention.count("cargo test --locked --release"), 3)
        for exact_name in (
            "exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption",
            "exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round",
            "exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round",
        ):
            self.assertEqual(contention.count(exact_name), 1)
        quality = self.step(conformance, "Check format, locked workspace and strict Clippy")
        rustfmt = quality[: quality.index("          if ($LASTEXITCODE -ne 0) {")]
        self.assertEqual(
            tuple(re.findall(r"--package ([a-z0-9-]+)", rustfmt)),
            supply.PRODUCTION_ROOTS,
        )
        for forbidden in (
            "--all",
            "--workspace",
            "continue-on-error",
            "helixos-kernel",
            "helixos-mcp-shim",
            "helixos-provision",
        ):
            self.assertNotIn(forbidden, rustfmt)
        self.assertIn(
            "cargo check --locked --manifest-path kernel/Cargo.toml `\n"
            "            --workspace --all-targets",
            quality,
        )
        self.assertIn(
            "cargo clippy --locked --manifest-path kernel/Cargo.toml `\n"
            "            --workspace --all-targets --all-features -- -D warnings",
            quality,
        )
        quickstart = QUICKSTART_PATH.read_text(encoding="utf-8")
        quickstart_fmt = quickstart[
            quickstart.index("cargo fmt \\\n") : quickstart.index(
                "cargo check --locked --workspace --all-targets"
            )
        ]
        self.assertEqual(
            tuple(re.findall(r"--package ([a-z0-9-]+)", quickstart_fmt)),
            supply.PRODUCTION_ROOTS,
        )
        self.assertNotIn("--all", quickstart_fmt)
        required = (
            "--package helix-contracts",
            "--package helix-plan-eligibility",
            "--package helix-replay-sqlite",
            "--package helix-plan-preparation",
            "--package helix-dispatch-contracts",
            "--package helix-plan-dispatch",
            "durable_dispatch_corpus",
            "release_100_000_generated_mutations_follow_closed_oracle",
            "dispatch_end_to_end_contention",
            "dispatch_migration",
            "dispatch_restore",
            "backup_restore",
            "dispatch_faults",
            "dispatch_maintenance_faults",
            "process_crash",
            "release_in_process_coordinator_handoff_and_readback_matrix",
            "release_process_kill_coordinator_handoff_and_readback_matrix",
            "release_dispatch_lifecycle_in_process_matrix",
            "release_dispatch_lifecycle_process_kill_matrix",
            "release_adapter_in_process_matrix_reopens_to_one_closed_state",
            "release_adapter_process_kill_matrix_reopens_to_one_closed_state",
            "dispatch_queue_control",
            "queue_control",
            "release_coordinator_queue_control_profile_cardinalities",
            "release_adapter_saturation_and_control_latency_profile",
        )
        for value in required:
            self.assertIn(value, conformance)
        self.assertEqual(
            conformance.count("-- --exact --ignored --nocapture --test-threads=1"),
            9,
        )
        for exact_name in (
            "exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption",
            "exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round",
            "exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round",
        ):
            self.assertGreaterEqual(conformance.count(exact_name), 2)
        self.assertIn("--locked", conformance)
        self.assertIn("--test-threads=1", conformance)
        self.assertNotIn("continue-on-error", self.workflow)

    def test_release_chain_uses_clean_external_bundle_and_requires_exact_removal(self):
        conformance = self.job("conformance")
        release = self.job("release-evidence")
        attestation = self.job("attest-evidence")
        self.assertEqual(re.findall(r"(?m)^    needs: (.+)$", conformance), ["path-policy"])
        self.assertEqual(re.findall(r"(?m)^    needs: (.+)$", release), ["conformance"])
        self.assertRegex(
            attestation,
            r"(?m)^    needs:\n      - conformance\n      - release-evidence$",
        )
        self.assertNotRegex(release, r"(?m)^    if\s*:")
        for name in (
            "Check out exact repository history",
            "Install pinned Rust and evidence tools outside the checkout",
            "Build exact supply-chain release bundle",
            "Execute exact isolated removal and final semantic verification",
            "Assert exact release evidence left the checkout clean",
            "Upload exact release evidence bundle",
        ):
            self.assertNotRegex(self.step(release, name), r"(?m)^        if\s*:")
        self.assertIn("fetch-depth: 0", release)
        for required in (
            'test -z "$(git status --porcelain=v1 --untracked-files=all)"',
            '"$RUNNER_TEMP/plan-005-release-evidence"',
            "tools/plan005_supply_chain.py build",
            '--source-commit "$GITHUB_SHA"',
            "tools/plan005_removal_drill.py",
            "tools/plan005_supply_chain.py manifest",
            "tools/plan005_supply_chain.py verify",
            "--require-removal",
            "--require-exact",
        ):
            self.assertIn(required, release)
        for exact_argument in (
            "--source-timestamp",
            "--scan-timestamp",
            "--artifact-name",
            "--github-repository",
            "--workflow-ref",
            "--run-id",
            "--run-attempt",
            "--runner-os",
            "--runner-arch",
            "--runner-name",
            "--image-os",
            "--image-version",
            "--cargo-target-dir",
        ):
            self.assertIn(exact_argument, release)
        commands = [
            "python3 tools/plan005_supply_chain.py build",
            "python3 tools/plan005_removal_drill.py",
            "python3 tools/plan005_supply_chain.py manifest",
            "python3 tools/plan005_supply_chain.py verify",
        ]
        positions = [release.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("plan-005-inputs/", release)
        self.assertNotIn("--advisory-db", release)
        self.assertNotIn("--spdx-license-list", release)

    def test_three_platform_artifacts_release_bundle_and_four_attestations_are_closed(self):
        conformance = self.job("conformance")
        release = self.job("release-evidence")
        attestation = self.job("attest-evidence")
        self.assertIn("plan-005-${{ matrix.platform }}-${{ github.sha }}", conformance)
        self.assertIn("plan-005-release-${{ github.sha }}", release)
        matrix = attestation[
            attestation.index("      matrix:\n") : attestation.index("\n\n    steps:")
        ]
        self.assertEqual(re.findall(r"(?m)^        ([a-z0-9_-]+):", matrix), ["include"])
        self.assertEqual(len(re.findall(r"(?m)^          - ", matrix)), 4)
        self.assertNotIn("exclude:", matrix)
        entries = re.findall(
            r"(?m)^\s{10}- label: (\S+)\n\s{12}artifact_prefix: (\S+)$",
            attestation,
        )
        self.assertEqual(
            entries,
            [
                ("linux-x86_64", "plan-005-linux-x86_64"),
                ("macos-arm64", "plan-005-macos-arm64"),
                ("windows-x64", "plan-005-windows-x64"),
                ("release-bundle", "plan-005-release"),
            ],
        )
        self.assertEqual(attestation.count("uses: actions/attest@"), 1)
        self.assertEqual(
            re.findall(r"(?m)^    if: (.+)$", attestation),
            ["github.event_name == 'push' || github.event_name == 'workflow_dispatch'"],
        )
        self.assertNotRegex(
            self.step(attestation, "Attest exact uploaded PLAN-005 artifact digest"),
            r"(?m)^        if\s*:",
        )
        for required in (
            "actions: read",
            "contents: read",
            "id-token: write",
            "attestations: write",
            "artifact-metadata: write",
            "actions/runs/$runId/artifacts?name=$encodedName",
            "artifact.workflow_run.head_sha",
            "subject-name: ${{ matrix.artifact_prefix }}-${{ github.sha }}",
            "subject-digest: ${{ steps.resolve-artifact.outputs.artifact_digest }}",
            "artifact_created_at",
            "artifact_expires_at",
            "attestation-id",
            "attestation-url",
        ):
            self.assertIn(required, attestation)
        self.assertIn("claim_status=pending-evidence", conformance)
        self.assertIn("claim_status=pending-evidence", release)
        self.assertIn("physical_m4_performance=false", conformance)
        self.assertIn("power_loss_evidence=false", conformance)
        self.assertIn("tier_1=false", conformance)


if __name__ == "__main__":
    unittest.main()
