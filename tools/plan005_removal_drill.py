#!/usr/bin/env python3
"""Prove PLAN-005 source removal in an isolated, fail-closed Git worktree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple


BASELINE_COMMIT = "6f8dfdd5194792e8592cd10ebaaf8828833effbe"
BASELINE_TREE = "d1f51cc3ba5d0e42ade27fb9aefda01750093971"
BASELINE_LEAF_COUNT = 495
BASELINE_FULL_INVENTORY_SHA256 = (
    "3495ead55ab40e469940c5a6a585064d75137eaba9af9b5adeaf51b553fba7b9"
)
BASELINE_PATH_INVENTORY_SHA256 = (
    "0a7a3e4cda89f78a7ccda8184c9c78f7bc52073b92003d7db669e4817ac0ec11"
)
EXCLUSION_LIST_SHA256 = (
    "cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530"
)
PROTECTED_MANIFEST_SHA256 = (
    "66569b2d563beca2d4d35c6fb15e456d8d190d7341e20790e92af109006776e0"
)
MANIFEST_SCHEMA = "helixos.plan-005-removal-protected-files/1"
REPORT_SCHEMA = "helixos.plan-005-removal-drill/1"
DEFAULT_MANIFEST = "specs/005-durable-dispatch/evidence/removal-protected-files.json"
DEFAULT_OUTPUT = "plan-005-release-evidence/removal"
EXPECTED_PACKAGES = {
    "helix-contracts",
    "helix-coordinator-sqlite",
    "helix-plan-eligibility",
    "helix-plan-preparation",
    "helix-replay-sqlite",
    "helixos-kernel",
    "helixos-mcp-shim",
    "helixos-provision",
}
EXPECTED_NONCLAIMS = [
    "software source removal only; not secure erasure",
    "isolated subsystem copy only; not production-state or full-machine decommission",
    "retained audit artifacts grant no live dispatch, restoration, or execution authority",
    "no physical power-loss, production supervisor/provider, physical M4, or Tier 1 claim",
]
ENVIRONMENT_ALLOWLIST = {
    "APPDATA",
    "AR",
    "CARGO_HOME",
    "CC",
    "CI",
    "COMSPEC",
    "CXX",
    "DEVELOPER_DIR",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LD_LIBRARY_PATH",
    "LOGNAME",
    "LOCALAPPDATA",
    "MACOSX_DEPLOYMENT_TARGET",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SDKROOT",
    "SHELL",
    "SystemRoot",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "WINDIR",
}
FILESYSTEM_EXECUTABLE_MODE_RELIABLE = os.name != "nt"
PATH_ENVIRONMENT_KEYS = {
    "APPDATA",
    "AR",
    "CARGO_HOME",
    "CC",
    "CXX",
    "DEVELOPER_DIR",
    "HOME",
    "LOCALAPPDATA",
    "RUSTUP_HOME",
    "SDKROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
}


class EvidenceError(RuntimeError):
    """Raised when the removal proof cannot be established."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _clean_environment(source: Mapping[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in source.items()
        if key in ENVIRONMENT_ALLOWLIST or key.startswith("LC_")
    }


def _run_git_bytes(repository: Path, argv: Sequence[str]) -> bytes:
    completed = subprocess.run(
        ["git", *argv],
        cwd=str(repository),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError("git {} failed: {}".format(" ".join(argv), message))
    return completed.stdout


def _run_git_text(repository: Path, argv: Sequence[str]) -> str:
    return _run_git_bytes(repository, argv).decode("utf-8").strip()


def _validate_relative_path(raw: object, label: str = "path") -> str:
    if not isinstance(raw, str) or not raw:
        raise EvidenceError("{} must be a non-empty UTF-8 string".format(label))
    if "\\" in raw or "\x00" in raw:
        raise EvidenceError("{} is not a normalized POSIX path: {}".format(label, raw))
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise EvidenceError("{} is unsafe: {}".format(label, raw))
    if pure.as_posix() != raw:
        raise EvidenceError("{} is not normalized: {}".format(label, raw))
    return raw


def _validate_string_list(
    value: object, label: str, *, prefixes: bool = False
) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise EvidenceError("{} must be a string list".format(label))
    result = []
    for item in value:
        candidate = item[:-1] if prefixes and item.endswith("/") else item
        _validate_relative_path(candidate, label)
        if prefixes and not item.endswith("/"):
            raise EvidenceError("{} entries must end with '/': {}".format(label, item))
        result.append(item)
    if result != sorted(result, key=lambda item: item.encode("utf-8")):
        raise EvidenceError("{} must be bytewise sorted".format(label))
    if len(result) != len(set(result)):
        raise EvidenceError("{} contains duplicate entries".format(label))
    return result


def _parse_ls_tree(raw: bytes) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_raw = record.split(b"\t", 1)
            mode_raw, type_raw, oid_raw = metadata.split(b" ", 2)
            path = path_raw.decode("utf-8")
            mode = mode_raw.decode("ascii")
            object_type = type_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            raise EvidenceError("Git tree inventory is malformed: {}".format(error))
        _validate_relative_path(path, "Git tree path")
        if path in result:
            raise EvidenceError("Git tree contains duplicate path: {}".format(path))
        result[path] = {"mode": mode, "type": object_type, "git_blob_oid": oid}
    return result


def _git_blob(repository: Path, oid: str) -> bytes:
    return _run_git_bytes(repository, ["cat-file", "blob", oid])


def _entry_stream(entries: Sequence[dict]) -> bytes:
    return b"".join(
        (
            "{} {} {}\t{}".format(
                entry["mode"],
                entry["type"],
                entry["git_blob_oid"],
                entry["path"],
            ).encode("utf-8")
            + b"\0"
        )
        for entry in entries
    )


def _path_stream(entries: Sequence[dict]) -> bytes:
    return b"".join(entry["path"].encode("utf-8") + b"\0" for entry in entries)


def load_and_validate_manifest(
    repository: Path, manifest_path: Path, baseline_argument: str
) -> dict:
    if baseline_argument != BASELINE_COMMIT:
        raise EvidenceError("--baseline does not match the frozen PLAN-005 baseline")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise EvidenceError("protected manifest must be a regular non-symlink file")
    if sha256_file(manifest_path) != PROTECTED_MANIFEST_SHA256:
        raise EvidenceError("protected manifest file digest mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("protected manifest is unreadable: {}".format(error))
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise EvidenceError("protected manifest schema mismatch")
    if manifest.get("acceptance_id") != "PLAN-005":
        raise EvidenceError("protected manifest acceptance identity mismatch")

    baseline = manifest.get("baseline")
    expected_baseline = {
        "commit": BASELINE_COMMIT,
        "tree": BASELINE_TREE,
        "leaf_blob_count": BASELINE_LEAF_COUNT,
        "full_inventory_sha256": BASELINE_FULL_INVENTORY_SHA256,
        "path_inventory_sha256": BASELINE_PATH_INVENTORY_SHA256,
        "mode_counts": {"100644": 490, "100755": 5},
    }
    if not isinstance(baseline, dict):
        raise EvidenceError("protected manifest baseline section is absent")
    for key, expected in expected_baseline.items():
        if baseline.get(key) != expected:
            raise EvidenceError("protected manifest baseline {} mismatch".format(key))

    resolved_commit = _run_git_text(
        repository, ["rev-parse", "{}^{{commit}}".format(BASELINE_COMMIT)]
    )
    resolved_tree = _run_git_text(
        repository, ["rev-parse", "{}^{{tree}}".format(BASELINE_COMMIT)]
    )
    if resolved_commit != BASELINE_COMMIT or resolved_tree != BASELINE_TREE:
        raise EvidenceError("frozen baseline Git object identity mismatch")

    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != BASELINE_LEAF_COUNT:
        raise EvidenceError("protected manifest must contain exactly 495 entries")
    expected_entry_keys = {
        "path",
        "mode",
        "type",
        "git_blob_oid",
        "content_sha256",
    }
    paths: List[str] = []
    mode_counts = {"100644": 0, "100755": 0}
    oid_pattern = re.compile(r"^[0-9a-f]{40}$")
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise EvidenceError("protected entry {} has an invalid shape".format(index))
        path = _validate_relative_path(entry.get("path"), "protected entry path")
        mode = entry.get("mode")
        if mode not in mode_counts:
            raise EvidenceError("protected entry has unsupported mode: {}".format(path))
        if entry.get("type") != "blob":
            raise EvidenceError("protected entry is not a blob: {}".format(path))
        if not isinstance(entry.get("git_blob_oid"), str) or not oid_pattern.fullmatch(
            entry["git_blob_oid"]
        ):
            raise EvidenceError("protected entry has invalid blob OID: {}".format(path))
        if not isinstance(entry.get("content_sha256"), str) or not digest_pattern.fullmatch(
            entry["content_sha256"]
        ):
            raise EvidenceError("protected entry has invalid content digest: {}".format(path))
        paths.append(path)
        mode_counts[mode] += 1
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        raise EvidenceError("protected entries are not bytewise sorted")
    if len(paths) != len(set(paths)):
        raise EvidenceError("protected entries contain duplicate paths")
    if mode_counts != expected_baseline["mode_counts"]:
        raise EvidenceError("protected entry mode cardinality mismatch")

    entry_stream = _entry_stream(entries)
    path_stream = _path_stream(entries)
    if sha256_bytes(entry_stream) != BASELINE_FULL_INVENTORY_SHA256:
        raise EvidenceError("protected full inventory digest mismatch")
    if sha256_bytes(path_stream) != BASELINE_PATH_INVENTORY_SHA256:
        raise EvidenceError("protected path inventory digest mismatch")
    git_inventory = _run_git_bytes(
        repository, ["ls-tree", "-r", "-z", "--full-tree", BASELINE_COMMIT]
    )
    if git_inventory != entry_stream:
        raise EvidenceError("protected manifest differs from the frozen Git tree")
    for entry in entries:
        if sha256_bytes(_git_blob(repository, entry["git_blob_oid"])) != entry[
            "content_sha256"
        ]:
            raise EvidenceError(
                "protected blob content digest mismatch: {}".format(entry["path"])
            )

    policy = manifest.get("removal_policy")
    if not isinstance(policy, dict):
        raise EvidenceError("protected manifest removal policy is absent")
    restored = _validate_string_list(
        policy.get("baseline_paths_restored"),
        "removal_policy.baseline_paths_restored",
    )
    removed_exact = _validate_string_list(
        policy.get("added_paths_removed"), "removal_policy.added_paths_removed"
    )
    removed_prefixes = _validate_string_list(
        policy.get("added_prefixes_removed"),
        "removal_policy.added_prefixes_removed",
        prefixes=True,
    )
    retained_exact = _validate_string_list(
        policy.get("added_paths_retained_for_audit"),
        "removal_policy.added_paths_retained_for_audit",
    )
    retained_prefixes = _validate_string_list(
        policy.get("added_prefixes_retained_for_audit"),
        "removal_policy.added_prefixes_retained_for_audit",
        prefixes=True,
    )
    baseline_paths = set(paths)
    if not set(restored).issubset(baseline_paths):
        raise EvidenceError("restoration allowlist contains a path absent from baseline")
    if baseline_paths.intersection(removed_exact + retained_exact):
        raise EvidenceError("added-path policy contains an existing baseline path")
    for path in removed_exact + retained_exact:
        matches = _class_matches(
            path,
            removed_exact,
            removed_prefixes,
            retained_exact,
            retained_prefixes,
        )
        if len(matches) != 1:
            raise EvidenceError("added-path policy overlaps for {}".format(path))
    for removed in removed_prefixes:
        for retained in retained_prefixes:
            if removed.startswith(retained) or retained.startswith(removed):
                raise EvidenceError("removed and retained prefixes overlap")

    exclusions = manifest.get("working_tree_exclusions")
    if not isinstance(exclusions, dict):
        raise EvidenceError("working-tree exclusions are absent")
    excluded_paths = _validate_string_list(
        exclusions.get("paths"), "working_tree_exclusions.paths"
    )
    exclusion_stream = "".join(path + "\n" for path in excluded_paths).encode("utf-8")
    if exclusions.get("count") != 27 or len(excluded_paths) != 27:
        raise EvidenceError("working-tree exclusion count mismatch")
    if (
        exclusions.get("sorted_newline_sha256") != EXCLUSION_LIST_SHA256
        or sha256_bytes(exclusion_stream) != EXCLUSION_LIST_SHA256
    ):
        raise EvidenceError("working-tree exclusion digest mismatch")
    if not set(excluded_paths).issubset(baseline_paths):
        raise EvidenceError("working-tree exclusion is absent from baseline")
    if set(excluded_paths).intersection(restored):
        raise EvidenceError("working-tree exclusions overlap restoration paths")
    expected_package_list = sorted(EXPECTED_PACKAGES)
    if manifest.get("expected_post_removal_workspace_packages") != expected_package_list:
        raise EvidenceError("expected post-removal package set mismatch")
    if manifest.get("nonclaims") != EXPECTED_NONCLAIMS:
        raise EvidenceError("protected removal nonclaims mismatch")
    return manifest


def _class_matches(
    path: str,
    removed_exact: Sequence[str],
    removed_prefixes: Sequence[str],
    retained_exact: Sequence[str],
    retained_prefixes: Sequence[str],
) -> List[str]:
    matches: List[str] = []
    if path in removed_exact or any(path.startswith(prefix) for prefix in removed_prefixes):
        matches.append("remove")
    if path in retained_exact or any(path.startswith(prefix) for prefix in retained_prefixes):
        matches.append("retain-audit")
    return matches


def _git_blob_oid(content: bytes) -> str:
    header = "blob {}\0".format(len(content)).encode("ascii")
    serialized = header + content
    try:
        digest = hashlib.sha1(serialized, usedforsecurity=False)
    except TypeError:  # Python 3.8 compatibility; this is Git identity, not cryptography.
        digest = hashlib.sha1(serialized)
    return digest.hexdigest()


def _filesystem_record(path: Path) -> dict:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise EvidenceError("source path disappeared while snapshotting: {}".format(path))
    if stat.S_ISLNK(metadata.st_mode):
        raise EvidenceError("source snapshot refuses symlink: {}".format(path))
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError("source snapshot requires regular file: {}".format(path))
    content = path.read_bytes()
    return {
        "mode": "100755" if metadata.st_mode & stat.S_IXUSR else "100644",
        "type": "blob",
        "git_blob_oid": _git_blob_oid(content),
        "content_sha256": sha256_bytes(content),
    }


def _parse_name_status(raw: bytes) -> List[Tuple[str, str]]:
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2:
        raise EvidenceError("working-tree name-status stream is malformed")
    result = []
    for offset in range(0, len(tokens), 2):
        try:
            status_code = tokens[offset].decode("ascii")
            path = tokens[offset + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError("working-tree status is not UTF-8: {}".format(error))
        if status_code not in {"A", "D", "M"}:
            raise EvidenceError(
                "working-tree status is unsupported "
                "(renames/types/conflicts fail closed): {} {}".format(status_code, path)
            )
        result.append(
            (status_code, _validate_relative_path(path, "working-tree path"))
        )
    return result


def _untracked_paths(repository: Path) -> List[str]:
    raw = _run_git_bytes(
        repository, ["ls-files", "--others", "--exclude-standard", "-z", "--"]
    )
    result = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            path = item.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError("untracked path is not UTF-8: {}".format(error))
        result.append(_validate_relative_path(path, "untracked path"))
    if result != sorted(result, key=lambda item: item.encode("utf-8")):
        raise EvidenceError("untracked path inventory is not bytewise sorted")
    return result


def _source_tree(repository: Path, commit: str) -> Dict[str, dict]:
    raw = _run_git_bytes(
        repository, ["ls-tree", "-r", "-z", "--full-tree", commit]
    )
    entries = _parse_ls_tree(raw)
    for path, entry in entries.items():
        if entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}:
            raise EvidenceError(
                "source tree contains a non-regular leaf "
                "(symlinks/submodules are refused): {}".format(path)
            )
    return entries


def _working_source_snapshot(
    repository: Path,
    head_commit: str,
    excluded_paths: Set[str],
) -> Tuple[Dict[str, dict], List[Tuple[str, str]], List[str], List[str]]:
    entries = _source_tree(repository, head_commit)
    changes = _parse_name_status(
        _run_git_bytes(
            repository,
            ["diff", "--name-status", "-z", "--no-renames", "HEAD", "--"],
        )
    )
    ignored_exclusions: List[str] = []
    overlays: List[Tuple[str, str]] = []
    for status_code, path in changes:
        if path in excluded_paths:
            if status_code != "M":
                raise EvidenceError(
                    "working-tree exclusion may only be an unstaged/aggregate "
                    "modification: {}".format(path)
                )
            ignored_exclusions.append(path)
            continue
        overlays.append((status_code, path))
        if status_code == "D":
            entries.pop(path, None)
        else:
            entries[path] = _filesystem_record(repository / path)

    untracked = _untracked_paths(repository)
    for path in untracked:
        if path in entries:
            raise EvidenceError(
                "untracked source path collides with tracked inventory: {}".format(path)
            )
        entries[path] = _filesystem_record(repository / path)
        overlays.append(("A", path))
    overlays.sort(key=lambda item: item[1].encode("utf-8"))
    ignored_exclusions.sort(key=lambda item: item.encode("utf-8"))
    return entries, overlays, ignored_exclusions, untracked


def _classify_source_delta(
    manifest: dict,
    baseline_entries: Mapping[str, dict],
    source_entries: Mapping[str, dict],
) -> dict:
    policy = manifest["removal_policy"]
    restored_allowlist = set(policy["baseline_paths_restored"])
    removed_exact = policy["added_paths_removed"]
    removed_prefixes = policy["added_prefixes_removed"]
    retained_exact = policy["added_paths_retained_for_audit"]
    retained_prefixes = policy["added_prefixes_retained_for_audit"]
    restored: List[str] = []
    removed: List[str] = []
    retained: List[str] = []

    for path, baseline_entry in baseline_entries.items():
        source_entry = source_entries.get(path)
        comparable = None
        if source_entry is not None:
            comparable = {
                "mode": source_entry["mode"],
                "type": source_entry["type"],
                "git_blob_oid": source_entry["git_blob_oid"],
            }
        expected = {
            "mode": baseline_entry["mode"],
            "type": baseline_entry["type"],
            "git_blob_oid": baseline_entry["git_blob_oid"],
        }
        if comparable != expected:
            if path not in restored_allowlist:
                raise EvidenceError(
                    "baseline path changed outside the restoration allowlist: {}".format(path)
                )
            restored.append(path)

    for path in source_entries:
        if path in baseline_entries:
            continue
        entry = source_entries[path]
        if entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}:
            raise EvidenceError("added source path is not a regular file: {}".format(path))
        matches = _class_matches(
            path,
            removed_exact,
            removed_prefixes,
            retained_exact,
            retained_prefixes,
        )
        if len(matches) != 1:
            raise EvidenceError(
                "added source path must match exactly one removal-policy class: {}".format(
                    path
                )
            )
        if path.startswith("graphify-out/memory/") and not re.search(
            r"(?:plan_005|durable_dispatch|helix_plan_dispatch|t0[0-9]{2})",
            PurePosixPath(path).name,
        ):
            raise EvidenceError(
                "Graphify removal path lacks a PLAN-005 task/feature identity: {}".format(
                    path
                )
            )
        if path.startswith("specs/005-durable-dispatch/"):
            if entry["mode"] != "100644" or PurePosixPath(path).suffix not in {
                ".json",
                ".md",
                ".sql",
            }:
                raise EvidenceError(
                    "retained PLAN-005 specification/evidence path is executable or "
                    "has an unsupported type: {}".format(path)
                )
        if matches[0] == "remove":
            removed.append(path)
        else:
            retained.append(path)

    for values in (restored, removed, retained):
        values.sort(key=lambda item: item.encode("utf-8"))
    if not restored or not removed:
        raise EvidenceError(
            "source does not contain both a baseline integration delta and "
            "removable PLAN-005 surfaces"
        )
    return {
        "restored_baseline_paths": restored,
        "removed_added_paths": removed,
        "retained_audit_paths": retained,
    }


def _delta_digest(source_entries: Mapping[str, dict], actions: dict) -> str:
    records = []
    for action_key in (
        "restored_baseline_paths",
        "removed_added_paths",
        "retained_audit_paths",
    ):
        for path in actions[action_key]:
            entry = source_entries.get(path)
            records.append(
                {
                    "action": action_key,
                    "path": path,
                    "mode": entry.get("mode") if entry else "absent",
                    "git_blob_oid": entry.get("git_blob_oid") if entry else "absent",
                }
            )
    serialized = json.dumps(
        records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return sha256_bytes((serialized + "\n").encode("utf-8"))


def _safe_target(root: Path, relative: str) -> Path:
    _validate_relative_path(relative)
    target = root.joinpath(*PurePosixPath(relative).parts)
    try:
        target.relative_to(root)
    except ValueError:
        raise EvidenceError("path escapes isolated worktree: {}".format(relative))
    cursor = root
    for part in PurePosixPath(relative).parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EvidenceError("isolated worktree parent is a symlink: {}".format(relative))
    return target


def _copy_overlay(source_root: Path, worktree: Path, status_code: str, relative: str) -> None:
    target = _safe_target(worktree, relative)
    if status_code == "D":
        if target.is_symlink():
            raise EvidenceError("refusing to remove symlink from isolated overlay")
        if target.exists():
            if not target.is_file():
                raise EvidenceError("isolated overlay deletion target is not a file")
            target.unlink()
        return
    source = source_root / relative
    record = _filesystem_record(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise EvidenceError("isolated overlay target is not a regular file: {}".format(relative))
    shutil.copyfile(str(source), str(target), follow_symlinks=False)
    target.chmod(0o755 if record["mode"] == "100755" else 0o644)


def _walk_regular_files(root: Path) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git":
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError("isolated source contains symlink: {}".format(relative))
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("isolated source contains non-regular file: {}".format(relative))
        result[relative] = _filesystem_record(path)
    return result


def _assert_filesystem_inventory(
    root: Path, expected: Mapping[str, dict], label: str
) -> Dict[str, dict]:
    observed = _walk_regular_files(root)
    if set(observed) != set(expected):
        missing = sorted(set(expected) - set(observed))
        unexpected = sorted(set(observed) - set(expected))
        raise EvidenceError(
            "{} file set mismatch; missing={}, unexpected={}".format(
                label, missing[:5], unexpected[:5]
            )
        )
    for path, expected_entry in expected.items():
        observed_entry = observed[path]
        compared_keys = ["type", "git_blob_oid"]
        if FILESYSTEM_EXECUTABLE_MODE_RELIABLE:
            compared_keys.insert(0, "mode")
        for key in compared_keys:
            if observed_entry[key] != expected_entry[key]:
                raise EvidenceError("{} differs at {} ({})".format(label, path, key))
        expected_sha = expected_entry.get("content_sha256")
        if expected_sha and observed_entry["content_sha256"] != expected_sha:
            raise EvidenceError("{} content digest differs at {}".format(label, path))
    return observed


def _protected_snapshot(root: Path, manifest: dict) -> dict:
    snapshot = {}
    for entry in manifest["entries"]:
        path = entry["path"]
        target = _safe_target(root, path)
        if not target.exists():
            snapshot[path] = {
                "expected_mode": entry["mode"],
                "expected_sha256": entry["content_sha256"],
                "observed": "absent",
            }
            continue
        observed = _filesystem_record(target)
        mode_matches = (
            observed["mode"] == entry["mode"]
            if FILESYSTEM_EXECUTABLE_MODE_RELIABLE
            else True
        )
        snapshot[path] = {
            "expected_mode": entry["mode"],
            "expected_sha256": entry["content_sha256"],
            "observed_mode": observed["mode"],
            "observed_sha256": observed["content_sha256"],
            "mode_verification": (
                "filesystem-and-git-index"
                if FILESYSTEM_EXECUTABLE_MODE_RELIABLE
                else "git-index"
            ),
            "matches_baseline": mode_matches
            and observed["content_sha256"] == entry["content_sha256"],
        }
    return snapshot


def _materialize_git_tree(
    repository: Path, worktree: Path, entries: Mapping[str, dict]
) -> None:
    """Write tracked blobs directly, avoiding checkout filters and EOL conversion."""
    for path in sorted(entries, key=lambda item: item.encode("utf-8")):
        entry = entries[path]
        target = _safe_target(worktree, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise EvidenceError("source materialization target is unsafe: {}".format(path))
        content = _git_blob(repository, entry["git_blob_oid"])
        if _git_blob_oid(content) != entry["git_blob_oid"]:
            raise EvidenceError("source Git blob identity changed: {}".format(path))
        target.write_bytes(content)
        target.chmod(0o755 if entry["mode"] == "100755" else 0o644)


def _restore_baseline_path(repository: Path, worktree: Path, entry: dict) -> None:
    target = _safe_target(worktree, entry["path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise EvidenceError("baseline restoration target is unsafe: {}".format(entry["path"]))
    content = _git_blob(repository, entry["git_blob_oid"])
    if sha256_bytes(content) != entry["content_sha256"]:
        raise EvidenceError("baseline blob changed during restoration")
    target.write_bytes(content)
    target.chmod(0o755 if entry["mode"] == "100755" else 0o644)


def _delete_added_path(worktree: Path, relative: str) -> None:
    target = _safe_target(worktree, relative)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise EvidenceError("removal target is not a regular added file: {}".format(relative))
    if not target.exists():
        raise EvidenceError("required PLAN-005 removal target is absent: {}".format(relative))
    target.unlink()
    parent = target.parent
    while parent != worktree:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent


def redact_output(
    text: str,
    repository: Path,
    worktree: Path,
    output: Path,
    cargo_target: Optional[Path] = None,
) -> str:
    replacements = [
        (str(worktree), "<removal-root>"),
        (str(repository), "<repo>"),
        (str(output), "<evidence-output>"),
        (str(Path.home()), "<home>"),
    ]
    if cargo_target is not None:
        replacements.append((str(cargo_target), "<cargo-target>"))
    for key in PATH_ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value and (os.path.isabs(value) or re.match(r"^[A-Za-z]:[\\/]", value)):
            replacements.append((value, "<env-path:{}>".format(key.lower())))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    result = text.replace("\r\n", "\n")
    for raw, replacement in replacements:
        if not raw:
            continue
        result = result.replace(raw, replacement)
        result = result.replace(raw.replace("/", "\\"), replacement)
    return result


def _redact_failure_message(message: str, args: argparse.Namespace) -> str:
    repository = Path(args.repository).resolve()
    candidates = [
        (str(repository), "<repo>"),
        (str(Path.home()), "<home>"),
    ]
    for raw in (args.output, args.manifest, args.cargo_target_dir):
        if not raw:
            continue
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = repository / candidate
        candidates.append((str(candidate.resolve()), "<configured-path>"))
    result = message
    for raw, replacement in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
        result = result.replace(raw, replacement)
        result = result.replace(raw.replace("/", "\\"), replacement)
    result = re.sub(
        r"(?:[A-Za-z]:)?[^\s]*helixos-plan005-removal-[^\s/\\]*(?:[/\\]source)?",
        "<removal-root>",
        result,
    )
    return result


def _run_evidence_command(
    name: str,
    argv: Sequence[str],
    cwd: Path,
    output: Path,
    repository: Path,
    worktree: Path,
    environment: Mapping[str, str],
    cargo_target: Path,
) -> dict:
    started = time.monotonic()
    completed = subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=dict(environment),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    redacted = redact_output(
        completed.stdout, repository, worktree, output, cargo_target
    )
    log = output / "logs" / "{}.txt".format(name)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(redacted.rstrip("\n") + "\n", encoding="utf-8")
    if completed.returncode != 0:
        raise EvidenceError(
            "removal drill command failed: {} "
            "(see <evidence-output>/logs/{}.txt)".format(name, name)
        )
    return {
        "name": name,
        "argv": list(argv),
        "exit_code": completed.returncode,
        "duration_ms": duration_ms,
        "log": "logs/{}.txt".format(name),
        "log_sha256": sha256_file(log),
    }


def _metadata_packages(raw: str) -> Set[str]:
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError("cargo metadata output is invalid: {}".format(error))
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise EvidenceError("cargo metadata output lacks packages")
    result: Set[str] = set()
    for item in packages:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise EvidenceError("cargo metadata package identity is incomplete")
        result.add(item["name"])
    return result


def _normalized_metadata(raw: str) -> dict:
    metadata = json.loads(raw)
    normalized = []
    for package in metadata["packages"]:
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise EvidenceError("cargo metadata package identity is incomplete")
        normalized.append(
            {
                "name": name,
                "version": version,
                "source": package.get("source") or "workspace-path",
            }
        )
    normalized.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    return {
        "schema": "helixos.plan-005-removal-metadata/1",
        "workspace_package_count": len(normalized),
        "workspace_packages": normalized,
        "workspace_root": "<removal-root>/kernel",
        "target_directory": "<cargo-target>",
    }


def _validate_output_location(repository: Path, output: Path) -> None:
    if output.is_symlink():
        raise EvidenceError("removal output directory must not be a symlink")
    try:
        repository.relative_to(output)
    except ValueError:
        pass
    else:
        raise EvidenceError("removal output cannot contain the source repository")
    if output == repository:
        raise EvidenceError("removal output cannot be the source repository")
    try:
        output.relative_to(repository)
    except ValueError:
        pass
    else:
        allowed_root = (repository / DEFAULT_OUTPUT).resolve()
        try:
            output.relative_to(allowed_root)
        except ValueError:
            raise EvidenceError(
                "output inside the repository is allowed only below {}".format(
                    DEFAULT_OUTPUT
                )
            )
    if output.exists():
        if not output.is_dir():
            raise EvidenceError("removal output must be a directory")
        if any(output.iterdir()):
            raise EvidenceError("removal output directory must be absent or empty")


def _paths_overlap(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        first.relative_to(second)
        return True
    except ValueError:
        pass
    try:
        second.relative_to(first)
        return True
    except ValueError:
        return False


def _validate_cargo_target(
    target: Path, repository: Path, worktree: Path, output: Path
) -> None:
    if target.is_symlink() or target.exists():
        raise EvidenceError("cargo target must be a fresh absent non-symlink path")
    for protected_root, label in (
        (repository, "source repository"),
        (worktree, "isolated source"),
        (output, "evidence output"),
    ):
        if _paths_overlap(target, protected_root):
            raise EvidenceError("cargo target overlaps {}".format(label))


def _verify_exact_commit_tooling(
    repository: Path,
    source_commit: str,
    head_commit: str,
    manifest_path: Path,
) -> str:
    if source_commit != head_commit:
        raise EvidenceError("exact-commit evidence requires --source-commit to equal HEAD")
    expected_manifest = (repository / DEFAULT_MANIFEST).resolve()
    expected_driver = (repository / "tools/plan005_removal_drill.py").resolve()
    if manifest_path != expected_manifest:
        raise EvidenceError("exact-commit evidence requires the repository manifest path")
    if Path(__file__).resolve() != expected_driver:
        raise EvidenceError("exact-commit evidence requires the repository driver path")
    for relative, local_path in (
        (DEFAULT_MANIFEST, expected_manifest),
        ("tools/plan005_removal_drill.py", expected_driver),
    ):
        try:
            oid = _run_git_text(
                repository, ["rev-parse", "{}:{}".format(source_commit, relative)]
            )
        except EvidenceError:
            raise EvidenceError(
                "exact source commit does not contain required evidence tool: {}".format(
                    relative
                )
            )
        if sha256_bytes(_git_blob(repository, oid)) != sha256_file(local_path):
            raise EvidenceError(
                "local evidence tooling differs from exact source commit: {}".format(
                    relative
                )
            )
    return sha256_file(expected_driver)


def _assert_ancestor(repository: Path, baseline: str, source_commit: str) -> None:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", baseline, source_commit],
        cwd=str(repository),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise EvidenceError("frozen baseline is not an ancestor of removal source")


def _status_snapshot(repository: Path) -> bytes:
    return _run_git_bytes(
        repository,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )


def execute_drill(args: argparse.Namespace) -> dict:
    repository = Path(args.repository).resolve()
    if not repository.is_dir():
        raise EvidenceError("repository is not a directory")
    top_level = Path(_run_git_text(repository, ["rev-parse", "--show-toplevel"])).resolve()
    if top_level != repository:
        raise EvidenceError("--repository must name the Git top-level directory")

    manifest_candidate = Path(args.manifest)
    if not manifest_candidate.is_absolute():
        manifest_candidate = repository / manifest_candidate
    if manifest_candidate.is_symlink():
        raise EvidenceError("protected manifest path must not be a symlink")
    manifest_path = manifest_candidate.resolve()
    manifest = load_and_validate_manifest(repository, manifest_path, args.baseline)
    manifest_sha256 = sha256_file(manifest_path)
    if args.validate_manifest_only:
        result = {
            "schema": MANIFEST_SCHEMA,
            "result": "valid-frozen-baseline-manifest",
            "baseline_commit": BASELINE_COMMIT,
            "baseline_tree": BASELINE_TREE,
            "protected_file_count": BASELINE_LEAF_COUNT,
            "manifest_sha256": manifest_sha256,
        }
        print(json.dumps(result, sort_keys=True))
        return result

    output_candidate = Path(args.output)
    if not output_candidate.is_absolute():
        output_candidate = repository / output_candidate
    if output_candidate.is_symlink():
        raise EvidenceError("removal output path must not be a symlink")
    output = output_candidate.resolve()
    _validate_output_location(repository, output)

    status_before = _status_snapshot(repository)
    head_commit = _run_git_text(repository, ["rev-parse", "HEAD^{commit}"])
    baseline_entries = {entry["path"]: dict(entry) for entry in manifest["entries"]}
    excluded_paths = set(manifest["working_tree_exclusions"]["paths"])
    overlays: List[Tuple[str, str]] = []
    ignored_exclusions: List[str] = []
    if args.source_commit:
        source_commit = _run_git_text(
            repository, ["rev-parse", "{}^{{commit}}".format(args.source_commit)]
        )
        source_mode = "exact-commit"
        driver_sha256 = _verify_exact_commit_tooling(
            repository, source_commit, head_commit, manifest_path
        )
        source_entries = _source_tree(repository, source_commit)
    else:
        source_commit = head_commit
        source_mode = "diagnostic-working-tree-snapshot"
        driver_sha256 = sha256_file(Path(__file__).resolve())
        (
            source_entries,
            overlays,
            ignored_exclusions,
            _untracked,
        ) = _working_source_snapshot(repository, head_commit, excluded_paths)
    _assert_ancestor(repository, BASELINE_COMMIT, source_commit)
    actions = _classify_source_delta(manifest, baseline_entries, source_entries)
    source_delta_sha256 = _delta_digest(source_entries, actions)

    output.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="helixos-plan005-removal-"))
    worktree = temporary / "source"
    worktree_added = False
    worktree_admin: Optional[Path] = None
    common_git_dir_raw = Path(
        _run_git_text(repository, ["rev-parse", "--git-common-dir"])
    )
    common_git_dir = (
        common_git_dir_raw
        if common_git_dir_raw.is_absolute()
        else repository / common_git_dir_raw
    ).resolve()
    commands: List[dict] = []
    try:
        _run_git_text(
            repository,
            [
                "worktree",
                "add",
                "--detach",
                "--force",
                "--no-checkout",
                str(worktree),
                source_commit,
            ],
        )
        worktree_added = True
        worktree_admin_raw = Path(_run_git_text(worktree, ["rev-parse", "--git-dir"]))
        worktree_admin = (
            worktree_admin_raw
            if worktree_admin_raw.is_absolute()
            else worktree / worktree_admin_raw
        ).resolve()
        if (
            worktree_admin.parent != (common_git_dir / "worktrees").resolve()
            or worktree_admin.is_symlink()
            or not worktree_admin.is_dir()
        ):
            raise EvidenceError("isolated worktree administrative path is outside Git")
        source_commit_tree = _run_git_text(
            repository, ["rev-parse", "{}^{{tree}}".format(source_commit)]
        )
        _run_git_text(worktree, ["read-tree", source_commit])
        if _run_git_text(worktree, ["write-tree"]) != source_commit_tree:
            raise EvidenceError("isolated source index differs from source commit tree")
        _materialize_git_tree(repository, worktree, _source_tree(repository, source_commit))
        if source_mode == "diagnostic-working-tree-snapshot":
            for status_code, path in overlays:
                _copy_overlay(repository, worktree, status_code, path)
        _assert_filesystem_inventory(worktree, source_entries, "source snapshot")

        for path in actions["restored_baseline_paths"]:
            _restore_baseline_path(repository, worktree, baseline_entries[path])
        for path in actions["removed_added_paths"]:
            _delete_added_path(worktree, path)

        _run_git_text(worktree, ["read-tree", BASELINE_COMMIT])
        post_removal_index_tree = _run_git_text(worktree, ["write-tree"])
        if post_removal_index_tree != BASELINE_TREE:
            raise EvidenceError("post-removal Git index is not the frozen baseline tree")

        expected_after = dict(baseline_entries)
        for path in actions["retained_audit_paths"]:
            expected_after[path] = source_entries[path]
        observed_after = _assert_filesystem_inventory(
            worktree, expected_after, "post-removal source"
        )
        protected_before = _protected_snapshot(worktree, manifest)
        if not all(item.get("matches_baseline") for item in protected_before.values()):
            raise EvidenceError("protected baseline bytes or modes differ after removal")
        for path in actions["removed_added_paths"]:
            if _safe_target(worktree, path).exists():
                raise EvidenceError("removed PLAN-005 source remains: {}".format(path))

        environment = _clean_environment(dict(os.environ))
        environment["CARGO_TERM_COLOR"] = "never"
        environment["CARGO_NET_OFFLINE"] = "true"
        environment["RUST_BACKTRACE"] = "1"
        if args.cargo_target_dir:
            cargo_target_candidate = Path(args.cargo_target_dir)
            if not cargo_target_candidate.is_absolute():
                cargo_target_candidate = repository / cargo_target_candidate
            if cargo_target_candidate.is_symlink():
                raise EvidenceError("cargo target path must not be a symlink")
            cargo_target = cargo_target_candidate.resolve()
        else:
            cargo_target = temporary / "cargo-target"
        _validate_cargo_target(cargo_target, repository, worktree, output)
        environment["CARGO_TARGET_DIR"] = str(cargo_target)
        metadata_argv = [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            "kernel/Cargo.toml",
        ]
        completed = subprocess.run(
            metadata_argv,
            cwd=str(worktree),
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            message = redact_output(
                completed.stderr, repository, worktree, output, cargo_target
            )
            raise EvidenceError("baseline cargo metadata failed: {}".format(message.strip()))
        packages = _metadata_packages(completed.stdout)
        if packages != EXPECTED_PACKAGES:
            raise EvidenceError(
                "post-removal package set mismatch: {}".format(
                    ", ".join(sorted(packages))
                )
            )
        metadata_path = output / "metadata-after-removal.json"
        write_json(metadata_path, _normalized_metadata(completed.stdout))
        commands.append(
            {
                "name": "metadata-after-removal",
                "argv": metadata_argv,
                "exit_code": 0,
                "log": "metadata-after-removal.json",
                "log_sha256": sha256_file(metadata_path),
            }
        )

        if not args.skip_tests:
            common = [
                "--locked",
                "--offline",
                "--manifest-path",
                "kernel/Cargo.toml",
                "--all-targets",
                "--all-features",
            ]
            tests = (
                (
                    "plan-001-contracts",
                    [
                        "cargo",
                        "test",
                        *common,
                        "--package",
                        "helix-contracts",
                        "--",
                        "--test-threads=1",
                    ],
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
                ),
                (
                    "plan-003-replay",
                    [
                        "cargo",
                        "test",
                        *common,
                        "--package",
                        "helix-replay-sqlite",
                        "--",
                        "--test-threads=1",
                    ],
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
                ),
            )
            for name, argv in tests:
                commands.append(
                    _run_evidence_command(
                        name,
                        argv,
                        worktree,
                        output,
                        repository,
                        worktree,
                        environment,
                        cargo_target,
                    )
                )

        post_removal_index_tree = _run_git_text(worktree, ["write-tree"])
        if post_removal_index_tree != BASELINE_TREE:
            raise EvidenceError("commands changed the frozen post-removal Git index")
        observed_after = _assert_filesystem_inventory(
            worktree, expected_after, "post-command removal source"
        )
        protected_after = _protected_snapshot(worktree, manifest)
        if not all(item.get("matches_baseline") for item in protected_after.values()):
            raise EvidenceError("commands changed protected baseline bytes or modes")
        for path in actions["removed_added_paths"]:
            if _safe_target(worktree, path).exists():
                raise EvidenceError(
                    "commands recreated removed PLAN-005 source: {}".format(path)
                )

        write_json(output / "protected-files-before.json", protected_before)
        write_json(output / "protected-files-after.json", protected_after)
        removal_inventory = {
            "schema": "helixos.plan-005-removal-inventory/1",
            "source_mode": source_mode,
            "source_commit": source_commit,
            "source_commit_tree": source_commit_tree,
            "source_delta_sha256": source_delta_sha256,
            **actions,
        }
        write_json(output / "removal-inventory.json", removal_inventory)

        status_after = _status_snapshot(repository)
        if status_after != status_before:
            raise EvidenceError("original working-tree status changed during isolated removal")
        immutable_eligible = source_mode == "exact-commit" and not args.skip_tests
        if immutable_eligible:
            result = "passing-isolated-exact-commit-removal"
        elif source_mode == "exact-commit":
            result = "diagnostic-exact-commit-removal-tests-skipped"
        elif args.skip_tests:
            result = "diagnostic-working-tree-removal-tests-skipped"
        else:
            result = "diagnostic-working-tree-removal"
        report = {
            "schema": REPORT_SCHEMA,
            "acceptance_id": "PLAN-005",
            "result": result,
            "evidence_scope": (
                "exact-commit"
                if source_mode == "exact-commit"
                else "diagnostic-uncommitted-working-tree-snapshot"
            ),
            "source_commit": source_commit,
            "source_commit_tree": source_commit_tree,
            "source_head_commit": head_commit,
            "source_mode": source_mode,
            "source_delta_sha256": source_delta_sha256,
            "driver_sha256": driver_sha256,
            "baseline_commit": BASELINE_COMMIT,
            "baseline_tree": BASELINE_TREE,
            "post_removal_index_tree": post_removal_index_tree,
            "protected_manifest_sha256": manifest_sha256,
            "protected_file_count": len(protected_after),
            "protected_baseline_restored_exactly": True,
            "original_working_tree_status_shape_unchanged": True,
            "original_working_tree_content_equality": "not-content-hashed",
            "ignored_user_owned_working_tree_paths": ignored_exclusions,
            "removed_added_file_count": len(actions["removed_added_paths"]),
            "restored_baseline_file_count": len(actions["restored_baseline_paths"]),
            "retained_audit_file_count": len(actions["retained_audit_paths"]),
            "post_removal_file_count": len(observed_after),
            "metadata_packages": sorted(packages),
            "sc009_exact_commit_eligible": immutable_eligible,
            "immutable_release_evidence_eligible": immutable_eligible,
            "source_dispatch_executable_surface_after_removal": (
                "absent-by-closed-file-and-package-inventory"
            ),
            "retained_state_authority": (
                "not-assessed-by-source-removal-driver; combined T082 evidence required"
            ),
            "source_boundary_proof": [
                "all 495 baseline runtime and prerequisite blobs/modes are exact",
                "post-removal Cargo metadata contains only the eight PLAN-001 through "
                "PLAN-004 and legacy packages",
                "every PLAN-005 executable/derived added file matched the closed "
                "allowlist and was removed",
                "only allowlisted specifications, historical evidence, and verification "
                "tools remain outside the baseline source tree",
            ],
            "tests_skipped": bool(args.skip_tests),
            "commands": commands,
            "limits": manifest["nonclaims"],
        }
        write_json(output / "report.json", report)
        return report
    finally:
        cleanup_failure: Optional[str] = None
        if worktree_added:
            completed_cleanup = subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=str(repository),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if completed_cleanup.returncode != 0:
                cleanup_failure = "owned isolated worktree removal command failed"
        shutil.rmtree(str(temporary), ignore_errors=True)
        if worktree_admin is not None and worktree_admin.exists():
            try:
                shutil.rmtree(str(worktree_admin))
            except OSError:
                cleanup_failure = "owned isolated worktree metadata cleanup failed"
        if cleanup_failure is not None:
            try:
                (output / "report.json").unlink()
            except OSError:
                pass
            raise EvidenceError(cleanup_failure)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".")
    parser.add_argument("--baseline", default=BASELINE_COMMIT)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--source-commit",
        help="Use an exact committed source; omit for a diagnostic filtered working-tree snapshot.",
    )
    parser.add_argument("--cargo-target-dir")
    parser.add_argument("--validate-manifest-only", action="store_true")
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Run structural removal and metadata only; the report is not full removal evidence.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = execute_drill(args)
    except EvidenceError as error:
        message = _redact_failure_message(str(error), args)
        print("PLAN-005 removal drill failed: {}".format(message), file=sys.stderr)
        return 1
    if not args.validate_manifest_only:
        outcome = (
            "passed immutable exact-commit gate"
            if report["immutable_release_evidence_eligible"]
            else "completed diagnostic-only run"
        )
        print(
            "PLAN-005 removal drill {} ({}, {} protected files)".format(
                outcome, report["evidence_scope"], report["protected_file_count"]
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
