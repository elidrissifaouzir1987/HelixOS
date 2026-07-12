#!/usr/bin/env python3
"""Execute the PLAN-004 removal drill in an isolated exact-commit worktree."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


BASELINE_COMMIT = "01a9181ef83539c0516139f8285551a9dfabc3b5"
BASELINE_LOCK_SHA256 = "f3b6c0cb07f9e9ddec2f6b64cb3b00f7df99fd93066315e92f1a5dfa4b3498f8"
BASELINE_PACKAGES = {
    "helix-contracts",
    "helix-plan-eligibility",
    "helix-replay-sqlite",
    "helixos-kernel",
    "helixos-mcp-shim",
    "helixos-provision",
}
REMOVED_MEMBERS = {"helix-plan-preparation", "helix-coordinator-sqlite"}
REMOVED_PATHS = (
    "kernel/helix-plan-preparation",
    "kernel/helix-coordinator-sqlite",
    "contracts/fixtures/durable-preparation-v1",
    ".github/workflows/durable-preparation.yml",
)
PROTECTED_PATHS = (
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
BASELINE_IDENTICAL_PATHS = {
    "contracts/fixtures/plan-envelope-v1",
    "contracts/fixtures/plan-eligibility-v1",
    "contracts/fixtures/durable-replay-store-v1",
    "specs/003-durable-replay-store/contracts",
    "kernel/helixos-kernel",
    "kernel/helixos-mcp-shim",
    "kernel/helixos-provision",
}
PLAN002_STRUCTURAL_SKIP = "only_reviewed_consumers_depend_on_the_eligibility_contract"
ENVIRONMENT_ALLOWLIST = {
    "AR",
    "CARGO_HOME",
    "CC",
    "CI",
    "COMSPEC",
    "CXX",
    "DEVELOPER_DIR",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "HOME",
    "LANG",
    "LD_LIBRARY_PATH",
    "LOGNAME",
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
    "WINDIR",
}


class EvidenceError(RuntimeError):
    """Raised when the removal proof cannot be established."""


def _clean_environment(source: Dict[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in source.items()
        if key in ENVIRONMENT_ALLOWLIST or key.startswith("LC_")
    }


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


def remove_catalog_entry(text: str, acceptance_id: str) -> str:
    pattern = re.compile(
        r"^  - acceptance_id: {}\n.*?(?=^  - acceptance_id: PLAN-[0-9]{{3}}\n|\Z)".format(
            re.escape(acceptance_id)
        ),
        re.MULTILINE | re.DOTALL,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise EvidenceError("catalog must contain exactly one {} entry".format(acceptance_id))
    match = matches[0]
    return text[: match.start()] + text[match.end() :]


def remove_workspace_members(text: str, members: Set[str]) -> str:
    removed: Set[str] = set()
    output = []
    for line in text.splitlines(keepends=True):
        match = re.fullmatch(r'(\s*)"([^"]+)",(\r?\n)?', line)
        if match and match.group(2) in members:
            removed.add(match.group(2))
            continue
        output.append(line)
    if removed != members:
        missing = ", ".join(sorted(members - removed))
        raise EvidenceError("workspace removal did not find exact members: {}".format(missing))
    result = "".join(output)
    if any(member in result for member in members):
        raise EvidenceError("removed workspace member remains referenced")
    return result


def remove_plan004_attributes(text: str) -> str:
    exact_comment = "# PLAN-004 SQL, canonical JSON, fixtures and retained evidence are digest-sensitive."
    prefixes = (
        "/specs/004-durable-preparation/",
        "/contracts/fixtures/durable-preparation-v1/",
        "/.github/workflows/durable-preparation.yml ",
    )
    output = []
    removed = 0
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if stripped == exact_comment or stripped.startswith(prefixes):
            removed += 1
            continue
        output.append(line)
    if removed != 6:
        raise EvidenceError("expected exactly six PLAN-004 .gitattributes lines")
    return "".join(output)


def redact_output(
    text: str,
    removal_root: Path,
    repository_root: Path,
    home: Path,
    extra_paths: Iterable[Tuple[Path, str]] = (),
) -> str:
    replacements = [
        (str(removal_root), "<removal-root>"),
        (str(repository_root), "<repo>"),
        (str(home), "<home>"),
    ]
    replacements.extend((str(path), replacement) for path, replacement in extra_paths)
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    result = text
    for raw, replacement in replacements:
        if raw:
            result = result.replace(raw, replacement)
            result = result.replace(raw.replace("/", "\\"), replacement)
    return result


def run_git(repository: Path, argv: List[str]) -> str:
    completed = subprocess.run(
        ["git"] + argv,
        cwd=str(repository),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise EvidenceError(
            "git {} failed: {}".format(" ".join(argv), completed.stderr.strip())
        )
    return completed.stdout.strip()


def git_object(repository: Path, revision: str, path: str) -> str:
    return run_git(repository, ["rev-parse", "{}:{}".format(revision, path)])


def snapshot_paths(root: Path, paths: tuple) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for relative_root in paths:
        base = root / relative_root
        if not base.exists():
            raise EvidenceError("protected path is absent: {}".format(relative_root))
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise EvidenceError("protected path contains symlink")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = sha256_file(path)
    return result


def _remove_path(path: Path) -> None:
    if not path.exists():
        raise EvidenceError("required removal path is absent: {}".format(path))
    if path.is_dir():
        shutil.rmtree(str(path))
    else:
        path.unlink()


def _run_evidence_command(
    name: str,
    argv: List[str],
    cwd: Path,
    output: Path,
    repository: Path,
    removal_root: Path,
    environment: Dict[str, str],
) -> dict:
    started = time.monotonic()
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    redacted = redact_output(
        completed.stdout,
        removal_root,
        repository,
        Path.home(),
        extra_paths=(
            (Path(environment["CARGO_TARGET_DIR"]), "<cargo-target>"),
        )
        if environment.get("CARGO_TARGET_DIR")
        else (),
    ).replace("\r\n", "\n")
    log = output / "logs" / "{}.txt".format(name)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(redacted.rstrip("\n") + "\n", encoding="utf-8")
    if completed.returncode != 0:
        raise EvidenceError("removal drill command failed: {} (see {})".format(name, log))
    return {
        "name": name,
        "argv": [
            redact_output(item, removal_root, repository, Path.home()) for item in argv
        ],
        "exit_code": completed.returncode,
        "duration_ms": elapsed_ms,
        "log": "removal/logs/{}.txt".format(name),
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
    return {item.get("name") for item in packages if isinstance(item.get("name"), str)}


def _normalized_metadata(raw: str) -> dict:
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError("cargo metadata output is invalid: {}".format(error))
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise EvidenceError("cargo metadata output lacks packages")
    normalized = []
    for package in packages:
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
        "schema": "helixos.plan-004-removal-metadata/1",
        "workspace_packages": normalized,
        "workspace_package_count": len(normalized),
        "workspace_root": "<removal-root>/kernel",
        "target_directory": "<cargo-target>",
    }


def _restore_baseline_lock(repository: Path, worktree: Path) -> str:
    completed = subprocess.run(
        ["git", "show", "{}:kernel/Cargo.lock".format(BASELINE_COMMIT)],
        cwd=str(repository),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise EvidenceError("baseline Cargo.lock is unavailable")
    lock = worktree / "kernel" / "Cargo.lock"
    lock.write_bytes(completed.stdout)
    digest = sha256_file(lock)
    if digest != BASELINE_LOCK_SHA256:
        raise EvidenceError("restored baseline Cargo.lock digest mismatch")
    return digest


def _validate_baseline_objects(repository: Path, source_commit: str) -> List[dict]:
    baseline = run_git(repository, ["rev-parse", "{}^{{commit}}".format(BASELINE_COMMIT)])
    if baseline != BASELINE_COMMIT:
        raise EvidenceError("frozen baseline commit identity mismatch")
    lineage = subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASELINE_COMMIT, source_commit],
        cwd=str(repository),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if lineage.returncode != 0:
        raise EvidenceError("frozen baseline is not an ancestor of the removal source")
    result = []
    for path in PROTECTED_PATHS:
        source_object = git_object(repository, source_commit, path)
        entry = {"path": path, "source_object": source_object}
        if path in BASELINE_IDENTICAL_PATHS:
            baseline_object = git_object(repository, BASELINE_COMMIT, path)
            if baseline_object != source_object:
                raise EvidenceError(
                    "frozen fixture or legacy prerequisite changed since baseline: {}".format(
                        path
                    )
                )
            entry["baseline_object"] = baseline_object
            entry["baseline_identical"] = True
        else:
            entry["baseline_identical"] = "not-claimed; bytes-protected-across-removal"
        result.append(entry)
    return result


def _assert_plan002_structural_skip_source(worktree: Path) -> None:
    source = (
        worktree
        / "kernel"
        / "helix-plan-eligibility"
        / "tests"
        / "portability.rs"
    ).read_text(encoding="utf-8")
    pattern = re.compile(
        r"(?m)^#\[test\]\nfn\s+{}\s*\(\s*\)\s*\{{".format(
            re.escape(PLAN002_STRUCTURAL_SKIP)
        )
    )
    if len(pattern.findall(source)) != 1:
        raise EvidenceError(
            "PLAN-002 structural skip must name exactly one reviewed test"
        )


def execute_drill(args: argparse.Namespace) -> None:
    repository = Path(args.repository).resolve()
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("removal output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    source_commit = run_git(repository, ["rev-parse", "HEAD^{commit}"])
    if source_commit != args.source_commit:
        raise EvidenceError("removal source commit does not match checkout HEAD")
    protected_objects = _validate_baseline_objects(repository, source_commit)
    commands = []
    temporary = tempfile.mkdtemp(prefix="helixos-plan004-removal-")
    removal_root = Path(temporary) / "source"
    worktree_added = False
    try:
        run_git(
            repository,
            ["worktree", "add", "--detach", "--force", str(removal_root), source_commit],
        )
        worktree_added = True
        before = snapshot_paths(removal_root, PROTECTED_PATHS)

        for relative in REMOVED_PATHS:
            _remove_path(removal_root / relative)
        workspace = removal_root / "kernel" / "Cargo.toml"
        workspace.write_text(
            remove_workspace_members(
                workspace.read_text(encoding="utf-8"), REMOVED_MEMBERS
            ),
            encoding="utf-8",
        )
        catalog = removal_root / "conformance" / "catalog.yaml"
        catalog.write_text(
            remove_catalog_entry(catalog.read_text(encoding="utf-8"), "PLAN-004"),
            encoding="utf-8",
        )
        attributes = removal_root / ".gitattributes"
        attributes.write_text(
            remove_plan004_attributes(attributes.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        restored_lock_digest = _restore_baseline_lock(repository, removal_root)

        for relative in REMOVED_PATHS:
            if (removal_root / relative).exists():
                raise EvidenceError("removed path remains: {}".format(relative))
        after = snapshot_paths(removal_root, PROTECTED_PATHS)
        if before != after:
            raise EvidenceError("protected prerequisite bytes changed during removal")
        _assert_plan002_structural_skip_source(removal_root)

        environment = _clean_environment(dict(os.environ))
        environment["CARGO_TERM_COLOR"] = "never"
        environment["CARGO_NET_OFFLINE"] = "true"
        environment["RUST_BACKTRACE"] = "1"
        if args.cargo_target_dir:
            environment["CARGO_TARGET_DIR"] = str(Path(args.cargo_target_dir).resolve())
        metadata_argv = [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            "kernel/Cargo.toml",
        ]
        completed = subprocess.run(
            metadata_argv,
            cwd=str(removal_root),
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            raise EvidenceError("baseline cargo metadata failed: {}".format(completed.stderr))
        packages = _metadata_packages(completed.stdout)
        if packages != BASELINE_PACKAGES:
            raise EvidenceError(
                "removal metadata package set mismatch: {}".format(", ".join(sorted(packages)))
            )
        metadata_path = output / "metadata-after-removal.json"
        write_json(metadata_path, _normalized_metadata(completed.stdout))
        commands.append(
            {
                "name": "metadata-after-removal",
                "argv": metadata_argv,
                "exit_code": 0,
                "log": "removal/metadata-after-removal.json",
                "log_sha256": sha256_file(metadata_path),
            }
        )

        common = [
            "--locked",
            "--manifest-path",
            "kernel/Cargo.toml",
            "--all-targets",
            "--all-features",
        ]
        tests = (
            (
                "plan-001-contracts",
                ["cargo", "test"]
                + common
                + ["--package", "helix-contracts", "--", "--test-threads=1"],
            ),
            (
                "plan-002-eligibility",
                ["cargo", "test"]
                + common
                + [
                    "--package",
                    "helix-plan-eligibility",
                    "--",
                    "--test-threads=1",
                    "--skip",
                    PLAN002_STRUCTURAL_SKIP,
                ],
            ),
            (
                "plan-003-replay",
                ["cargo", "test"]
                + common
                + ["--package", "helix-replay-sqlite", "--", "--test-threads=1"],
            ),
            (
                "legacy-mvp0",
                ["cargo", "test"]
                + common
                + [
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
                    removal_root,
                    output,
                    repository,
                    removal_root,
                    environment,
                )
            )

        write_json(output / "protected-files-before.json", before)
        write_json(output / "protected-files-after.json", after)
        report = {
            "schema": "helixos.plan-004-removal-drill/1",
            "acceptance_id": "PLAN-004",
            "result": "passing-isolated-clean-copy-removal",
            "source_commit": source_commit,
            "baseline_commit": BASELINE_COMMIT,
            "removed_workspace_members": sorted(REMOVED_MEMBERS),
            "removed_paths": list(REMOVED_PATHS),
            "catalog_entry_removed": "PLAN-004",
            "restored_baseline_lock_sha256": restored_lock_digest,
            "metadata_packages": sorted(packages),
            "protected_git_objects": protected_objects,
            "protected_file_count": len(before),
            "protected_bytes_unchanged": True,
            "plan_002_structural_oracle": {
                "test": PLAN002_STRUCTURAL_SKIP,
                "status": "explicitly-skipped-after-its-reviewed-preparation-consumer-is-removed",
                "source_bytes": "protected-and-unchanged",
                "semantic_tests": "executed",
            },
            "commands": commands,
            "limits": [
                "software removal drill, not secure erasure",
                "isolated exact-commit worktree, not production machine decommission",
            ],
        }
        write_json(output / "report.json", report)
    finally:
        if worktree_added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(removal_root)],
                cwd=str(repository),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=str(repository),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        shutil.rmtree(temporary, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--cargo-target-dir")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        execute_drill(args)
    except EvidenceError as error:
        print("PLAN-004 removal drill failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
