#!/usr/bin/env python3
"""Generate the HelixOS roadmap snapshot from authoritative project sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROADMAP_SOURCE = ROOT / "ROADMAP-SPECS.md"
CATALOG_SOURCE = ROOT / "conformance" / "catalog.yaml"
OUTPUT = ROOT / "docs" / "roadmap" / "roadmap-data.js"
SCHEMA = "helixos.roadmap-data/1"
FINGERPRINT_DOMAIN = b"helixos-roadmap-input-v1\0"

TASK_RE = re.compile(r"^- \[([ xX])\]\s+(T\d+)\s+(.+)$")
PHASE_RE = re.compile(r"^##\s+Phase\s+(\d+):\s*(.+)$")
TASK_TITLE_RE = re.compile(r"^#\s+Tasks:\s*(.+)$")
STRATEGIC_PHASE_RE = re.compile(r"^##\s+(R[0-8])\s+—\s+(.+)$", re.MULTILINE)
CATALOG_ENTRY_RE = re.compile(r"(?m)^  - acceptance_id:\s*(PLAN-\d+)\s*$")


class RoadmapSourceError(RuntimeError):
    """Raised when an authoritative source cannot be parsed without guessing."""


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def source_files() -> list[Path]:
    task_files = sorted((ROOT / "specs").glob("*/tasks.md"))
    if not task_files:
        raise RoadmapSourceError("no specs/*/tasks.md source found")
    paths = [ROADMAP_SOURCE, CATALOG_SOURCE, *task_files]
    missing = [relative(path) for path in paths if not path.is_file()]
    if missing:
        raise RoadmapSourceError(f"missing roadmap sources: {', '.join(missing)}")
    return paths


def fingerprint_sources(paths: list[Path]) -> tuple[str, list[dict[str, str]]]:
    digest = hashlib.sha256(FINGERPRINT_DOMAIN)
    inventory: list[dict[str, str]] = []
    for path in paths:
        name = relative(path).encode("utf-8")
        content = path.read_bytes()
        digest.update(struct.pack(">I", len(name)))
        digest.update(name)
        digest.update(struct.pack(">Q", len(content)))
        digest.update(content)
        inventory.append(
            {
                "path": name.decode("utf-8"),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return digest.hexdigest(), inventory


def clean_markdown(value: str) -> str:
    value = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", value)
    value = value.replace("`", "")
    value = re.sub(r"\*\*([^*]+)\*\*", r"\1", value)
    return " ".join(value.split())


def strip_task_tags(value: str) -> tuple[list[str], str]:
    tags: list[str] = []
    rest = value
    while True:
        match = re.match(r"^\[([^]]+)]\s+", rest)
        if not match:
            break
        tags.append(match.group(1))
        rest = rest[match.end() :]
    return tags, clean_markdown(rest)


def task_kind(task_id: str, description: str) -> str:
    lowered = description.casefold()
    if "contradict" in lowered or "scope contradiction" in lowered:
        return "decision"
    if lowered.startswith(("capture ", "execute every ", "revalidate ")) or any(
        token in lowered for token in ("immutable ci", "ci matrix", "matrix and record")
    ):
        return "evidence"
    if task_id in {"T082", "T083"}:
        return "evidence"
    return "implementation"


def parse_tasks(path: Path) -> dict[str, object]:
    lines = path.read_text(encoding="utf-8").splitlines()
    title = next(
        (match.group(1) for line in lines if (match := TASK_TITLE_RE.match(line))),
        None,
    )
    if title is None:
        raise RoadmapSourceError(f"{relative(path)} has no '# Tasks:' title")

    current_phase = "Unphased"
    current_phase_number: int | None = None
    tasks: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    malformed = [
        line
        for line in lines
        if line.startswith("- [") and re.match(r"^- \[[^]]*]\s+T\d+", line) and not TASK_RE.match(line)
    ]
    if malformed:
        raise RoadmapSourceError(f"malformed task checkbox in {relative(path)}")

    for line_number, line in enumerate(lines, start=1):
        if phase := PHASE_RE.match(line):
            current_phase_number = int(phase.group(1))
            current_phase = clean_markdown(phase.group(2))
            continue
        task = TASK_RE.match(line)
        if task is None:
            continue
        done = task.group(1).casefold() == "x"
        task_id = task.group(2)
        if task_id in seen_ids:
            raise RoadmapSourceError(f"duplicate {task_id} in {relative(path)}")
        seen_ids.add(task_id)
        tags, description = strip_task_tags(task.group(3))
        tasks.append(
            {
                "id": task_id,
                "done": done,
                "tags": tags,
                "description": description,
                "phase": current_phase,
                "phaseNumber": current_phase_number,
                "kind": task_kind(task_id, description),
                "source": f"{relative(path)}#L{line_number}",
            }
        )

    if not tasks:
        raise RoadmapSourceError(f"{relative(path)} has no tasks")

    phases: list[dict[str, object]] = []
    for task in tasks:
        key = (task["phaseNumber"], task["phase"])
        if not phases or phases[-1]["key"] != key:
            phases.append(
                {
                    "key": key,
                    "number": task["phaseNumber"],
                    "title": task["phase"],
                    "total": 0,
                    "done": 0,
                }
            )
        phases[-1]["total"] += 1
        phases[-1]["done"] += int(bool(task["done"]))
    for phase in phases:
        phase.pop("key")

    total = len(tasks)
    completed = sum(int(bool(task["done"])) for task in tasks)
    return {
        "taskTitle": title,
        "taskSource": relative(path),
        "tasks": tasks,
        "phases": phases,
        "total": total,
        "completed": completed,
        "remaining": total - completed,
        "taskPercent": round(completed * 100 / total, 1),
    }


def scalar(block: str, key: str, *, required: bool = False) -> str | None:
    match = re.search(rf"(?m)^    {re.escape(key)}:\s*([^\n]+?)\s*$", block)
    if match:
        value = match.group(1).strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        return value
    if required:
        raise RoadmapSourceError(f"catalog entry missing {key}")
    return None


def nested_status(block: str, section: str) -> str | None:
    match = re.search(
        rf"(?ms)^      {re.escape(section)}:\s*$.*?^        status:\s*([^\n]+?)\s*$",
        block,
    )
    return match.group(1).strip() if match else None


def parse_catalog(path: Path) -> dict[str, dict[str, object]]:
    text = path.read_text(encoding="utf-8")
    matches = list(CATALOG_ENTRY_RE.finditer(text))
    if not matches:
        raise RoadmapSourceError("conformance catalog has no PLAN entries")
    entries: dict[str, dict[str, object]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.start() : end]
        plan_id = match.group(1)
        if plan_id in entries:
            raise RoadmapSourceError(f"duplicate {plan_id} in conformance catalog")
        title = scalar(block, "title", required=True)
        claim_status = scalar(block, "claim_status", required=True)
        feature = scalar(block, "feature", required=True)
        entries[plan_id] = {
            "id": plan_id,
            "title": title,
            "feature": feature,
            "spec": scalar(block, "spec"),
            "ciWorkflow": scalar(block, "ci_workflow"),
            "claimStatus": claim_status,
            "evidence": {
                "local": nested_status(block, "local") or "not-recorded",
                "immutable": nested_status(block, "immutable") or "not-recorded",
                "macMiniM4": nested_status(block, "mac_mini_m4") or "not-recorded",
            },
        }
    return entries


def catalog_id_for_task_path(
    task_path: str, catalog: dict[str, dict[str, object]]
) -> str | None:
    feature_dir = Path(task_path).parent.as_posix()
    candidates = []
    for plan_id, entry in catalog.items():
        feature = str(entry["feature"]).removesuffix("/spec.md").rstrip("/")
        spec = str(entry.get("spec") or "").removesuffix("/spec.md").rstrip("/")
        if feature_dir in {feature, spec}:
            candidates.append(plan_id)
    if len(candidates) > 1:
        raise RoadmapSourceError(f"ambiguous catalog match for {task_path}")
    return candidates[0] if candidates else None


def parse_strategic_roadmap(path: Path) -> tuple[list[dict[str, object]], list[str], list[str]]:
    text = path.read_text(encoding="utf-8")
    matches = list(STRATEGIC_PHASE_RE.finditer(text))
    if len(matches) != 9:
        raise RoadmapSourceError("ROADMAP-SPECS.md must define R0 through R8")

    exit_gates = {
        "R0": "Décisions runtime, services, réseau et baseline M4 archivées.",
        "R1": "Fondation durable, preuves immuables, restore et retrait exercés.",
        "R2": "Tranche Mac utile, isolée, vérifiée et récupérable.",
        "R3": "Opérations, supply chain et incidents durcis.",
        "R4": "Driver Linux complet et comportement portable inchangé.",
        "R5": "Driver Windows complet sans fallback de sécurité plus faible.",
        "R6": "Projection et connaissance bornées, reconstructibles et isolées.",
        "R7": "Autonomie planifiée avec budgets, fenêtres et arrêt souverain.",
        "R8": "Extensions signées, isolées, révocables et supprimables.",
    }
    stages: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.start() : end]
        stage_id = match.group(1)

        def field_paragraph(label: str) -> str:
            lines = block.splitlines()
            prefix = f"**{label}**"
            for line_index, line in enumerate(lines):
                if not line.startswith(prefix):
                    continue
                value = line.split(":", 1)[1].strip() if ":" in line else ""
                continuation = []
                for candidate in lines[line_index + 1 :]:
                    if not candidate.strip() or candidate.startswith(("#", "**", "- ")):
                        break
                    continuation.append(candidate.strip())
                return clean_markdown(" ".join([value, *continuation]))
            return ""

        goal = field_paragraph("But")
        effort = field_paragraph("Effort indicatif")
        if not goal:
            paragraph: list[str] = []
            for candidate in block.splitlines()[1:]:
                if not candidate.strip():
                    if paragraph:
                        break
                    continue
                if candidate.startswith(("#", "**", "- ")):
                    if paragraph:
                        break
                    continue
                paragraph.append(candidate.strip())
            goal = clean_markdown(" ".join(paragraph))
        status = "planned"
        if stage_id == "R0":
            status = "incomplete"
        elif stage_id == "R1":
            status = "active"
        stages.append(
            {
                "id": stage_id,
                "title": clean_markdown(match.group(2)),
                "goal": goal,
                "effort": effort or "Non estimé",
                "status": status,
                "exitGate": exit_gates[stage_id],
            }
        )

    def bullets_between(start_marker: str, end_marker: str) -> list[str]:
        start = text.find(start_marker)
        end = text.find(end_marker, start + len(start_marker))
        if start < 0 or end < 0:
            return []
        return [
            clean_markdown(line[2:].rstrip(";."))
            for line in text[start:end].splitlines()
            if line.startswith("- ")
        ]

    existing = bullets_between("Le dépôt n'est pas vide :", "Les tests kernel/CLI")
    done_definition = bullets_between("### Definition of Done commune", "---")
    return stages, existing, done_definition


def mark_blocked_dependencies(open_tasks: list[dict[str, object]]) -> None:
    by_id: dict[tuple[str, str], dict[str, object]] = {
        (str(task["planId"]), str(task["id"])): task for task in open_tasks
    }
    for decision in [task for task in open_tasks if task["kind"] == "decision"]:
        referenced = set(re.findall(r"\bT\d{3}\b", str(decision["description"])))
        for task_id in referenced:
            target = by_id.get((str(decision["planId"]), task_id))
            if target is not None and target is not decision:
                target["blockedBy"] = str(decision["id"])


def build_data() -> dict[str, object]:
    paths = source_files()
    fingerprint, inventory = fingerprint_sources(paths)
    catalog = parse_catalog(CATALOG_SOURCE)
    stages, existing_assets, definition_of_done = parse_strategic_roadmap(ROADMAP_SOURCE)

    features: list[dict[str, object]] = []
    matched_catalog_ids: set[str] = set()
    for path in paths:
        if path.name != "tasks.md":
            continue
        parsed = parse_tasks(path)
        plan_id = catalog_id_for_task_path(str(parsed["taskSource"]), catalog)
        if plan_id is None:
            plan_id = f"UNTRACKED-{len(features) + 1:03d}"
            conformance: dict[str, object] = {
                "id": plan_id,
                "title": parsed["taskTitle"],
                "claimStatus": "missing-catalog-entry",
                "evidence": {},
            }
        else:
            conformance = catalog[plan_id]
            matched_catalog_ids.add(plan_id)
        features.append(
            {
                "id": plan_id,
                "title": conformance.get("title") or parsed["taskTitle"],
                **parsed,
                "conformance": conformance,
            }
        )

    for plan_id, conformance in catalog.items():
        if plan_id not in matched_catalog_ids:
            features.append(
                {
                    "id": plan_id,
                    "title": conformance["title"],
                    "taskTitle": "No tasks source",
                    "taskSource": None,
                    "tasks": [],
                    "phases": [],
                    "total": 0,
                    "completed": 0,
                    "remaining": 0,
                    "taskPercent": None,
                    "conformance": conformance,
                    "diagnostic": "catalog-only",
                }
            )

    features.sort(key=lambda feature: str(feature["id"]))
    open_tasks: list[dict[str, object]] = []
    for feature in features:
        for task in feature["tasks"]:
            if not task["done"]:
                open_tasks.append({"planId": feature["id"], "planTitle": feature["title"], **task})
    mark_blocked_dependencies(open_tasks)

    active_feature = next(
        (feature for feature in reversed(features) if feature["remaining"]),
        features[-1] if features else None,
    )
    focus = None
    if active_feature is not None:
        active_open_tasks = [
            task for task in open_tasks if task["planId"] == active_feature["id"]
        ]
        focus = (
            next(
                (
                    task
                    for task in active_open_tasks
                    if task["kind"] == "implementation" and not task.get("blockedBy")
                ),
                None,
            )
            or next(
                (task for task in active_open_tasks if task["kind"] == "decision"),
                None,
            )
            or next(iter(active_open_tasks), None)
        )

    total = sum(int(feature["total"]) for feature in features)
    completed = sum(int(feature["completed"]) for feature in features)
    r1 = next(stage for stage in stages if stage["id"] == "R1")
    r1["trackedTaskTotal"] = total
    r1["trackedTaskCompleted"] = completed

    blockers: list[dict[str, str]] = [
        {
            "id": "R0-GATE",
            "title": "R0 n'est pas formellement fermé",
            "detail": "Les décisions runtime, services, réseau et la baseline physique M4 ne sont pas toutes archivées.",
            "source": "ROADMAP-SPECS.md#R0",
        }
    ]
    blockers.extend(
        {
            "id": f"{task['planId']} · {task['id']}",
            "title": "Décision de périmètre requise",
            "detail": str(task["description"]),
            "source": str(task["source"]),
        }
        for task in open_tasks
        if task["kind"] == "decision"
    )

    roadmap_date = re.search(
        r"(?m)^\*\*Date\*\*\s*:\s*(.+)$", ROADMAP_SOURCE.read_text(encoding="utf-8")
    )
    return {
        "schema": SCHEMA,
        "roadmapDate": roadmap_date.group(1).strip() if roadmap_date else "unknown",
        "sourceFingerprint": fingerprint,
        "sources": inventory,
        "summary": {
            "strategicStage": "R1",
            "focusPlan": active_feature["id"] if active_feature else None,
            "trackedTasks": total,
            "completedTasks": completed,
            "remainingTasks": total - completed,
            "trackedTaskPercent": round(completed * 100 / total, 1) if total else 0,
            "acceptedClaims": sum(
                int(feature["conformance"].get("claimStatus") not in {"pending", "pending-evidence"})
                for feature in features
            ),
            "totalClaims": len(features),
        },
        "currentFocus": focus,
        "strategicStages": stages,
        "features": features,
        "openTasks": open_tasks,
        "blockers": blockers,
        "existingAssets": existing_assets,
        "definitionOfDone": definition_of_done,
    }


def generated_bytes() -> bytes:
    data = build_data()
    payload = json.dumps(data, ensure_ascii=True, sort_keys=True, indent=2)
    return (
        "/* Generated by tools/update_roadmap.py. Do not edit by hand. */\n"
        f"window.HELIXOS_ROADMAP_DATA = {payload};\n"
    ).encode("utf-8")


def write_if_changed(content: bytes) -> bool:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.is_file() and OUTPUT.read_bytes() == content:
        return False
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=".roadmap-data-", suffix=".js", dir=OUTPUT.parent
    )
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, OUTPUT)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return True


def check(content: bytes) -> int:
    if not OUTPUT.is_file():
        print(
            f"roadmap data missing: {relative(OUTPUT)}; run python3 tools/update_roadmap.py",
            file=sys.stderr,
        )
        return 1
    current = OUTPUT.read_bytes()
    if current != content:
        print(
            f"roadmap data is stale: {relative(OUTPUT)}; run python3 tools/update_roadmap.py",
            file=sys.stderr,
        )
        return 1
    print(f"roadmap data is current ({build_data()['sourceFingerprint'][:12]})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail if generated data is stale")
    mode.add_argument("--watch", action="store_true", help="regenerate whenever a source changes")
    parser.add_argument("--interval", type=float, default=1.0, help="watch polling interval in seconds")
    arguments = parser.parse_args()
    if arguments.interval < 0.2:
        parser.error("--interval must be at least 0.2 seconds")

    try:
        content = generated_bytes()
        if arguments.check:
            return check(content)
        changed = write_if_changed(content)
        print(f"{'updated' if changed else 'current'}: {relative(OUTPUT)}")
        if not arguments.watch:
            return 0
        previous = content
        print("watching roadmap sources; press Ctrl-C to stop")
        while True:
            time.sleep(arguments.interval)
            content = generated_bytes()
            if content != previous:
                write_if_changed(content)
                previous = content
                print(f"updated: {relative(OUTPUT)}")
    except KeyboardInterrupt:
        return 0
    except (OSError, UnicodeError, RoadmapSourceError, ValueError) as error:
        print(f"roadmap generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
