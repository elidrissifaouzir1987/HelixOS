---
type: "ci-remediation"
date: "2026-07-15T10:34:54.480774+00:00"
question: "PLAN-005 integration: how was the PLAN-004 removal workspace parser spoof corrected?"
contributor: "graphify"
outcome: "corrected"
correction: "Use locked/offline Cargo metadata workspace IDs plus exact manifest-path binding in detached exact-commit worktrees; never scan raw TOML for security-relevant workspace membership."
source_nodes: ["tools/plan004_removal_drill.py", "tools/plan004_supply_chain.py", "tools/tests/test_plan004_evidence.py", "specs/005-durable-dispatch/evidence/us4-restore-removal.md"]
---

# Q: PLAN-005 integration: how was the PLAN-004 removal workspace parser spoof corrected?

## Answer

The raw TOML workspace scan could be spoofed by a fake workspace block inside a multiline string plus a quoted real members key. The PLAN-004 producer now runs locked, offline, no-deps Cargo metadata in its detached exact-commit worktree before deletion, resolves only semantic workspace_members IDs, and binds every required package to its exact kernel/<name>/Cargo.toml path; the verifier independently repeats the same semantic and path checks in a detached exact-commit worktree. It then restores the frozen six-package manifest and lock while recording the three detached PLAN-005 packages. Historical eight-member bundles remain valid only through the explicit empty-downstream compatibility rule. A real temporary Cargo workspace regression proves both the hidden ninth member and a decoy manifest path are detected. Validation passed: PLAN-004 evidence 24/24, exact drill 5/5 commands, exact retained-evidence verifier, PLAN-005 evidence 38/38, and Rust portability 7/7.

## Outcome

- Signal: corrected
- Correction: Use locked/offline Cargo metadata workspace IDs plus exact manifest-path binding in detached exact-commit worktrees; never scan raw TOML for security-relevant workspace membership.

## Source Nodes

- tools/plan004_removal_drill.py
- tools/plan004_supply_chain.py
- tools/tests/test_plan004_evidence.py
- specs/005-durable-dispatch/evidence/us4-restore-removal.md
