---
type: "query"
date: "2026-07-15T08:52:35.756858+00:00"
question: "PLAN-005: Why did PR 6 fail PLAN-004 and time out PLAN-001, and what is the ownership-correct remediation?"
contributor: "graphify"
outcome: "useful"
source_nodes: [".github/workflows/contracts.yml", ".github/workflows/durable-preparation.yml", ".github/workflows/durable-dispatch.yml", "tools/tests/test_plan004_evidence.py", "tools/tests/test_plan005_evidence.py", "specs/005-durable-dispatch/evidence/removal-protected-files.json", "kernel/helix-plan-dispatch/tests/portability.rs"]
---

# Q: PLAN-005: Why did PR 6 fail PLAN-004 and time out PLAN-001, and what is the ownership-correct remediation?

## Answer

The historical PLAN-001 workspace sweep and PLAN-004 coordinator sweep unintentionally executed three non-ignored PLAN-005 release contention matrices in debug mode. Hosted Linux and Windows failed the 100-by-64 cardinality after root-lease acquisition refusals, and PLAN-001 reached its 30-minute timeout. PLAN-005 already proves the same exact cardinalities separately with release builds on Linux, macOS, and Windows. The correction keeps the exact PLAN-005 gates unchanged, adds three named --skip filters only to the historical broad sweeps, records those exclusions in both evidence descriptors, and extends the removal restoration allowlist so removing PLAN-005 restores the earlier workflows and policy test exactly. Local evidence: 58 Python policy tests and 7 Rust portability tests pass.

## Outcome

- Signal: useful

## Source Nodes

- .github/workflows/contracts.yml
- .github/workflows/durable-preparation.yml
- .github/workflows/durable-dispatch.yml
- tools/tests/test_plan004_evidence.py
- tools/tests/test_plan005_evidence.py
- specs/005-durable-dispatch/evidence/removal-protected-files.json
- kernel/helix-plan-dispatch/tests/portability.rs
