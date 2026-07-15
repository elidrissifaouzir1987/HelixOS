---
type: "ci-correction"
date: "2026-07-15T01:41:32.661070+00:00"
question: "Why did corrected PLAN-005 run 29382053544 fail Rustfmt identically on Linux, macOS and Windows?"
contributor: "graphify"
outcome: "corrected"
correction: "Separate the mutating-format ownership boundary from non-mutating workspace integration gates: format only PLAN-005 production roots, but retain global check and Clippy."
source_nodes: ["durable-dispatch.yml", "PRODUCTION_ROOTS", "T094"]
---

# Q: Why did corrected PLAN-005 run 29382053544 fail Rustfmt identically on Linux, macOS and Windows?

## Answer

The global cargo fmt --all gate included the 27 user-owned legacy Rust paths that PLAN-005 explicitly excludes from formatting, staging and commits. An exact detached worktree proved that Rustfmt passes for the four reviewed production roots while workspace-wide cargo check and strict all-feature Clippy both pass unchanged. Scope only Rustfmt to PRODUCTION_ROOTS; keep check and Clippy global.

## Outcome

- Signal: corrected
- Correction: Separate the mutating-format ownership boundary from non-mutating workspace integration gates: format only PLAN-005 production roots, but retain global check and Clippy.

## Source Nodes

- durable-dispatch.yml
- PRODUCTION_ROOTS
- T094