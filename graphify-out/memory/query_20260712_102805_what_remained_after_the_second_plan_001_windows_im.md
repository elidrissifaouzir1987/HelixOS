---
type: "ci-failure"
date: "2026-07-12T10:28:05.928725+00:00"
question: "What remained after the second PLAN-001 Windows immutable CI attempt?"
contributor: "graphify"
outcome: "corrected"
correction: "Gate test-only imports at the same platform boundary as their sole consumer so strict cross-platform Clippy stays warning-free."
source_nodes: ["root_safety.rs", "contracts.yml"]
---

# Q: What remained after the second PLAN-001 Windows immutable CI attempt?

## Answer

The production and test fixes passed formatting locally, but strict Windows Clippy found ROOT_LOCK_FILENAME imported into the shared root_safety test module even though its only remaining consumer is a Unix-only mutation test. Gate that test-only import with cfg(unix); this changes no runtime behavior and keeps -D warnings portable.

## Outcome

- Signal: corrected
- Correction: Gate test-only imports at the same platform boundary as their sole consumer so strict cross-platform Clippy stays warning-free.

## Source Nodes

- root_safety.rs
- contracts.yml