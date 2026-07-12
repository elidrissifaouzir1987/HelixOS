---
type: "implementation"
date: "2026-07-12T10:08:13.124825+00:00"
question: "What is the final portable correction for the Windows coordinator Clippy failures in PR #5?"
contributor: "graphify"
outcome: "corrected"
correction: "Use fully qualified references inside the existing non-Windows implementation instead of adding alternate cfg spellings that evade the source guard; keep the non-Unix inspection helper fail-closed."
source_nodes: ["maintenance.rs", "root_safety.rs", "portability.rs"]
---

# Q: What is the final portable correction for the Windows coordinator Clippy failures in PR #5?

## Answer

Keep the portability guard's exact platform split unchanged. Remove restore-only imports from the shared import surface and use fully qualified crate paths only inside the existing non-Windows restore implementation. Split restore-root inspection after shared prevalidation into a Unix custody helper and a non-Unix fail-closed helper returning RootUnavailable. Native strict Clippy, the exact portability guard, root-safety tests, and contract regression tests pass; the final GitHub Windows runner remains the authoritative cross-platform check.

## Outcome

- Signal: corrected
- Correction: Use fully qualified references inside the existing non-Windows implementation instead of adding alternate cfg spellings that evade the source guard; keep the non-Unix inspection helper fail-closed.

## Source Nodes

- maintenance.rs
- root_safety.rs
- portability.rs