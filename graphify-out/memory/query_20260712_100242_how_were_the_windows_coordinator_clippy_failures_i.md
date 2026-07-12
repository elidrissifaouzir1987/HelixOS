---
type: "implementation"
date: "2026-07-12T10:02:42.348746+00:00"
question: "How were the Windows coordinator Clippy failures in PR #5 corrected?"
contributor: "graphify"
outcome: "corrected"
correction: "Align imports with the non-Windows restore implementation and isolate the non-Unix refusal in a cfg-specific helper instead of returning before code that remains compiled."
source_nodes: ["maintenance.rs", "root_safety.rs"]
---

# Q: How were the Windows coordinator Clippy failures in PR #5 corrected?

## Answer

Gate the four restore-only maintenance imports with the same non-Windows configuration as their only consumer, and keep shared inspection preconditions in the public function while dispatching post-validation custody to Unix and non-Unix helpers. The non-Unix helper remains fail-closed with RootUnavailable, so no unreachable Unix body is compiled. Native strict Clippy and 15 root-safety tests pass; macOS cross-Clippy cannot reach the crate because the Windows C SDK headers are unavailable.

## Outcome

- Signal: corrected
- Correction: Align imports with the non-Windows restore implementation and isolate the non-Unix refusal in a cfg-specific helper instead of returning before code that remains compiled.

## Source Nodes

- maintenance.rs
- root_safety.rs