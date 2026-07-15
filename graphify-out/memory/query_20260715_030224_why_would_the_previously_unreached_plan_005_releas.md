---
type: "release-evidence-diagnosis"
date: "2026-07-15T03:02:24.260499+00:00"
question: "Why would the previously unreached PLAN-005 release job reject its own isolated removal evidence, and what corrected the proof?"
contributor: "graphify"
outcome: "corrected"
correction: "Compare the restored protected baseline immediately before validation commands with the protected baseline after those commands; retain exact source provenance and source-delta evidence for the pre-removal state."
source_nodes: ["execute_drill", "plan005_removal_drill.py", "_validate_removal_evidence", "Plan005RemovalSafetyTests"]
---

# Q: Why would the previously unreached PLAN-005 release job reject its own isolated removal evidence, and what corrected the proof?

## Answer

The removal driver captured protected-files-before.json from the exact PLAN-005 source before restoring the 23 allowlisted baseline paths, while the release verifier required that snapshot to equal the post-command baseline snapshot. Since PLAN-005 legitimately changes baseline files, the comparison was structurally unsatisfiable. The correction takes the before snapshot immediately after the closed removal/restoration step and before executing validation commands, then compares it with the after snapshot taken after those commands. Exact source provenance and the classified source delta still bind the pre-removal state. A diagnostic real drill restored 23 paths, retained 495 baseline records byte-for-byte, and produced identical before/after snapshots; all 37 evidence tests passed.

## Outcome

- Signal: corrected
- Correction: Compare the restored protected baseline immediately before validation commands with the protected baseline after those commands; retain exact source provenance and source-delta evidence for the pre-removal state.

## Source Nodes

- execute_drill
- plan005_removal_drill.py
- _validate_removal_evidence
- Plan005RemovalSafetyTests