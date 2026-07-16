---
type: "query"
date: "2026-07-16T15:10:48.023541+00:00"
question: "How was the PLAN-006 Phase 1 dependency-policy failure corrected?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep the frozen guards exact while recognizing the single reviewed PLAN-006 projection leaf; do not evade or broadly weaken allowlists."
---

# Q: How was the PLAN-006 Phase 1 dependency-policy failure corrected?

## Answer

Adding helix-task-authority-projections as a new reviewed leaf made four exact direct-consumer tests fail. The correction added only that package to the eligibility, preparation, coordinator and dispatch consumer lists. No existing production crate gained a PLAN-006 dependency, and all focused plus full locked tests passed.

## Outcome

- Signal: corrected
- Correction: Keep the frozen guards exact while recognizing the single reviewed PLAN-006 projection leaf; do not evade or broadly weaken allowlists.