---
type: "query"
date: "2026-07-17T15:53:04.076904+00:00"
question: "What corrected the PLAN-006 T014 portability oracle after the canonical JSON f64 bridge false positive?"
contributor: "graphify"
outcome: "corrected"
correction: "The earlier oracle removed the complete visit_f64 block and could hide forbidden APIs inside it; the corrected oracle preserves the block and neutralizes only the three reviewed float identifiers."
---

# Q: What corrected the PLAN-006 T014 portability oracle after the canonical JSON f64 bridge false positive?

## Answer

T014 freezes UniqueVisitor::visit_f64 to the exact reviewed serde_json adapter, neutralizes only the identifiers visit_f64, f64, and from_f64 for the floating-point ban, keeps the remaining bridge text visible to every non-floating portability scan, and rejects seeded f32/f64 authority fields plus an exact tonic token injected inside the bridge. Evidence: the portability target passes 6/6 and the package passes 50/50 tests.

## Outcome

- Signal: corrected
- Correction: The earlier oracle removed the complete visit_f64 block and could hide forbidden APIs inside it; the corrected oracle preserves the block and neutralizes only the three reviewed float identifiers.