---
type: "query"
date: "2026-07-13T00:27:32.452904+00:00"
question: "Were the original PLAN-005 receipt fixtures and historical grant-key handling semantically correct?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat historical grant verification as retained evidence only, and require receipt reason, time, epoch, and generation relationships to be semantically coherent before accepting signed evidence."
---

# Q: Were the original PLAN-005 receipt fixtures and historical grant-key handling semantically correct?

## Answer

No. Review found that the original GRANT_EXPIRED receipt decided before the deadline, the SUPERVISOR_EPOCH_MISMATCH receipt repeated the grant epoch, and the current grant decoder accepted a historical key as fresh authority. The fixtures were corrected and all receipt bases re-signed with a fresh ephemeral receipt key whose private material was discarded; the 143-case inventory stayed stable. Current grant decoding now rejects historical keys, while a separate retained-evidence API preserves restart and upgrade verification without creating delivery authority.

## Outcome

- Signal: corrected
- Correction: Treat historical grant verification as retained evidence only, and require receipt reason, time, epoch, and generation relationships to be semantically coherent before accepting signed evidence.