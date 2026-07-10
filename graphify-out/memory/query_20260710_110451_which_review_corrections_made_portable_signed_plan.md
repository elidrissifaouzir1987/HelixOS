---
type: "security-review"
date: "2026-07-10T11:04:51.197116+00:00"
question: "Which review corrections made portable signed plan v1 safe enough for local completion?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep cryptographic authenticity, current authorization/eligibility, and prepared recovery as distinct typed trust transitions; fail closed before external resolvers and redact all untrusted diagnostics."
---

# Q: Which review corrections made portable signed plan v1 safe enough for local completion?

## Answer

The adversarial review found and corrected: explicit JSON null aliasing an omitted recovery preimage; file writes incorrectly allowed at L0 and irreversible effects below L2; missing price_table_id in the signed budget; compensation space below preimage length; malformed signatures reaching the key resolver; public Debug and serde error chains leaking plan data; incomplete Windows device/bidi/default-ignorable path filtering; direct public deserialization of unverified signed envelopes; schema/code bounds drift; missing exhaustive valid-input and protected-leaf mutation proof; and a non-reusable negative corpus. Code, schemas, ADR, fixtures and tests were updated together. The remaining architectural boundary is intentionally deferred: authenticity must never be treated as current dispatch eligibility, and compensation needs a durable prepared-recovery receipt before L1 execution.

## Outcome

- Signal: corrected
- Correction: Keep cryptographic authenticity, current authorization/eligibility, and prepared recovery as distinct typed trust transitions; fail closed before external resolvers and redact all untrusted diagnostics.