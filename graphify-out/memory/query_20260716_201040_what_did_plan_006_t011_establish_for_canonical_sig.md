---
type: "implementation"
date: "2026-07-16T20:10:40.297863+00:00"
question: "What did PLAN-006 T011 establish for canonical signed task-authority wires and protected digests?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["decode_canonical_value", "to_jcs_vec", "require_closed_object", "Sha256Digest", "T011"]
---

# Q: What did PLAN-006 T011 establish for canonical signed task-authority wires and protected digests?

## Answer

T011 added bounded duplicate-aware JSON decoding that rejects oversize input and BOMs, detects decoded-name duplicates recursively, reserializes with RFC 8785 JCS, and requires exact wire-byte equality. It added exact closed-object inventory checks and a SHA-256 digest type with strict 64-character lowercase hex parsing, manual Serde, and payload-opaque Debug. A temporary T013/T014 compile harness ran 13/13 unit tests, then was removed so the committed scope remains canonical.rs and digest.rs only. Existing schema/oracle tests pass; the permanent foundation source tests remain intentionally RED only for crypto.rs, error.rs, validation.rs, and final lib.rs wiring owned by T012-T014.

## Outcome

- Signal: useful

## Source Nodes

- decode_canonical_value
- to_jcs_vec
- require_closed_object
- Sha256Digest
- T011