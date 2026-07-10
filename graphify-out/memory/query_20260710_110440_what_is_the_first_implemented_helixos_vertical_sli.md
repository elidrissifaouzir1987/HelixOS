---
type: "implementation"
date: "2026-07-10T11:04:40.705852+00:00"
question: "What is the first implemented HelixOS vertical slice and what evidence exists?"
contributor: "graphify"
outcome: "useful"
---

# Q: What is the first implemented HelixOS vertical slice and what evidence exists?

## Answer

Feature 001 implements an isolated helix-contracts Rust crate for portable root_id+components resources, RFC 8785 JCS, SHA-256 plan IDs, domain-separated Ed25519 signatures, strict untrusted-wire verification, stable denial codes, redacted diagnostics, positive fixtures, and a 23-case reusable negative corpus. Authoritative artifacts are specs/001-portable-signed-contracts, docs/adr/0005-canonical-signed-contracts.md, contracts, conformance/catalog.yaml, and kernel/helix-contracts. Local gates passed: exact-pinned Draft 2020-12 validation, deterministic regeneration of 28 fixture files, strict Clippy, 40 contract tests plus 106 legacy tests, a 100000-envelope release soak in 17.07 seconds, and benchmark p95 27000 ns with raw evidence. PLAN-001 and Tier 1 remain pending an immutable Linux/macOS-arm64/Windows CI run. AuthenticPlanEnvelopeV1 is authenticity only; the next feature must add explicit eligibility for time, boot, epochs, lease, replay, policy/catalog and capability freshness, plus durable recovery-preparation evidence.

## Outcome

- Signal: useful