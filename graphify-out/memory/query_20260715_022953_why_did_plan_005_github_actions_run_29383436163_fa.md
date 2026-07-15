---
type: "ci-remediation"
date: "2026-07-15T02:29:53.534830+00:00"
question: "Why did PLAN-005 GitHub Actions run 29383436163 fail on Linux, macOS, and Windows, and what corrections preserve the frozen contract and Windows publication semantics?"
contributor: "graphify"
outcome: "corrected"
correction: "Restore the authoritative terminal LF and use non-truncating writable handles for Windows-compatible file flushes; do not repin the frozen digest or weaken root identity checks."
source_nodes: ["publish_dispatch_member_v1", "publish_dispatch_index_terminal_v1", "publish_create_only", "frozen_contract_fixtures_have_exact_raw_and_jcs_projection_digests"]
---

# Q: Why did PLAN-005 GitHub Actions run 29383436163 fail on Linux, macOS, and Windows, and what corrections preserve the frozen contract and Windows publication semantics?

## Answer

Linux and macOS reached conformance and found expected-outcomes.json was one required terminal LF short: the 25,824-byte blob hashed to 2e3f6f97..., while the catalog, corpus runner, evidence, and 25,825-byte oracle all require 8a34adce.... Restoring exactly one terminal LF preserves the already-correct JCS digest 7b9283.... Windows failed earlier because coordinator and adapter publication called sync_all through File::open read-only handles; Win32 FlushFileBuffers requires GENERIC_WRITE. Non-truncating OpenOptions write-only reopens at the same four existing flush sites preserve create-only hard-link ordering and do not affect the same-handle fs-id root guard. Local evidence: 30 active dispatch maintenance tests passed, the 143-case corpus reported 8a34adce..., and strict Clippy passed for both modified packages.

## Outcome

- Signal: corrected
- Correction: Restore the authoritative terminal LF and use non-truncating writable handles for Windows-compatible file flushes; do not repin the frozen digest or weaken root identity checks.

## Source Nodes

- publish_dispatch_member_v1
- publish_dispatch_index_terminal_v1
- publish_create_only
- frozen_contract_fixtures_have_exact_raw_and_jcs_projection_digests