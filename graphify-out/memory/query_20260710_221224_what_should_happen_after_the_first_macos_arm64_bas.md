---
type: "query"
date: "2026-07-10T22:12:24.931170+00:00"
question: "What should happen after the first macOS arm64 baseline?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["Kernel", "SqliteReplayClaimantV1", "ReplayClaimReceiptV1"]
---

# Q: What should happen after the first macOS arm64 baseline?

## Answer

Expanded from graph vocabulary: trust, kernel, replay, sqlite, preparation, prepare, recovery, budget, grant, dispatch, execution, pipeline. Priority order: first repair the local baseline gates without weakening them by making the provisioning test distinguish OpenSSL 3 from macOS LibreSSL and by resolving the documented full-workspace formatting gate mismatch; rerun the unfiltered fast baseline. Second, run PLAN-003 T055 on the physical Mac mini M4 using a dedicated validated local APFS root and preserve raw benchmark evidence, without claiming power-loss or F_FULLFSYNC proof. Third, specify Feature 004 for fresh comparison, budget and recovery reservation, and durable PREPARING, then continue toward ExecutionGrant, adapter receipt, reconciliation, settlement, and compensation. Do not start R2 Hermes or host-effect integration before these R1 boundaries exist.

## Outcome

- Signal: useful

## Source Nodes

- Kernel
- SqliteReplayClaimantV1
- ReplayClaimReceiptV1