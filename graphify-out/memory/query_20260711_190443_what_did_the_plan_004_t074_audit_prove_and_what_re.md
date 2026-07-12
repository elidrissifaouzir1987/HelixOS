---
type: "audit"
date: "2026-07-11T19:04:43.252725+00:00"
question: "What did the PLAN-004 T074 audit prove and what remains RED?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not treat registry iteration or a manual checkpoint loop as process-kill evidence; carry a caller-owned probe through the actual action and revalidate every affected durability domain after restart."
source_nodes: ["FaultSessionV1", "process_crash.rs", "process_probe.rs", "maintenance.rs"]
---

# Q: What did the PLAN-004 T074 audit prove and what remains RED?

## Answer

The frozen matrix now expands to 167 controlled cases after the independent coordinator pending-root marker boundary. Static executable audits prove the provider create/write/sync/close/reopen/publication sequence, detached attestation sequence, exactly one semantic callsite for each of 37 backup/restore helpers, and independent coordinator SQLite, coordinator root-marker, and recovery metadata RESTORE_PENDING publications. Ordinary process_crash and conformance_execution gates pass. The ignored release child remains genuinely RED: it manually replays FaultSession checkpoints after opening an empty coordinator rather than carrying the caller-owned session through a production workflow; the preflight now rejects that fake loop. A real fix requires explicitly threading a private probe/effect handler through production actions and phase-aware reopen validation, with no environment/thread-local/global selector.

## Outcome

- Signal: corrected
- Correction: Do not treat registry iteration or a manual checkpoint loop as process-kill evidence; carry a caller-owned probe through the actual action and revalidate every affected durability domain after restart.

## Source Nodes

- FaultSessionV1
- process_crash.rs
- process_probe.rs
- maintenance.rs