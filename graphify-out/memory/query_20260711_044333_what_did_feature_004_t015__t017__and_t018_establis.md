---
type: "implementation"
date: "2026-07-11T04:43:33.306975+00:00"
question: "What did Feature 004 T015, T017, and T018 establish before T019 and T020?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["PreparationAttemptIdV1", "ReadyPreparationContextV1", "PreparationAuthoritySourceV1", "FinalCommitGateV1", "NoDispatchAuthorityGuardV1"]
---

# Q: What did Feature 004 T015, T017, and T018 establish before T019 and T020?

## Answer

T015 was created first and initially had five expected failures: missing attempt, context, guard/permit, T019, and T020 contracts. T017 then added a crate-created OS-random domain-separated opaque attempt identity, complete non-Clone/non-Serde preliminary/final ready contexts with all authority/replay/budget/recovery bindings, safe integers, redacted diagnostics, and injected UTC plus suspend-aware monotonic clock traits. T018 added injected authority guard sets, final capture, explicit reverse release, opaque no-dispatch binding/source/guard custody, a one-shot external supervisor commit gate/permit/in-flight protocol, and the exclusive min(caller deadline, entry plus 250 ms) permit ceiling without ambient clock, thread, or fencing store. After implementation four T017/T018 contract tests pass; only the explicitly reserved T019 provider/store and T020 outcome/export tests remain red. Locked all-target check, strict clippy, format, and library tests pass.

## Outcome

- Signal: useful

## Source Nodes

- PreparationAttemptIdV1
- ReadyPreparationContextV1
- PreparationAuthoritySourceV1
- FinalCommitGateV1
- NoDispatchAuthorityGuardV1