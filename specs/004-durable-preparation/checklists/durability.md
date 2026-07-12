# Durability and Authority Requirements Checklist: Durable Preparation Before Dispatch

**Purpose**: Review whether the authority, atomicity, recovery, ambiguity and restore
requirements are complete, precise, internally consistent and objectively assessable
before implementation tasks are accepted.
**Created**: 2026-07-11
**Feature**: [spec.md](../spec.md)

**Note**: This is a requirements-writing gate, not an implementation test plan. Items
ask whether the specification and its planning contracts define the required behavior
clearly enough for independent implementation and review.

## Requirement Completeness

- [x] CHK001 Are every untrusted actor, trusted authority source and the sole new
  preparation authority enumerated without leaving an implicit authority path?
  [Completeness, Spec §Constitution Constraints, Spec §FR-001–FR-005]
- [x] CHK002 Are all invalid substitutes for `EligiblePlanV1` and all prohibited uses
  of preparation records, receipts and markers explicitly covered? [Coverage, Spec
  §FR-001, Spec §FR-004–FR-005]
- [x] CHK003 Are the entry, durable linearization, known-failure, ambiguous and restore
  boundaries all defined while dispatch, grants, effects and compensation execution
  remain explicitly excluded? [Completeness, Spec §In Scope, Spec §Out of Scope, Spec
  §FR-034]
- [x] CHK004 Are all facts that must be carried by the durable operation, comparison,
  transition, reservation, recovery evidence and event records specified? [Completeness,
  Spec §FR-023, Spec §FR-028–FR-030]
- [x] CHK005 Does the requirements set define a total first-failure order that includes
  context health, replay, operation identity, budget, recovery and durable-store
  outcomes in both preliminary and final passes? [Completeness, Spec §FR-009,
  Spec §FR-014, Plan §Phase 0]
- [x] CHK006 Are the receipt, guard, readback and reconciliation obligations complete
  for every separate durability domain, including the supervisor, replay store,
  recovery provider and coordinator store? [Completeness, Spec §FR-027,
  Spec §FR-031–FR-033]

## Requirement Clarity

- [x] CHK007 Is “complete trusted preparation context” defined by an exact closed list
  of fields and health states rather than an extensible or provider-dependent notion?
  [Clarity, Spec §FR-007–FR-008]
- [x] CHK008 Are guard acquisition, lifetime, revocation, deadline, release and
  supervisor commit-permit/deadman semantics stated precisely enough to rule out a
  check-then-write interpretation? [Clarity, Spec §FR-012, Plan §Constitution Check]
- [x] CHK009 Are UTC expiry, boot-monotonic deadline and capability-freshness boundary
  conditions defined with explicit exclusive comparisons and a deterministic denial
  result at equality? [Clarity, Spec §FR-010, Spec §Edge Cases]
- [x] CHK010 Is exact replay verification distinguished unambiguously from replay
  admission, claim creation and comparison with the store’s latest global generation?
  [Clarity, Spec §FR-009, Spec §Assumptions]
- [x] CHK011 Are definite pre-commit failure, acknowledged commit, lost acknowledgement,
  conflicting readback and unclassifiable commit outcomes distinguished with exact
  retry, release, marker and quarantine consequences? [Clarity, Spec §FR-020,
  Spec §FR-032–FR-033]
- [x] CHK012 Are recovery evidence classes, provider/profile approval, publication
  states, capacity, retirement states and irreversibility evidence defined without a
  path that could imply synthetic production recovery? [Clarity, Spec §FR-022–FR-027,
  Spec §Out of Scope]
- [x] CHK013 Is “non-dispatchable” translated into explicit prohibitions for every
  record, receipt, marker, event and restored preparation rather than used as an
  undefined security label? [Clarity, Spec §FR-004–FR-005, Spec §FR-034, Spec §FR-038]

## Requirement Consistency

- [x] CHK014 Is the normative sequence consistent across the feature requirements and
  planning contracts: preliminary authority, exact replay, operation/budget preflight,
  recovery publication, guarded replay/preflight repetition, then durable commit?
  [Consistency, Spec §FR-011–FR-014, Plan §Phase 0]
- [x] CHK015 Do the budget requirements consistently require non-mutating preflight
  before recovery while reserving only inside the atomic coordinator transaction?
  [Consistency, Spec §FR-015–FR-020, Plan §Acceptance Traceability]
- [x] CHK016 Do the atomicity requirements name the same all-or-none record set for
  `PREPARING`, its permanent transition, budget reservation, recovery reference and
  preparation event? [Consistency, Spec §FR-028–FR-030, Spec §SC-001]
- [x] CHK017 Are monotonic operation state, append-only transition evidence and
  quarantine custody consistently separated so ambiguity cannot be represented as a
  positive or terminal operation transition? [Consistency, Spec §FR-033–FR-034,
  Spec §SC-006]
- [x] CHK018 Are indefinite retention, guarded material retirement and permanent
  retirement tombstones compatible without implying record pruning or physical secure
  erasure? [Consistency, Spec §FR-040, Spec §Assumptions, Plan §Constitution Check]
- [x] CHK019 Are quiescent backup, multi-provider recovery inventory, rotated epochs,
  paused restore and permanent non-reactivation requirements mutually consistent across
  independent stores? [Consistency, Spec §FR-037–FR-038, Spec §SC-007]
- [x] CHK020 Is the conformance-only status of deterministic/synthetic recovery evidence
  consistent in user scenarios, requirements, success criteria and scope exclusions?
  [Consistency, Spec §User Story 3, Spec §FR-022, Spec §SC-005, Spec §Out of Scope]

## Acceptance Criteria Quality

- [x] CHK021 Can every carried authority field and each first-denial code be mapped to
  an independently varied corpus case with a measurable zero-mutation expectation?
  [Measurability, Spec §FR-008, Spec §FR-014, Spec §SC-002]
- [x] CHK022 Are the concurrency populations, round counts, uniqueness outcomes and
  shared-allowance aggregate limits quantified for both thread and process contention?
  [Measurability, Spec §FR-019, Spec §SC-003–SC-004]
- [x] CHK023 Is “every declared preparation boundary” backed by an exhaustive named
  boundary inventory so crash coverage cannot be satisfied by an arbitrary subset?
  [Ambiguity, Spec §FR-036, Spec §SC-006]
- [x] CHK024 Are latency, warmup, sample-count, percentile, scheduler-tolerance,
  environment and retained-evidence requirements sufficient to reproduce performance
  claims without including recovery-transfer latency? [Measurability, Spec §FR-042,
  Spec §SC-009–SC-010]
- [x] CHK025 Are redaction success criteria objectively bounded while explicitly
  distinguishing allowed public synthetic fixture values from prohibited private or
  user-bound values? [Measurability, Spec §FR-039–FR-040, Spec §SC-011]

## Scenario and Edge-Case Coverage

- [x] CHK026 Are known cancellation/failure, possible commit, conflicting readback,
  orphan material and retirement uncertainty specified as distinct scenarios with
  non-overlapping outcomes? [Coverage, Spec §FR-021, Spec §FR-027,
  Spec §FR-032–FR-033]
- [x] CHK027 Are permit-owner termination, process hang, permit expiry and concurrent
  PAUSE/HALT covered as requirements, including who resolves ambiguity and what blocks
  later commits? [Coverage, Spec §FR-012, Spec §Edge Cases, Plan §Constitution Check]
- [x] CHK028 Are busy, read-only, full, corrupt, rolled-back, unknown-version and weaker-
  durability stores each assigned a clear fail-closed or quarantine requirement without
  admission-time repair? [Coverage, Spec §FR-035, Spec §Edge Cases]
- [x] CHK029 Are backup cuts that straddle independent-store updates, provider/profile
  rotation, pending retirement, missing material and restored historical `PREPARING`
  rows all covered by explicit deny, quarantine or terminal-reconciliation rules?
  [Coverage, Spec §FR-027, Spec §FR-037–FR-038, Spec §Edge Cases]
- [x] CHK030 Are exact-limit, plus-one, checked-overflow, reservation-ID reuse,
  cross-operation binding and aggregate shared-budget contention all specified for every
  supported v1 dimension? [Coverage, Spec §FR-016–FR-020, Spec §SC-004]

## Dependencies and Assumptions

- [x] CHK031 Are ownership, health, version and failure assumptions documented for the
  external supervisor guard, replay verifier, recovery provider, budget authority and
  encrypted-at-rest provisioner profile? [Assumption, Spec §Assumptions, Spec §FR-012,
  Spec §FR-022, Spec §FR-035]
- [x] CHK032 Are the frozen PLAN-001/002/003 compatibility obligations and the evidence
  needed to detect any wire, eligibility or replay regression explicitly traceable to
  removal and rollback criteria? [Dependency, Spec §FR-002, Spec §FR-043–FR-044,
  Spec §SC-012]

## Clarified High-Risk Definitions

- [x] CHK033 Is the commit-permit deadline quantified as the earlier caller deadline or
  fixed 250 ms ceiling, with equality and deadman tolerance measurable? [Clarity,
  Spec §FR-012, Spec §SC-010]
- [x] CHK034 Is known-failure budget release conditioned on an exact live sovereign
  no-dispatch guard whose issuer, bindings, lifetime and negative cases are complete?
  [Completeness, Spec §FR-021, Spec §SC-004]
- [x] CHK035 Are acknowledged commit, confirmed rollback, explicit uncertainty and
  missing classification assigned non-overlapping readback and outcome rules?
  [Consistency, Spec §FR-012, Spec §FR-033]
- [x] CHK036 Are operation-bound and true-orphan retirement specified as separate
  guarded paths, with a permanent orphan-resolution tombstone and no fabricated
  operation? [Coverage, Spec §FR-027, Spec §User Story 3]
- [x] CHK037 Is `complete_reference_set` defined to cover operation references, active
  quarantine and provider-enumerated packages while pending retirement blocks backup?
  [Clarity, Recovery Provider Contract §10]
- [x] CHK038 Are the owner, durable representation, agreement rules and prohibited
  transitions of `RESTORE_PENDING` defined independently for both restored roots?
  [Completeness, Spec §FR-037–FR-038]
- [x] CHK039 Is feature-local clean-root restore explicitly distinguished from the full
  constitutional clean-machine restore and activation gate? [Boundary, Spec §Out of
  Scope, Spec §Assumptions]
- [x] CHK040 Does backup provenance require cryptographic authentication that rejects
  coherent package substitution, rather than relying only on internal digests or
  encrypted storage? [Security, Spec §FR-037, Spec §SC-007]
- [x] CHK041 Are the domain-separated package-binding, inventory JCS and detached-
  attestation signature encodings defined with exact ordered inputs? [Clarity, Recovery
  Provider Contract §10, Backup Provenance Schema]
- [x] CHK042 Are provider maintenance requirements complete for enumeration, orphan
  reconciliation, cleanup guards, retirement, backup export, restore import and root-
  metadata publication? [Completeness, Recovery Provider Contract §2, §9–§10]

## Planning Review

- 2026-07-11: 42/42 requirements-writing checks passed after five recorded
  clarifications, cross-artifact review, JSON Schema/SQL validation and two independent
  task/checklist audits. Items CHK007, CHK011, CHK016, CHK019, CHK021, CHK023, CHK029,
  CHK033, CHK035 and CHK041 were closed by explicit artifact amendments before task
  acceptance.
- T083 revalidates this gate against completed implementation and retained evidence; it
  does not defer any planning ambiguity.

## Implementation Revalidation

- 2026-07-12 implementation revalidation confirms that all 42/42 checked items still
  describe a complete, precise and internally consistent requirements gate. Passing
  source, contract, budget, recovery, backup/restore, redaction and portability tests
  do not by themselves convert those planning checks into release evidence. This
  completes T083 without changing the release decision.
- CHK023 is now locally backed by implementation evidence: the frozen registry expands
  exactly to 123 boundaries and 167 controlled cases, and the exact release process-kill
  driver completed all 167 after carrying caller-owned probe custody through each real
  action and performing the phase-specific reopen check. This closes T074 as local
  process-kill/fault-injection evidence; registry enumeration alone remains insufficient,
  and no power-loss or immutable release claim follows.
- CHK019 and CHK038 are now locally resolved by the accepted Option B boundary. The
  default public surface exports exactly two non-constructible redacted evidence
  projections with no producer; restore validation, reconciliation, quarantine,
  limits/errors and all sovereign custody remain crate-internal. The negative surface,
  internal bounds, redaction and portability tests pass, closing T075 and T085 without
  claiming a production host or activation authority.
- CHK024 is now backed by retained controlled local evidence from clean source commit
  `f7b021db52503aaedcc59b9c9c8d95d357555352`. The physical Mac mini M4 run traversed
  the real final-comparison/coordinator-commit path for 500 warmups and 10,000 measured
  samples (10,500 acknowledged commits total): p50 11,218,708 ns, p95 24,096,375 ns,
  p99 25,443,666 ns and max 26,528,459 ns. The p95 <= 25 ms and p99 <= 100 ms gates
  passed. The coordinator artifact SHA-256 is
  `ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12`; recovery
  transfer remains separate with SHA-256
  `da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e`.
- CHK023 retains a local synthetic process-kill pass only. It is not power-loss,
  sector-loss, `F_FULLFSYNC`, immutable CI or production durability evidence.
- The release decision remains **withheld** and `claim_status` remains
  `pending-evidence`. Immutable three-platform CI/artifacts/attestations, supply-chain
  evidence, `F_FULLFSYNC` spike evidence, power-loss evidence, approval of the observed
  FileVault-at-rest profile, the full clean-machine restore/activation gate and Tier 1
  acceptance all remain pending. The 42/42 result is the requirements-writing gate,
  not completion of those release gates or of the full R0-R8 project.

## Notes

- Check items off as completed: `[x]`.
- Record any finding beside the affected item and link the resulting specification or
  contract amendment.
- A failed item blocks task acceptance when it leaves authority, atomicity, ambiguity,
  recovery or restore semantics open to multiple conforming interpretations.
