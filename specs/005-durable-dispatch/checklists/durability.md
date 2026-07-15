# Security & Durability Requirements Checklist: Durable One-Shot Dispatch

**Purpose**: Formal pre-task review of PLAN-005 authority, one-shot, ambiguity,
migration, restore and release-evidence requirements
**Created**: 2026-07-12
**Feature**: [spec.md](../spec.md)

**Note**: This checklist evaluates the quality and completeness of the written
requirements, not whether an implementation already exists.

## Requirement Completeness

- [x] CHK001 Are the only accepted public dispatch inputs and their untrusted status
  explicitly defined, including the durable reload that supplies all positive authority?
  [Completeness, Spec §FR-001, §FR-040, §FR-049]
- [x] CHK002 Are all PLAN-004 prerequisite bindings required for dispatch enumerated,
  including operation/preparation generations, replay, reservation, recovery and event
  custody? [Completeness, Spec §FR-001, §FR-004, Data Model §2]
- [x] CHK003 Are restored, quarantined, failed, stale and already-overlaid preparations
  explicitly non-dispatchable without a recovery exception that could revive authority?
  [Completeness, Spec §FR-002]
- [x] CHK004 Are grant and receipt contract profiles complete with canonical encoding,
  digest, signature, signer purpose, key identity, domains, limits and unknown-version
  denial? [Completeness, Spec §FR-003, §FR-017, §FR-042]
- [x] CHK005 Are grant fields complete for task, workload, plan, lease, authorization,
  policy, catalog, capability, budget, recovery, destination, time and fencing?
  [Completeness, Spec §FR-004, Contract §Execution Grant 2.2]
- [x] CHK006 Are adapter receive, consume, definite refusal, duplicate, conflict and
  quarantine requirements each specified as distinct outcomes? [Completeness, Spec
  §FR-012–FR-017, §FR-043]
- [x] CHK007 Are coordinator states and all permitted PLAN-005 transitions named without
  an unspecified intermediate state, including the normative definite-refusal path to
  `FAILED` and late-receipt reconciliation custody? [Completeness, Spec §FR-020,
  §FR-023, §FR-043, Key Entities]
- [x] CHK008 Are post-handoff cancellation, PAUSE, audit failure and deadline-expiry
  requirements documented without deleting possible authority evidence? [Completeness,
  Spec §FR-023–FR-027]
- [x] CHK009 Are migration, incompatible-open, downgrade, backup, clean restore, orphan,
  conflict and removal requirements all present? [Completeness, Spec §FR-030–FR-032,
  §FR-036–FR-037, Plan §Phase 0]
- [x] CHK010 Are retention, at-rest protection, redaction, private-key exclusion, pruning
  and secure-erasure nonclaims all explicit? [Completeness, Spec §FR-018, §FR-030,
  §FR-045]

## Requirement Clarity

- [x] CHK011 Is “short grant” quantified by an exact maximum and the minimum-of-authority
  deadline rule, with retry renewal forbidden? [Clarity, Spec §FR-041, Research §Decision 5]
- [x] CHK012 Is deadline equality distinguished from exact-capacity equality, and is
  over-by-one behavior unambiguous? [Clarity, Spec §FR-011]
- [x] CHK013 Is the serialized authority boundary described as retained ordered guards
  plus a linearizable permit across the complete compare-and-transition, not merely a
  recent recheck? [Clarity, Spec §FR-010]
- [x] CHK014 Are the exact signed grant bytes, not only digest/metadata, included in the
  atomic dispatch commit and exact retry contract? [Clarity, Spec §FR-007, §FR-022]
- [x] CHK015 Is `EXECUTING` defined precisely as consumed adapter authority without
  effect/success, and is the no-execution-token boundary explicit? [Clarity, Spec
  §FR-015, §FR-020, Scope]
- [x] CHK016 Is “definite absence” specified with quiesced/fenced transport, healthy
  matching adapter state, deadline closure and authoritative generation rather than an
  empty-row observation? [Clarity, Spec §FR-023]
- [x] CHK017 Are `CONSUMED` and `REFUSED_DEFINITE` receipt meanings and their permitted
  coordinator consequences, base-operation update and reservation custody closed and
  unambiguous? [Clarity, Spec §FR-043, Contract §Execution Receipt 3.2]
- [x] CHK018 Is redaction scoped clearly so required internal wire identities/digests are
  retained while public logs, Debug, metrics and outward events redact them? [Clarity,
  Spec §FR-018]

## Requirement Consistency

- [x] CHK019 Do spec, research, data model and protocol agree that the PLAN-004 base row
  remains immutable while V2 supplies effective dispatch lifecycle? [Consistency, Spec
  §FR-002, Plan §Storage, Research §Decision 4, Data Model §5]
- [x] CHK020 Do the authority requirements consistently forbid `PreparedOperationV1`,
  direct rows, caller projections and legacy kernel authority? [Consistency, Spec
  §FR-039–FR-040, §FR-049]
- [x] CHK021 Are grant and receipt signer domains/purposes consistently distinct across
  all artifacts and protected from cross-protocol verification? [Consistency, Spec
  §FR-042, Research §Decision 6, Contract §Profiles]
- [x] CHK022 Do the documents consistently state that coordinator, adapter, supervisor,
  transport and signing custody are separate domains with no distributed transaction?
  [Consistency, Spec §FR-044, Protocol §2, Data Model §9]
- [x] CHK023 Are reservations and recovery custody consistently retained through
  `DISPATCHING`, `EXECUTING` and `OUTCOME_UNKNOWN`, with settlement/release deferred?
  [Consistency, Research §Decision 10, Spec §Scope]
- [x] CHK024 Are hosted/process-kill, physical-M4, power-loss, subsystem restore,
  full-machine restore and Tier 1 claims consistently distinguished? [Consistency, Spec
  §FR-046, §FR-048, Plan §Target Platform]

## Acceptance Criteria Quality

- [x] CHK025 Is concurrency acceptance quantified with repetition plus thread/process
  rounds/counts and an exact one-grant/one-consumption outcome? [Measurability, Spec
  §SC-001]
- [x] CHK026 Is fault coverage measurable through a separate closed versioned exhaustive
  ordered inventory fixed at exactly 90 boundaries and 180 declared
  in-process/process-kill cases, with stable IDs/cardinality/owners/coverage rather than
  implementation-selected “every boundary” wording? [Measurability, Spec §FR-047,
  Contract §fault-boundaries-v1.json, §SC-002]
- [x] CHK027 Are tamper/replay/cross-binding/stale-epoch denial categories sufficiently
  enumerated for objective corpus coverage? [Measurability, Spec §SC-003]
- [x] CHK028 Is lost-acknowledgement recovery quantified as 100% original-receipt recovery
  with zero second consumption? [Measurability, Spec §SC-004]
- [x] CHK029 Is the M4 measurement boundary, warmup/sample count, hardware/profile
  metadata and p95/p99 threshold fully specified? [Measurability, Spec §SC-005]
- [x] CHK030 Are ordinary/control queue capacities, flood size, refusal deadline and
  control-lane p99 threshold plus controlled-trial count exact? [Measurability, Spec
  §SC-006]
- [x] CHK031 Are restore and removal outcomes objectively defined as zero revived
  authority plus preserved historical/prerequisite evidence? [Measurability, Spec
  §SC-007, §SC-010]
- [x] CHK032 Are release verification and portability criteria tied to one exact commit,
  unchanged corpus, exact artifacts and declared platform refusals? [Measurability, Spec
  §SC-008–SC-009]

## Scenario and Edge-Case Coverage

- [x] CHK033 Are primary, duplicate, conflict, refusal, lost-response, crash, overload,
  migration, restore and removal scenario classes represented? [Coverage, Spec §User
  Stories 1–4, Edge Cases]
- [x] CHK034 Are signer failure, key rotation/revocation, domain confusion and historical
  public verification requirements covered? [Coverage, Spec §FR-009, §FR-030, §FR-042]
- [x] CHK035 Are exact deadline, grant-lifetime, capacity, queue and generation boundary
  cases documented? [Coverage, Spec §Edge Cases, §FR-011, §FR-034, §FR-041]
- [x] CHK036 Are coordinator uncertain commit, possible transport handoff, adapter
  uncertain receipt and restored cross-store disagreement separately classified?
  [Coverage, Spec §FR-023, §FR-028–FR-032]
- [x] CHK037 Are adapter store busy/full/unavailable/corrupt and audit unavailable before
  versus after possible acceptance addressed? [Coverage, Spec §Edge Cases, §FR-027]
- [x] CHK038 Are key/operation/nonce collisions and key rotation prevented from reopening
  the one-shot namespace? [Coverage, Spec §FR-016, §FR-042]

## Dependencies, Evidence and Scope

- [x] CHK039 Are PLAN-001 through PLAN-004 prerequisites, injected authority-view
  assumption and signed-authority migration debt documented without treating them as
  production-ready? [Assumption, Spec §Assumptions, §FR-039]
- [x] CHK040 Are required acceptance IDs and aggregate `pending-evidence` status named,
  including external/physical gates that hosted CI cannot satisfy? [Traceability, Spec
  §FR-048, Plan §Acceptance Traceability]
- [x] CHK041 Is PLAN-005's own fault registry explicitly separate from immutable PLAN-004
  evidence and corpus? [Dependency, Spec §FR-047]
- [x] CHK042 Are the real-effect, IPC, supervisor, signed lease/approval, WebAuthn, R2 and
  Tier 1 exclusions explicit enough to prevent task-generation scope creep? [Scope, Spec
  §Out of Scope]
- [x] CHK043 Are supply-chain, immutable CI, migration rollback, subsystem restore and
  isolated removal evidence requirements mapped to exact planned artifacts? [Traceability,
  Spec §FR-038, §FR-048, Plan §Acceptance Traceability]

## Contract Artifact Precision

- [x] CHK044 Are grant and receipt wire requirements frozen by exhaustive closed JSON
  Schemas and non-placeholder canonical examples with exact ID/nonce encodings?
  [Completeness, Contract §execution-grant-v1.schema.json,
  §execution-receipt-v1.schema.json]
- [x] CHK045 Do coordinator and adapter SQL requirements enforce composite
  grant/operation/attempt/receipt/transition/event graphs rather than independent
  references that can be mixed? [Consistency, Data Model §9, Contract §SQL schemas]
- [x] CHK046 Are every append-only/create-only evidence row and every allowed mutable
  projection column distinguished by explicit no-delete/no-update or transition guards?
  [Completeness, Spec §FR-016, §FR-045, Contract §SQL schemas]
- [x] CHK047 Does `RESTORE_PENDING` have explicit storage-level requirements denying all
  new grant, handoff, consumption and activation authority until reviewed
  reconciliation? [Coverage, Spec §FR-031, Contract §SQL schemas]
- [x] CHK048 Does the backup contract distinguish exact coordinator/adapter constants,
  generations, counts, backup order, unique key purposes and signature-protected
  manifest fields? [Completeness, Spec §FR-030, Contract
  §dispatch-backup-manifest-v1.schema.json]

## Notes

- Focus: authority/security plus durability/recovery, selected as the two highest-risk
  domains for this feature.
- Depth/audience: formal pre-task and PR-review gate.
- Review status: 48/48 requirement-quality items satisfied after independent wire, SQL,
  restore-lock, backup, fault-registry and cross-artifact validation.
