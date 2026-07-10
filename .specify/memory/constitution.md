<!--
Sync Impact Report
- Version change: Spec Kit template -> HelixOS 2.0.0 (mirror adoption; no semantic bump)
- Canonical source: ../../constitution.md
- Principles synchronized: I through X
- Added sections: Mandatory Specification Gates; Development Workflow
- Removed sections: none from the canonical constitution
- Templates: plan-template.md ✅; spec-template.md ✅; tasks-template.md ✅
- Follow-up TODOs: none
-->

# HelixOS Constitution

This file is the Spec Kit execution mirror of [`constitution.md`](../../constitution.md).
The root file is the canonical public text. A change is valid only when both files
remain semantically aligned. In a conflict, the root constitution wins and planning
MUST stop until this mirror is repaired.

HelixOS is a capability control plane, not a hardware kernel. The agent, its models,
skills, MCP servers, web UI, knowledge providers, retrieved content, and native compute
workers are assumed compromisable. Security MUST come from deterministic controls after
the model, never from prompt obedience.

## Core Principles

### I. Host Boundary and Threat Model (NON-NEGOTIABLE)

- Production agent workloads MUST run inside an isolated VM without host filesystem
  shares, host-runtime sockets/APIs, host devices, or unrestricted egress.
- Root in the guest is assumed to own the complete guest. Compromise MUST grant no new
  host capability, secret, or egress beyond a valid lease and approved plan.
- Knowledge compartments MUST NOT be directly reachable from the agent in Tier 1.
- Every new integration MUST update the versioned threat model before activation.

### II. Minimal Typed Task Authority

- The host MUST expose typed intentions only; no raw host API or agent-accessible shell.
- A signed `TaskLease` MUST bind task, workload, intentions, resource identifiers,
  budgets, counters, expiry, and delegation limits.
- Resources MUST use opaque roots plus validated relative components, never agent-chosen
  absolute paths or platform-native path objects in common contracts.
- Unknown intent, schema, version, target, or sovereign resource MUST be denied.
- Delegation MUST only reduce scope, duration, and budget.

### III. Sovereign Human Authorization

- Canonical plans MUST bind the full effect, preconditions, budget, verification,
  recovery profile, nonce, expiry, and fencing epoch before approval.
- L2 effects MUST use WebAuthn user verification on a dedicated approval origin.
- Raw secret reads, agent lease extension, unknown contracts, and sovereign-target
  mutation remain forbidden even with human approval.
- Notifications are not approvals and MUST NOT carry bearer authority.

### IV. Durable Effects and Honest Recovery

- The normative lifecycle is `receive -> validate -> plan -> authorize -> prepare ->
  execute -> verify -> settle`; durable transitions MUST precede the next effect.
- Universal exactly-once behavior MUST NOT be claimed. Ambiguous crashes become
  `OUTCOME_UNKNOWN` and require reconciliation rather than automatic replay.
- Every side effect MUST have a verification predicate and an effect-specific recovery
  statement backed by durable evidence.
- Dispatch MUST use a durable inbox/receipt protocol and a supervisor-owned fencing epoch.

### V. Data, Secrets, and Privacy

- The operation database is authoritative for plans, approvals, receipts, and budgets;
  knowledge indexes are derived and reconstructible.
- Untrusted services MUST NOT mount the host vault. Projection is explicit
  declassification into immutable, filtered, manifest-backed compartments.
- Secret bytes MUST remain in platform credential stores. Agents may request typed uses
  such as sign/authenticate through approved packages but MUST NOT receive raw values.
- Model, web, notification, and connector traffic MUST pass through a separate mediated
  egress component with destination, size, classification, and cost controls.
- Logs and Graphify memory MUST NOT contain credentials, sensitive full content, or
  private chain-of-thought.

### VI. Portability by Contract and Conformance

- Common contracts and policy MUST NOT expose macOS, Linux, or Windows primitives.
- Adapters MUST publish observed capabilities and accept short, one-shot signed
  `ExecutionGrant` values only.
- macOS Apple Silicon is the reference implementation; portability is proven only when
  an unchanged conformance suite passes on a second driver.
- Unsupported capabilities MUST be reported or refused, never emulated with a weaker
  security fallback.

### VII. Performance, Availability, and Budgets

- Performance claims MUST name hardware, OS/runtime, corpus, concurrency, repetitions,
  percentiles, and evidence artifact.
- Control and emergency lanes MUST remain available under bounded queues, backpressure,
  deadlines, and resource exhaustion.
- Cost, action, byte, file, concurrency, and duration budgets MUST be reserved before
  dispatch and reconciled afterward.
- A pre-dispatch failure of policy, identity, budget, durable audit, or receipt storage
  MUST fail closed. A possible post-dispatch effect MUST become unknown, never falsely
  reported as blocked.

### VIII. Verifiable Minimal Observability

- Operational state, security audit, logs, metrics, traces, and the human journal MUST be
  separate data classes with explicit access and retention.
- Every effect MUST carry task/lease/workload identity, versions, plan hash, decision,
  receipt, outcome, cost, latency, and trace identifiers.
- The audit ledger MUST be hash-chained, checkpoint-signed, redacted before
  serialization, and copied encrypted off-host for Tier 1.

### IX. Supply Chain and Lifecycle

- Dependencies, native artifacts, OCI images, guest kernels/rootfs, models, and runtime
  components MUST be pinned and verified. Releases require signatures, provenance, and
  an SBOM appropriate to the artifact.
- Updates MUST verify, quiesce, back up, migrate compatibly, smoke-test, and either commit
  or roll back. A single fencing owner MUST remain active.
- A clean-machine restore MUST start paused, rotate epochs, expire grants, and reconcile
  possible effects before resuming.

### X. Incremental, Spec-Driven Proof

- Delivery order MUST remain: contracts/harness; useful Mac slice; security/operations;
  second driver; third driver; knowledge; autonomy; isolated extensions.
- Every feature MUST have explicit IN/OUT scope, measurable acceptance, negative tests,
  recovery/restore evidence, and a removal path.
- A Tier 1 claim MUST be backed by security, conformance, restore, upgrade/rollback, and
  performance evidence on real target hardware.
- Graphify, models, and runtime products remain replaceable non-sovereign dependencies.

## Mandatory Specification Gates

Every Spec Kit feature MUST answer, with `N/A` justified where genuinely irrelevant:

1. What is untrusted, what authority is introduced, and which negative abuse case proves
   the boundary?
2. Which typed contract and version rules are added or changed?
3. What state becomes durable before an effect, and how are retry, ambiguity,
   verification, compensation, and restore handled?
4. What data classes, secret uses, egress destinations, and retention rules apply?
5. Which platform-independent behavior and conformance fixture prove portability?
6. Which performance/budget thresholds and overload behavior are measurable?
7. Which audit, supply-chain, rollback, and clean-restore artifacts are required?

Any host share, raw secret exposure, unrestricted egress, unknown schema/intent, missing
required test, or mutation of a sovereign target is a blocking violation.

## Development Workflow

1. Work MUST follow `spec -> clarify if needed -> plan -> checklist -> tasks -> implement
   -> test -> converge` for each bounded feature.
2. Tests for contracts and security invariants MUST be written before or together with
   implementation and MUST include negative and tamper cases.
3. Task files MUST contain exact paths, acceptance traceability, dependencies, and
   independently testable increments. Completed work MUST be checked off only after its
   evidence passes.
4. Architecture decisions MUST be captured in an ADR or feature research artifact.
5. Graphify MUST be refreshed after code changes. Meaningful decisions, dead ends,
   corrections, and verified outcomes MUST be stored as concise Graphify work-memory
   records without secrets or chain-of-thought.
6. Existing unrelated user changes MUST be preserved. No feature may silently broaden
   scope or weaken a constitutional MUST.

## Governance

- MAJOR changes alter trust, authority, effect semantics, or a non-negotiable ban; MINOR
  changes add compatible controls; PATCH changes clarify without changing guarantees.
- Amendments MUST record owner, date, motivation, threat, alternatives, migration,
  required tests, and rollback.
- A deviation MUST be scoped, owned, time-limited, compensated, tested, and assigned a
  removal date. It can never permit raw runtime secrets, host shares, agent-issued leases,
  unknown intents, sovereign mutations, or messaging-only L2 approval.
- Every plan and release MUST pass a Constitution Check. Violations block implementation
  unless the canonical constitution is amended first.

**Version**: 2.0.0 | **Ratified**: 2026-07-10 | **Last Amended**: 2026-07-10
