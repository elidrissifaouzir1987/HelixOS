# Feature Specification: Portable Signed Contracts

**Feature Branch**: `master`

**Created**: 2026-07-10

**Status**: Implemented and locally verified; immutable multi-OS CI evidence pending

**Input**: User description: "Use Graphify as project memory, use Spec Kit for
specification, tasks and implementation, then begin creating HelixOS."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Stable Plan Identity (Priority: P1)

As a HelixOS core developer, I can turn the same authorized plan into the same
portable canonical representation and plan identifier on every supported platform,
so an approval can never refer to different effects on different machines.

**Why this priority**: Every approval, execution grant, audit record, retry decision,
and adapter receipt depends on a stable plan identity. No later durable workflow is
safe without it.

**Independent Test**: A fixed corpus of valid plans can be processed on macOS arm64,
Linux x86_64/arm64, and Windows x64; each platform produces byte-identical canonical
content and the same identifier.

**Acceptance Scenarios**:

1. **Given** two semantically identical plans whose object members were supplied in
   different orders, **When** each is canonicalized, **Then** their canonical bytes and
   identifiers are identical.
2. **Given** two plans that differ in any effect-bearing field, **When** identifiers are
   produced, **Then** their identifiers differ.
3. **Given** a valid portable resource reference, **When** the plan is serialized and
   read on another supported platform, **Then** its root and relative components retain
   exactly the same meaning without using a native absolute path.

---

### User Story 2 - Verify Before Trust (Priority: P2)

As a trusted consumer such as an approval service or platform adapter, I can verify
the plan's supported version, canonical identifier, signer, and signature before I
accept it, and I receive a deterministic denial for unknown or tampered input.

**Why this priority**: A canonical hash without authenticated provenance does not prove
who authorized the effect, and permissive version handling would silently reinterpret
future contracts.

**Independent Test**: A consumer accepts a known signed fixture and rejects fixtures
with a changed payload, signature, signer, algorithm, version, or malformed field,
without dispatching an effect.

**Acceptance Scenarios**:

1. **Given** a supported plan signed by a trusted key, **When** it is verified, **Then**
   the consumer receives the verified plan and its stable identifier.
2. **Given** a signed plan whose payload changes after signing, **When** it is verified,
   **Then** verification fails before any plan field is trusted for execution.
3. **Given** an unknown contract major version or signature profile, **When** it is
   decoded, **Then** it is denied rather than downgraded, ignored, or sent for approval.

---

### User Story 3 - Reusable Conformance Evidence (Priority: P3)

As a release or adapter maintainer, I can run one versioned conformance corpus against
all implementations and obtain evidence showing which contract versions and edge cases
pass, so portability is measured instead of asserted.

**Why this priority**: macOS is the reference platform, but HelixOS may only claim
portability after an unchanged contract suite passes on another driver.

**Independent Test**: The same committed fixtures and expected results run without
platform-specific branches and produce a machine-readable pass/fail report.

**Acceptance Scenarios**:

1. **Given** the committed positive and negative fixture corpus, **When** it is run on a
   supported platform, **Then** every case produces its declared canonical bytes,
   identifier, and validation result.
2. **Given** a new implementation that changes canonical output, **When** conformance is
   run, **Then** the release gate fails and identifies the first differing fixture.

### Edge Cases

- Object member order and nested member order differ while meaning is identical.
- Strings include empty values, accents, combining characters, emoji, control escapes,
  and non-BMP Unicode characters.
- Integer values are at their accepted minimum and maximum boundaries.
- A numeric value is fractional, non-finite, outside the accepted range, or represented
  in an alternate textual form.
- A resource component is empty, `.` or `..`, absolute, contains a separator, NUL,
  Windows drive/UNC syntax, alternate-data-stream syntax, or a normalization ambiguity.
- A required field is absent, duplicated, null unexpectedly, or has the wrong type.
- An unknown field appears in a security-critical object.
- The contract version is older, newer, truncated, or syntactically invalid.
- The plan identifier, signer key identifier, signature bytes, or signature profile is
  malformed or inconsistent with the payload.
- Verification uses a valid signature from an untrusted key.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define a versioned plan envelope containing every field
  needed to identify the task, lease, intended effect, target resource, preconditions,
  budget, recovery class, verification predicate, validity window, nonce, and fencing
  epoch.
- **FR-002**: The envelope MUST use platform-neutral data types and MUST NOT contain an
  absolute/native path, floating-point value, platform handle, or process-local value.
- **FR-003**: A target resource MUST be represented by an opaque root identifier and an
  ordered list of validated relative components.
- **FR-004**: Resource components MUST reject traversal, separators, absolute/drive/UNC
  syntax, NUL, alternate-data-stream syntax, and normalization ambiguity before a plan
  is accepted.
- **FR-005**: The same valid logical envelope MUST produce byte-identical canonical
  content regardless of source member order, process, architecture, or supported OS.
- **FR-006**: Every effect-bearing field MUST influence the canonical content and plan
  identifier.
- **FR-007**: The plan identifier MUST be derived from the complete canonical unsigned
  envelope using a versioned cryptographic digest profile.
- **FR-008**: A signed envelope MUST bind the canonical unsigned envelope, plan
  identifier, signature profile, and signer key identifier.
- **FR-009**: Verification MUST recompute canonical content and the plan identifier
  before validating the signature and trust decision.
- **FR-010**: Verification MUST deny malformed data, duplicate or unknown
  security-critical fields, unsupported versions/profiles, untrusted signers, invalid
  identifiers, and invalid signatures with typed deterministic errors.
- **FR-011**: Contract compatibility MUST be explicit. Version 1 consumers MUST accept
  only the declared compatible version set and MUST deny all other major versions.
- **FR-012**: The new contract MUST be independently usable and testable without
  replacing the existing MVP-0 pipeline in this feature.
- **FR-013**: A versioned positive and negative conformance corpus MUST be committed and
  MUST be reusable by later macOS, Linux, and Windows adapters without modification.
- **FR-014**: The corpus MUST cover ordering, Unicode, numeric bounds, resource
  validation, version denial, tampering, wrong-key, and malformed-signature cases.
- **FR-015**: Errors, tests, and diagnostics MUST NOT expose private key material,
  secrets, or full sensitive plan content.
- **FR-016**: Dependency and contract versions MUST be pinned in the repository, and the
  research artifact MUST record alternatives and the removal/migration path.
- **FR-017**: The implementation MUST produce the `PLAN-001` acceptance evidence named
  by the HelixOS architecture and conformance catalogue.

### Key Entities

- **Contract Version**: The explicitly supported contract generation and compatibility
  rules used before any other field is trusted.
- **Resource Reference**: An opaque root plus validated relative components, independent
  from host path syntax.
- **Plan Envelope**: The complete unsigned description of the proposed effect and all
  authority, budget, validity, recovery, and verification bindings.
- **Plan Identifier**: The stable content-derived identifier of the canonical unsigned
  plan.
- **Signed Plan Envelope**: The plan plus signer/profile metadata and signature needed by
  a trusted consumer.
- **Conformance Fixture**: A versioned input with expected canonical content, identifier,
  and accept/deny result.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All positive fixtures produce byte-identical canonical content and plan
  identifiers across every CI platform on which the suite runs.
- **SC-002**: 100% of the declared tamper, wrong-key, unsupported-version, malformed
  numeric, and invalid-resource fixtures are denied before a simulated dispatch point.
- **SC-003**: Changing any single effect-bearing field in the mutation corpus changes the
  plan identifier in 100% of cases.
- **SC-004**: At least 100,000 generated valid envelopes complete canonicalization and
  verification without a panic, acceptance of an invalid value, or platform-dependent
  output.
- **SC-005**: On the reference development machine, canonicalization plus identifier
  creation for a representative envelope has p95 at or below 1 ms over at least 10,000
  measured iterations; the benchmark records hardware, OS, build profile, corpus, and
  raw result artifact.
- **SC-006**: Existing workspace tests remain green and the new crate can be removed
  without changing MVP-0 runtime behavior, proving this slice is not a hidden big-bang
  migration.

## Assumptions

- This feature establishes the contract library and evidence only; durable workflow,
  WebAuthn, adapter dispatch, and legacy-pipeline migration are later features.
- Version 1 starts with one supported major version. Backward compatibility is added only
  through an explicit future version policy and fixtures.
- Keys used by tests are deterministic fixtures and are never production credentials.
- macOS arm64 is the reference target, but the first implementation is built on the
  current Windows host and CI must exercise Linux and macOS as they become available.
- The core remains responsible for trust-store and policy decisions; this feature only
  accepts an explicit trusted-key input and returns verification results.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The contract conveys no authority by itself. Unknown input
  is denied, and no verification path may dispatch an effect.
- **Durability and recovery**: This feature has no external effect. Its output becomes a
  prerequisite for later durable transitions; malformed or ambiguous input is rejected.
- **Data and secrets**: Only public verification keys and deterministic test keys appear
  in fixtures. Private production keys and sensitive plan payloads are out of scope.
- **Portability**: Common types contain no OS primitives. The same fixture corpus is the
  required portability evidence.
- **Performance and budgets**: SC-004 and SC-005 define robustness and reference latency;
  no hidden network or model call is permitted.
- **Audit and lifecycle**: Contract/dependency versions, expected fixture hashes, typed
  errors, and `PLAN-001` evidence are committed. Legacy runtime removal or migration is
  explicitly deferred.
