# Contract: Preparation Recovery Provider v1

**Contract ID**: `helixos.preparation-recovery-provider/1`
**Status**: design contract; implementation pending

## 1. Purpose and trust boundary

The recovery provider prepares evidence before `PREPARING` for an authenticated
compensable plan. It is a separate durability domain from the replay store, supervisor
and coordinator database. Its receipt is immutable evidence, not compensation,
preparation, dispatch or adapter authority.

Provider implementations are trusted host wiring. The agent cannot select a root,
profile, evidence class, provider generation, material identity or guard.

## 2. Interface

Semantic Rust sketch:

```rust
pub trait RecoveryProviderV1: Send + Sync {
    type PublicationGuard: RecoveryPublicationGuardV1;

    fn acquire_publication_guard(
        &self,
        input: &RecoveryBindingV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard>;

    fn prepare_and_publish(
        &self,
        guard: &mut Self::PublicationGuard,
        input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1;

    fn verify_published(
        &self,
        guard: &mut Self::PublicationGuard,
        receipt: &RecoveryMaterialReceiptV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1;
}
```

Cleanup uses a mutually exclusive `RecoveryCleanupGuardV1` for the same material/
operation namespace. Publication and cleanup guards use cross-process semantics
attested by provisioning; a process mutex alone is insufficient.

Maintenance wiring additionally implements a closed `RecoveryMaintenanceProviderV1`
surface for provider-wide guard acquisition, strict package/tombstone enumeration,
exact orphan reconciliation, idempotent retirement, canonical backup export, empty-root
restore import and independent `RecoveryRootMetadataV1` publication/verification. These
operations accept only trusted maintenance custody and never agent-selected roots,
identifiers or profiles. Backup cannot claim a complete reference set unless provider
enumeration and coordinator/quarantine reconciliation agree.

## 3. Approved profile

`RecoveryProviderProfileV1` binds:

- bounded profile ID;
- profile version `1`;
- provider ID and generation;
- evidence class;
- capability binding digest;
- approved at-rest profile ID;
- create-only staging support;
- synchronized file/object support;
- no-clobber same-volume publication support;
- closed maximum material/capacity bounds.

`SYNTHETIC_CONFORMANCE` proves protocol behavior only. A production compensability
claim requires a separately reviewed evidence class with retained durability,
corruption, backup and clean-restore evidence. Unknown/unapproved class denies.

## 4. Binding input

The provider receives a restricted, non-serializable view containing:

- plan/operation/preparation-attempt identities;
- target reference and authenticated precondition identity/digest/length;
- recovery class, atomicity, expected preimage digest and reserved capacity;
- provider profile/generation/capability binding;
- boot, instance and fencing epochs;
- caller absolute monotonic deadline.

It never receives an agent-selected native path. The trusted platform provider obtains
source bytes through its own mediated capability. The portable synthetic provider uses
reviewed public test bytes only.

## 5. Manifest-last publication protocol

For compensation, while holding the publication guard:

1. Derive an opaque material identity from a domain-separated encoding of the complete
   binding. Do not use a native path as identity.
2. Generate one fresh publication-attempt ID.
3. Create staging with exclusive create/no-clobber semantics.
4. Write exactly the authenticated preimage length; synchronize data/metadata according
   to the approved profile.
5. Close, reopen and verify exact content digest and length.
6. Verify actual/preallocated capacity is at least the signed reserved bytes.
7. Publish material to its deterministic final identity without overwrite.
8. Create a canonical closed manifest, synchronize it and publish it last without
   overwrite.
9. Reopen final material and manifest and verify every binding.
10. Return `RecoveryMaterialReceiptV1` and retain the guard through coordinator
    commit/readback.

The complete verified final manifest is the publication point. Staging or material
without the final manifest is non-authoritative and quarantined.

No portable directory-fsync, power-cut, sector-loss, snapshot or secure-erasure claim
is made. Evidence states the provider profile and exact tested failure class.

## 6. Receipt fields and validation

The immutable receipt binds:

- contract version, provider-profile ID/version and evidence class;
- provider ID/generation, approved at-rest profile and capability binding;
- plan, operation and preparation attempt;
- target reference digest and precondition identity/digest/length;
- recovery class and atomicity;
- actual material digest/length and reserved capacity;
- material and publication-attempt identities;
- manifest digest and fixed state `PUBLISHED`;
- boot, instance and fencing epochs.

Final verification requires exact equality with the authenticated plan and final
context. The coordinator verifier also requires `material_digest = precondition_digest`
and exact equality between receipt `reserved_capacity`, the signed recovery-byte bound
and the held budget reservation. It reopens the published pair under the retained guard
and proves it is present, complete, non-retired and approved.

Missing, temporary, extra, stale, truncated, corrupt, substituted, differently bound,
undersized, unpublished or retired material returns a closed nonpositive result.

## 7. Irreversible plans

An irreversible plan may proceed only when PLAN-001 already proves:

- `risk_level = L2`;
- `recovery_class = IRREVERSIBLE`;
- no preimage digest;
- the authenticated atomicity value.

The coordinator records `IrreversibilityEvidenceV1 { no_material: true }`. It does not
call this provider and cannot fabricate a recovery receipt. A failed compensable case
cannot be reclassified; it requires a new L2 signed plan.

## 8. Orphan and ambiguity semantics

- Publication before coordinator commit may leave material without an operation.
- Material alone never creates or proves an operation.
- Commit uncertainty keeps the publication guard until immediate readback completes;
  unresolved material becomes `QUARANTINED`.
- Time-based expiry or one observed absent operation is not cleanup proof.
- Any unavailable/unhealthy coordinator view retains quarantine.

## 9. Retirement protocol

Recovery bytes have two mutually exclusive retirement eligibility paths:

- **operation-bound**: the matching operation is durably `FAILED`, its exact budget is
  reconciled and no active/in-flight authority or backup pin remains;
- **true orphan**: one healthy guarded coordinator view proves that no operation,
  attempt, reservation, event, in-flight permit or active ambiguity can reference the
  material, and coordinator quarantine has committed a permanent
  `ORPHAN_RETIREMENT_AUTHORIZED` resolution tombstone. No operation is fabricated.

Maintenance must:

1. acquire the exclusive cleanup guard before any coordinator write/maintenance gate;
2. verify the coordinator store's application/schema/profile and full invariants;
3. prove the selected eligibility path and no conflicting active authority or backup
   pin references the material;
4. verify the matching provider manifest and current generation;
5. for operation-bound material, commit coordinator recovery state
   `PUBLISHED -> RETIREMENT_PENDING`; for a true orphan, require the already committed
   permanent quarantine resolution in `ORPHAN_RETIREMENT_AUTHORIZED`; both bind a fresh
   retirement ID while retaining original receipt/digest/length;
6. retire the provider bytes idempotently and publish an immutable retirement manifest;
7. commit coordinator state `RETIREMENT_PENDING -> RETIRED_TOMBSTONE` with the exact
   retirement-manifest digest;
8. retain both coordinator and provider tombstones indefinitely.

Failure before step 5 keeps published material. A crash after step 5 is an explicit
reconciliation state: if bytes remain, maintenance may finish retirement; if the exact
provider tombstone exists, it may finish coordinator recording; otherwise it remains
quarantined. `RETIREMENT_PENDING` blocks backup. A compensable `PREPARING` operation
must always remain `PUBLISHED`; only `FAILED` may enter retirement. Physical secure
erasure is not claimed, and an identifier is never reused. A true orphan never appears
in operation, transition, reservation or event tables.

## 10. Backup and restore membership

A quiescent backup holds a provider-wide maintenance guard, refuses any
`RETIREMENT_PENDING` evidence and emits one canonical recovery inventory. Entries are
grouped by retained provider-profile ID/version, provider ID/generation, evidence class
and at-rest profile so one store backup can cover provider rotation. Groups are strictly
sorted/unique by `(provider_profile_id, provider_id, provider_generation)`; entries
inside each group are sorted by lowercase `package_binding_sha256`, strictly increasing
and unique. Runtime validation checks every group count, the total checked sum, rejects
duplicate groups/bindings and verifies the canonical digests below.

### 10.1 Byte-exact package binding

The following helpers are normative:

```text
str(x)        = u16be(byte_length(UTF8(x))) || UTF8(x)
u64(x)        = the exactly eight-octet unsigned big-endian encoding of x
digest(x)     = the exactly 32 raw octets decoded from required lowercase SHA-256 hex
opt(None)     = 0x00
opt(Some(d))  = 0x01 || digest(d)
```

All integers are validated in `0..=9007199254740991` before encoding. All identifiers
and enums have already passed their closed ASCII/schema constraints. No JSON spelling,
hex text, native path, platform integer representation or terminating NUL participates.

```text
package_binding_sha256 = lowercase_hex(SHA-256(
  UTF8("HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0") ||
  str(provider_profile_id) ||
  u64(provider_profile_version) ||
  str(provider_id) ||
  u64(provider_generation) ||
  str(evidence_class) ||
  str(at_rest_profile_id) ||
  str(custody) ||
  str(state) ||
  digest(manifest_sha256) ||
  digest(material_sha256) ||
  u64(material_length) ||
  u64(reserved_capacity) ||
  opt(retirement_manifest_sha256)
))
```

`package_binding_sha256` itself is not included in its preimage. For
`MATERIAL_PRESENT`, `retirement_manifest_sha256` is absent and encodes as the one byte
`0x00`. For `RETIRED_TOMBSTONE`, it is present and encodes as `0x01 || digest(value)`;
omission never means skipping the field. The frozen corpus README carries two normative
known-answer vectors:

```text
provider_profile_id="p", provider_profile_version=1,
provider_id="r", provider_generation=1,
evidence_class="SYNTHETIC_CONFORMANCE", at_rest_profile_id="a",
custody="OPERATION_BOUND", manifest_sha256=0x11 repeated 32 times,
material_sha256=0x22 repeated 32 times, material_length=3, reserved_capacity=3

state="MATERIAL_PRESENT", retirement_manifest_sha256 absent
  -> 85e7d004e1847040a09dcd23c04ce08e6c823adaf6661e38cfde4a7fd0e58e10

state="RETIRED_TOMBSTONE", retirement_manifest_sha256=0x33 repeated 32 times
  -> 2e4ecdaa0804d619187dd055004e687563ea8242f01dc6c92eacaf9181094838
```

### 10.2 Canonical inventory and top-level manifest digests

```text
jcs_sha256(value) = lowercase_hex(SHA-256(RFC8785(value)))
```

The standalone recovery inventory file contains exactly the RFC 8785 UTF-8 bytes of the
complete `helixos.recovery-snapshot/1` object: no BOM, prefix, suffix, insignificant
whitespace or trailing newline. Duplicate object keys are rejected before schema
validation. `inventory_sha256 = jcs_sha256(complete recovery-snapshot object)`;
`inventory_sha256` is not a member of that standalone object and is carried by the
top-level manifest summary, avoiding self-reference.

The top-level manifest file likewise contains exactly the RFC 8785 UTF-8 bytes of the
complete `helixos.preparation-backup/1` object.
`top_level_manifest_sha256 = jcs_sha256(complete preparation-backup object)`; neither
that digest nor the detached attestation is a member of the object. The protected
attestation field must equal this digest exactly. The signature input remains
`UTF8("HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0") || RFC8785(protected)`; the
attestation envelope and signature are not included in the top-level digest.

For both JSON files, decoding rejects duplicate keys and malformed JSON, validates the
closed schema and cross-field invariants, canonicalizes under RFC 8785, requires stored
bytes to equal those canonical bytes exactly, then hashes those exact bytes.

`complete_reference_set=true` covers every coordinator operation reference, active
quarantine package and provider-enumerated published/tombstone package. Each entry has
closed custody `OPERATION_BOUND`, `QUARANTINED_ORPHAN` or
`ORPHAN_RESOLUTION_TOMBSTONE`; unrecorded extras must first become durable quarantine.
Any orphan retirement authorization still awaiting its provider tombstone blocks the
cut.

The top-level counts `operation_retirement_pending` and
`orphan_retirement_pending` are both fixed to zero. The closed decoder cross-validates
them against coordinator recovery evidence, coordinator quarantine, provider
enumeration and inventory `no_retirement_pending=true`; any disagreement blocks backup.

For `MATERIAL_PRESENT`, backup exports and verifies the immutable material plus original
manifest. For `RETIRED_TOMBSTONE`, it exports the immutable retirement manifest and
retained original digest/length evidence but does not require deleted material bytes.
The top-level preparation manifest binds the standalone inventory digest, provider
generations and entry count. It declares that a detached provenance attestation is
required. After publishing the manifest, the provisioner signs
`HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0 || JCS(protected)` and publishes the
closed attestation envelope last with no-clobber semantics. The protected payload binds
the exact manifest digest, opaque source root/instance identities, coordinator and
recovery generations, inventory digest/counts, at-rest profile and signing profile/key
identity. Raw key material never enters this contract.

Restore requires new empty approved roots and pinned provisioner trust/revocation
configuration. It verifies the detached signature and every protected binding before
publishing either root, verifies each material/tombstone entry, and cross-checks every
coordinator/quarantine/provider reference. Coordinator and recovery metadata then
independently publish the same restore identity, attestation digest and
`RESTORE_PENDING`; disagreement or one-root-only publication quarantines. Ordinary
open, prepare and retirement deny, and Feature 004 cannot activate either root. Missing,
extra, duplicate, unsorted, count-mismatched, unknown or coherently substituted package
evidence quarantines the restore. Old material never reactivates old `PREPARING`
authority.

Before its first provenance decision, restore acquires linear custody of the exact
provisioner trust generation used for verification. Once the package is accepted, it
retains that custody through all destination mutations, refusal quarantine,
root-custody release and PAUSE release.
Every revocation, key rotation, profile replacement or other trust update MUST serialize
behind this custody and may proceed only after it is dropped. A sampled recheck before a
mutation is not a conforming substitute because it leaves a TOCTOU window.

The sovereign PAUSE authority owns a durable begin-or-resume restore ticket. Its exact
attempt binding is SHA-256 over
`HELIXOS\0PREPARATION-RESTORE-ATTEMPT-BINDING\0V1\0`, followed in order by ten raw
32-byte digests: attestation, top-level manifest, recovery inventory, source coordinator
root, source recovery root, source instance, coordinator schema, coordinator database,
provisioner coordinator-destination reservation, and provisioner recovery-destination
reservation. These are followed by the at-rest profile UTF-8 byte length as one unsigned
64-bit big-endian integer and then the exact profile bytes. The two destination bindings
are provisioner-owned opaque reservation identities, not filesystem paths or portable
claims derived from inode metadata. An exact repeat returns the same restore identity,
coordinator root identity and recovery root identity; any different package or physical
destination contends without mutating a second root.

The acquired PAUSE custody is also the provisioner-owned namespace custody for those
two reservation identities. For its complete lifetime it MUST serialize revocation of
the ticket and any rename, replacement, remount or rebinding of either physical
destination; a check-then-release or check-only token is insufficient. Coordinator
SQLite may open its reserved member by native path only while this custody and the
root-local lease are both retained. Windows path preflight uses the high-resolution
volume serial plus 128-bit file ID and never falls back to creation time or attributes,
but stable Rust cannot derive that identity from an already-retained handle. Therefore
the v1 clean-root restore acceptance path returns `RESTORE_PLATFORM_UNSUPPORTED` on
Windows before package capture, PAUSE acquisition or destination mutation. Windows
support requires a later reviewed handle-bound custody implementation; path re-open is
not promoted to equivalent evidence.

The restore identity is SHA-256 over
`HELIXOS\0RESTORE-IDENTITY\0V1\0 || attestation_sha256 || restricted_attempt_nonce`,
where the nonce is a fresh provisioner-restricted 32-byte value retained by the durable
ticket. Resume classifies an existing destination under custody: absent DB imports;
exact imported `ACTIVE` continues; exact `RESTORE_PENDING` is never overwritten or
transitioned again; any other state quarantines. Recovery package import and pending
metadata publication are exact-repeat idempotent by package/ticket binding. Any refusal
after a destination starts persists quarantine while PAUSE and all available root
custodies are still held.

Frozen v1 known-answer vectors:

- attempt binding: digests `[00*32, 01*32, ..., 09*32]`, profile
  `at-rest.synthetic-v1`, preimage length `395`, expected SHA-256
  `8aa11233c25a272e7fbe2ca85b52b29fda269434eeaab673a80512b6531af0e9`;
- restore identity: attestation `aa*32`, nonce `bb*32`, preimage length `92`, expected
  SHA-256 `f5579b4ce91922d67bb19920dfd866e543bcd88b34dad1393402433f8f18ef76`.

The v1 package tree is also closed. The root contains exactly
`coordinator.sqlite3`, directories `published`, `staging`, and `recovery-packages`, and
no other member. `published` contains exactly `preparation-backup.json`,
`recovery-inventory.json`, and `provenance-attestation.json`. `staging` is empty or
contains only the same three names as crash leftovers; every present leftover must be
byte-identical to its published member (a hard link is permitted but not required).
`recovery-packages` contains exactly one zero-padded lowercase 16-hex directory per
inventory entry, numbered from `0000000000000000` in canonical provider-set then
package-binding order. A `MATERIAL_PRESENT` directory contains exactly `manifest.json`
and `material.bin`; a `RETIRED_TOMBSTONE` directory contains exactly
`retirement-manifest.json`. Missing, extra, renamed, permuted, wrong-state, divergent
staging, symlink, special-file, non-UTF-8, digest or length mismatch quarantines before
destination mutation.

Across the complete inventory, `manifest_sha256` is globally unique. This is stricter
than package-binding uniqueness: two entries with different provider/package bindings
cannot reuse identical manifest bytes. The coordinator and quarantine reference model
uses that digest as its immutable recovery key, so the canonical finalizer and decoder
both reject such a duplicate before a backup can be published.

Package acceptance is resource bounded before content hashing or destination mutation.
The closed v1 limits are at most 132 descendant directories, 256 regular files, three
relative path components, 64 MiB per regular file and 256 MiB across all regular files.
A count, depth, individual length or checked aggregate length above its limit is an
invalid package and follows the same pre-mutation package-quarantine path. Sparse files
are bounded by their logical length; the implementation never relies on allocated-block
size to admit an oversized member.

## 11. Data protection and diagnostics

- Material and manifests are at least as restricted as source data.
- Production roots require an approved encrypted-at-rest provisioning profile.
- No key bytes, native paths, material content, identifiers, digests, provider errors or
  user-bound values appear in public errors/events/metrics/evidence.
- Agent/model workloads, Graphify and egress never receive material or private receipt
  values.
- V1 has no automatic pruning. Material is retained while PREPARING, ambiguous or
  quarantined; retirement follows section 9 and leaves a permanent tombstone.

## 12. Required conformance cases

- exact compensable positive under synthetic conformance profile;
- authenticated L2 irreversible positive with zero provider call;
- missing, short, extra, corrupt, substituted, stale, unpublished and retired material;
- provider/evidence class/generation/capability mismatch;
- capacity exact, minus one and plus one;
- process kill at each create/write/sync/verify/material-publish/manifest-publish/
  readback boundary;
- publication versus cleanup contention and fixed lock order;
- commit absent/exact/ambiguous orphan handling;
- backup/restore membership mismatch;
- crashes before/after true-orphan resolution and provider retirement, with no fabricated
  operation;
- coherent package substitution, absent/early/bad detached attestation, unknown or
  revoked signing profile/key and altered signed binding;
- one-root-only pending metadata, restore-ID/attestation mismatch and ordinary open/
  prepare/retirement denial while pending;
- redaction sentinels;
- explicit labels preventing synthetic/process-kill evidence from becoming production/
  power-loss claims.
