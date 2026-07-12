# Durable preparation v1 conformance corpus

This directory is the closed, language-neutral corpus for Feature 004 durable
preparation. It freezes the authoritative section 6.1 first-failure taxonomy, the
section 14 fault-boundary registry, recovery package-binding byte encodings and the
redacted expectations consumed unchanged on macOS arm64, Linux x64 and Windows x64.

The corpus is synthetic conformance evidence only. It is not approval, replay
admission, compensation authority, a budget reservation, a prepared marker, dispatch
authority, a backup activation decision or permission to perform a host effect.

Normative sources:

- `specs/004-durable-preparation/contracts/authority-compare-v1.md`, especially
  section 6.1;
- `specs/004-durable-preparation/contracts/recovery-provider-v1.md`, especially
  sections 10.1 and 10.2; and
- `specs/004-durable-preparation/contracts/durable-preparation-v1.md`, especially
  sections 6, 8 and 14.

## Frozen artifacts and counts

| File | Role | Rows | SHA-256 |
|---|---|---:|---|
| `cases.json` | Closed cases, encodings, KATs and 123-boundary registry | 335 cases | `086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d` |
| `expected-outcomes.json` | Redacted executable expectation projection | 335 cases | `87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b` |

The case inventory contains exactly:

- 150 independent section 6.1 leaves across 45 contiguous normative rows;
- 91 leaves that participate in both captures;
- 241 single-fault cases: two for each double-capture leaf and one for each other
  leaf;
- 91 later-row ordering cases, one for each double-capture leaf;
- 3 positive controls: compensable, authenticated L2 irreversible with zero recovery
  provider calls, and exact replay with an unrelated global-generation advance;
- 2 package-binding known-answer vectors; and
- 123 unique section 14 boundary IDs in nine ordered phases.

An `or`, slash or relational alternative internal to one comma-separated section 6.1
leaf is one closed fault class. For example, `differs/unavailable`, `corrupt/unknown`
and `sampled >= bound` are each one leaf. Every comma-separated field or fault is an
independent leaf. This rule yields the frozen per-row leaf counts:

```text
5,1,2,2,7,1,2,2,1,2,1,1,3,3,2,2,3,2,4,4,7,1,5,1,3,1,6,1,1,1,7,4,4,6,5,9,10,3,5,1,7,1,1,1,9
```

Both JSON artifacts are exact UTF-8 RFC 8785 JCS bytes: no BOM, prefix, suffix,
insignificant whitespace or trailing newline. Duplicate members, unsafe integers,
unknown fields/tokens, unsorted or duplicate IDs and noncanonical bytes reject the
complete corpus. Case rows are strictly ASCII-sorted by `case_id`; boundaries are
strictly ordered by numeric `order` and unique by `boundary_id`.

## `cases.json` closed shape

The top-level object contains exactly `cases`, `counts`, `domain_encodings`,
`fault_boundaries`, `package_binding_kats` and `schema`. The schema is exactly
`helixos.durable-preparation-cases/1`.

Each preparation case contains exactly:

```json
{
  "case_id": "leaf-r06-l01-capture-generation-final",
  "case_kind": "single-fault",
  "expected_code": "PREPARATION_CONTEXT_MISMATCH",
  "expected_outcome": "denied",
  "fault_phase": "final",
  "normative_row": 6,
  "primary_fault": "capture-generation-differs",
  "profile": "synthetic-compensable-v1",
  "secondary_fault": "none"
}
```

Closed rules:

- `case_id` matches `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, is at most 96 ASCII bytes,
  is unique and never contains a runtime identifier, path, digest or platform label;
- `case_kind` is `positive-control`, `single-fault` or `ordering`;
- `fault_phase` is `positive`, `preliminary`, `final`, `recovery`, `store` or
  `readback`;
- `normative_row` is `0` only for positive controls and otherwise is `1..=45`;
- `profile` is `synthetic-compensable-v1` or `synthetic-irreversible-v1`;
- a single-fault or positive case has `secondary_fault:"none"`; an ordering case
  combines the named primary fault with the first reviewed leaf in a strictly later
  normative row; and
- the runner exhaustively maps public mutation tokens. No token contains native SQL,
  a path, provider diagnostics, environment selection or private data.

For each of the 91 double-capture leaves there is one preliminary single fault with
zero recovery calls and one final single fault introduced after manifest-last
publication. Ordering cases are final except the six row-34-before-row-35 cases, which
are preliminary: recovery profile approval must win before the Phase B publication
failure can occur. Those six cases have zero recovery calls and no recovery quarantine;
other final ordering denials retain non-authoritative quarantine custody. The primary
row always wins and the permanent replay claim is never released.

Row 1 is phase-frozen rather than inferred by a runner: API and internal input version
faults are preliminary; context version is the row's sole double-capture leaf; receipt
and irreversibility version/enum faults are recovery/final validation cases. Rows 2..34
participate in both captures except row 14, whose live-guard faults exist only after
recovery publication.

## Stable expected projection

`expected-outcomes.json` has exactly `cases` and `schema`, with schema
`helixos.durable-preparation-summary/1`. Each sorted case row contains exactly:

```json
{
  "case_id": "leaf-r06-l01-capture-generation-final",
  "code": "PREPARATION_CONTEXT_MISMATCH",
  "event_generation_delta": "zero",
  "operation_generation_delta": "zero",
  "outcome": "denied",
  "recovery_may_remain_quarantined": true,
  "recovery_provider_calls": {"acquire":1,"prepare":1,"total":3,"verify":1},
  "replay_claim_released": false,
  "reservation_generation_delta": "zero"
}
```

Generation deltas are closed values `zero`, `one` or `zero-or-one`. Only a prepared
positive result is `one`. A pre-commit denial/definite failure is `zero`. A row-45
commit/readback ambiguity is `zero-or-one`; it must never be rewritten as definite
absence. `recovery_provider_calls.total` is exactly the checked sum of `acquire`,
`prepare` and `verify`. Preliminary operation/budget denials are all zero-call cases.
Authenticated L2 irreversibility is also zero-call. `replay_claim_released` is always
false.

The outcome/code ownership is closed: rows 1..34, 36 and 37 are `denied`; rows 35 and
39..44 are `failed`; rows 38 and 45 are `ambiguous`; positive controls are `prepared`
with `code:"NONE"`.

## Normative package-binding encoding

The machine-readable `domain_encodings.package_binding` object freezes this exact
preimage order:

```text
UTF8("HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0") ||
str(provider_profile_id) || u64(provider_profile_version) ||
str(provider_id) || u64(provider_generation) || str(evidence_class) ||
str(at_rest_profile_id) || str(custody) || str(state) ||
digest(manifest_sha256) || digest(material_sha256) ||
u64(material_length) || u64(reserved_capacity) ||
opt(retirement_manifest_sha256)
```

The helpers are byte exact:

- `str(x) = u16be(byte_length(UTF8(x))) || UTF8(x)`;
- `u64(x)` is exactly eight unsigned big-endian octets after validation in
  `0..=9007199254740991`;
- `digest(x)` is exactly 32 raw octets decoded from required lowercase SHA-256 hex;
- `opt(None) = 0x00`; and
- `opt(Some(d)) = 0x01 || digest(d)`.

No JSON spelling, hex text, native path, NUL terminator or platform integer layout is
part of the preimage. `package_binding_sha256` itself is excluded.

The two normative KATs share profile `p/1`, provider `r/1`, evidence class
`SYNTHETIC_CONFORMANCE`, at-rest profile `a`, custody `OPERATION_BOUND`, manifest
digest byte `0x11` repeated 32 times, material digest byte `0x22` repeated 32 times,
length `3` and reserved capacity `3`:

| State | Optional retirement digest | Preimage bytes | Expected SHA-256 |
|---|---|---:|---|
| `MATERIAL_PRESENT` | absent (`00`) | 207 | `85e7d004e1847040a09dcd23c04ce08e6c823adaf6661e38cfde4a7fd0e58e10` |
| `RETIRED_TOMBSTONE` | `0x33` repeated 32 (`01 || digest`) | 240 | `2e4ecdaa0804d619187dd055004e687563ea8242f01dc6c92eacaf9181094838` |

The corpus carries each full expected preimage as lowercase hex, so implementations
must match the bytes before matching the final digest.

## Canonical JSON and provenance domains

`domain_encodings` also freezes:

- `inventory_sha256 = lowercase_hex(SHA-256(RFC8785(complete recovery snapshot)))`;
- `top_level_manifest_sha256 = lowercase_hex(SHA-256(RFC8785(complete preparation
  backup manifest)))`; and
- detached signature input
  `UTF8("HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0") || RFC8785(protected)`.

The inventory digest is not a member of the standalone inventory. The top-level digest
is not a member of the top-level manifest. Neither the detached envelope nor signature
is included in the top-level digest.

## Closed fault-boundary registry

Each boundary row contains exactly `boundary_id`, `expected_registry_occurrences`,
`multiplicity`, `order`, `owner`, `phase` and `prepared_success_occurrences`. `owner` is
`portable` or `coordinator`;
`expected_registry_occurrences` is always `1` and proves one exact taxonomy entry.
`multiplicity` is one of the closed classes `unit`, `preliminary-groups`,
`final-guards`, `final-groups`, `commit-members`, `material-packages`,
`retirement-tombstones` or `restore-packages`; it never mixes strings and numbers.
`prepared_success_occurrences` is the exact integer reached on one successful
compensable preparation: normally `0` or `1`, with fixed repeated values `12`, `10`,
`12` and `8` for the four corresponding repeated classes. Mutually exclusive permit
and readback alternatives are `0`. Backup/restore package classes use external checked
cardinalities `M`, `T` and `P` when deriving their phase executions, while their
preparation-success count remains `0`. The exact phase registry counts are:

| Phase | IDs |
|---|---:|
| `preliminary` | 10 |
| `recovery` | 13 |
| `final-comparison` | 14 |
| `positive-coordinator-commit` | 15 |
| `acknowledgement-and-readback` | 12 |
| `known-failure` | 12 |
| `quarantine-and-retirement` | 10 |
| `backup` | 23 |
| `restore` | 14 |

These 123 rows are the independent slash-action expansion of durable-preparation
contract section 14. `each ...` actions have one stable boundary ID whose controlled
runner occurrence counter selects the desired member/package/guard occurrence. A new,
removed, duplicate or renamed boundary is contract and corpus drift.

One successful compensable `Prepared` path reaches exactly 93 checkpoints after fixed
multiplicities and mutually exclusive commit/readback alternatives are applied. A
successful backup reaches `21 + M + T`; a successful restore reaches `13 + P`.

## Verification procedure

Run the portable drift checker from `kernel/`:

```sh
cargo run --locked -p helix-coordinator-sqlite --example durable_preparation_corpus
```

Its canonical redacted summary has SHA-256
`e0dac29c01276a7f6168a83bff51accefc86a129f1046065ebea5f136bbddd87`.

1. Strictly decode both files, rejecting duplicate members before schema checks.
2. Require exact RFC 8785 bytes, no BOM/newline, the pinned SHA-256 values above and
   the closed top-level/member sets.
3. Verify all counts, the 45-row leaf vector, ASCII ordering/uniqueness, 91 complete
   preliminary/final/ordering triples and exact later-row precedence.
4. Recompute both package-binding preimages and SHA-256 results from the normative
   helpers; never hash JSON text.
5. Compare the 123 boundary rows byte-for-byte with the private closed taxonomies and
   require each ID exactly once.
6. Execute every preparation case using only reviewed synthetic wiring, project only
   the expected redacted fields, canonicalize, and compare exact bytes and SHA-256.
7. Fail on any unexecuted case, unexpected provider call, generation drift, replay
   release, positive ambiguous result or platform-specific selection.

The files contain no real plan, operation, attempt, task, workload, replay, reservation,
provider or key identifier; no nonce, signature, private digest, material content,
budget value, path, username, hostname or raw error. Process-kill evidence remains
labelled process-kill and synthetic recovery remains conformance-only.

Changing a field, ID, token, count, order, encoding, KAT, outcome, call expectation or
summary byte requires explicit contract review and a new corpus version when
incompatible.
