# Plan eligibility v1 conformance corpus

This directory is the versioned, language-neutral corpus for the in-process
`plan-eligibility-v1` contract. It proves deterministic context construction, current
eligibility, replay-call ordering, stable redacted outcomes, and cross-platform byte
identity. A fixture is evidence only. It is not approval, a durable replay receipt, an
`ExecutionGrant`, or authority to perform a host effect.

The normative sources are:

- `specs/002-plan-eligibility/spec.md` for requirements and measurable acceptance;
- `specs/002-plan-eligibility/contracts/plan-eligibility-v1.md` for evaluation order,
  context-build codes, eligibility denials, replay binding, and summary bytes; and
- `docs/adr/0006-current-plan-eligibility.md` for the trust-boundary decision.

## Frozen corpus files

| File | Role |
|---|---|
| `README.md` | Public v1 format, generation, verification, redaction, and authority rules. |
| `cases.json` | Closed, sorted manifest of the coherent case and every declared single-fault case. |
| `expected-outcomes.json` | Exact RFC 8785 JCS bytes of the four-field public outcome projection. |

`cases.json` and `expected-outcomes.json` are generated/reviewed artifacts delivered by
the later corpus task. They must not be hand-edited after generation. Unknown files do
not extend the v1 contract unless this README and the feature contract explicitly name
them.

## `cases.json` v1 shape

The manifest is a closed JSON object with exactly `schema` and `cases`:

```json
{
  "schema": "helixos.plan-eligibility-cases/1",
  "cases": [
    {
      "case_id": "eligible-coherent",
      "stage": "runtime",
      "profile": "coherent-v1",
      "fault": "none",
      "claimant": "claimed-matching",
      "expected_outcome": "eligible",
      "expected_code": "NONE",
      "expected_claimant_reached": true
    }
  ]
}
```

Each case object contains exactly these fields:

| Field | Closed rule |
|---|---|
| `case_id` | Public stable ASCII token matching `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 96 bytes, unique in the corpus. |
| `stage` | `context_build` or `runtime`. |
| `profile` | Exactly `coherent-v1` for this corpus version. |
| `fault` | `none` or one reviewed public mutation token implemented identically by every runner. |
| `claimant` | One of the closed claimant profiles below. |
| `expected_outcome` | `eligible`, `denied`, or `context_build_denied`. |
| `expected_code` | `NONE`, one frozen context-build code, or one frozen `EligibilityDenialV1::code()`. |
| `expected_claimant_reached` | JSON boolean; it must equal the actual claimant-call probe. |

Unknown or missing fields, duplicate members, non-UTF-8 input, an unknown enum value,
an invalid case ID, or duplicate/unsorted cases reject the entire manifest. Numeric or
free-form expected codes are forbidden.

### Stable case identifiers

`case_id` is the public primary key and must not contain or derive from a runtime plan,
operation, task, workload, key, lease, nonce, resource, path, digest, provider message,
OS, architecture, hostname, or username.

V1 uses these naming families:

- `eligible-coherent` for the sole coherent positive profile;
- `build-<public-fault-token>` for checked context-construction failures;
- `deny-<public-fault-token>` for runtime first-failure cases; and
- a descriptive suffix such as `-at-boundary`, `-before-boundary`, or
  `-after-boundary` when multiple cases intentionally select the same stable code.

Once committed, a case ID is never renamed, reused for different semantics, or selected
conditionally by platform. New compatible cases receive new IDs and the array is sorted
again. Changing the meaning of an existing ID or any closed field creates a new corpus
schema version.

### Closed claimant profiles

| `claimant` | Meaning |
|---|---|
| `not-reached` | The context build or read-only eligibility gate must finish before any claimant call. |
| `claimed-matching` | The deterministic claimant returns a new receipt whose binding digest exactly matches the request. |
| `claimed-wrong-binding` | The claimant is reached but returns a receipt with another binding digest. |
| `already-claimed` | The claimant returns `AlreadyClaimed`. |
| `binding-conflict` | The claimant returns `BindingConflict`. |
| `unavailable` | The claimant returns a definite pre-write `Unavailable` outcome. |
| `ambiguous` | The claimant reports that commit may have occurred. No retry is permitted. |

No claimant profile may expose a raw provider/storage error, sleep, read ambient state,
or select behavior from the host OS.

## Runtime and construction outcomes

The output rules are closed:

| Case class | Required outcome | Required code | `claimant_reached` |
|---|---|---|---|
| Coherent runtime case with `claimed-matching` | `eligible` | `NONE` | `true` |
| Runtime fault in context/admission, time/boot/epochs, authority, policy/catalogue, or capabilities | `denied` | Exact first `EligibilityDenialV1` code | `false` |
| Runtime replay outcome | `denied` | Exact replay denial code | `true` |
| Claimed receipt with wrong binding digest | `denied` | `REPLAY_RECEIPT_BINDING_MISMATCH` | `true` |
| Checked constructor failure | `context_build_denied` | Exact `CONTEXT_BUILD_*` code | `false` |

The frozen context-build codes are:

```text
CONTEXT_BUILD_INTEGER_OUT_OF_RANGE
CONTEXT_BUILD_INVALID_INTERVAL
CONTEXT_BUILD_INVALID_IDENTIFIER
CONTEXT_BUILD_INVALID_CAPABILITY_SET
CONTEXT_BUILD_LIMIT_EXCEEDED
```

Runtime denial codes and their exact first-failure order are frozen by
`specs/002-plan-eligibility/contracts/plan-eligibility-v1.md`. The manifest must contain
the coherent case plus a single-fault case for every bound fact, exact boundary, terminal
provider state, replay outcome, and receipt-binding mismatch declared there.

## Exact `expected-outcomes.json` bytes

`expected-outcomes.json` is the public projection of the manifest's expectations. Its
top-level object contains exactly `cases` and `schema`; each case contains exactly
`case_id`, `claimant_reached`, `code`, and `outcome`.

The byte-identity format is UTF-8 RFC 8785 JCS. It has:

- no UTF-8 BOM;
- no leading or trailing whitespace;
- no trailing newline;
- no insignificant whitespace;
- object members in RFC 8785 order; and
- case rows sorted uniquely by ASCII `case_id` before canonicalization.

For example, the exact bytes for a one-row summary are:

```json
{"cases":[{"case_id":"public-ascii-token","claimant_reached":false,"code":"PLAN_EXPIRED","outcome":"denied"}],"schema":"helixos.plan-eligibility-summary/1"}
```

The code fence is documentation and therefore includes Markdown line termination. The
artifact itself ends immediately after the final `}` byte. Eligible rows use
`code:"NONE"`. No other outcome or summary field is permitted.

CI compares both the exact bytes and SHA-256 digest of this file. Parsing and comparing
semantic JSON values is insufficient.

## Redaction and synthetic data

All corpus inputs are public synthetic data. The public expected summary contains only
the reviewed case ID, closed outcome, closed stable code, and claimant-reached boolean.
It must never contain:

- plan, operation, task, workload, key, lease, claim, host, or provider identifiers;
- nonce, signature, digest, key bytes, protected plan content, or resource components;
- native paths, usernames, hostnames, OS/architecture labels, timestamps from a real
  machine, or raw expected/actual values; or
- provider, database, filesystem, network, panic, or debug error text.

Sentinel tests must exercise denial, failure, marker, claims, replay, constructor,
`Display`, `Debug`, and error-source surfaces. Adding diagnostic text to the expected
summary is a breaking corpus change and is forbidden for v1.

## No platform selection

Every registered runner consumes every case in the same byte-identical `cases.json` and
compares against the same byte-identical `expected-outcomes.json`. The manifest has no
`os`, `arch`, include, exclude, skip, fallback, or expectation-override field.

Tests must not choose fixtures, mutation values, claimant outcomes, denial codes, or
ordering through `cfg(target_os)`, environment variables, native clocks, path behavior,
or platform metadata. Windows, Linux, and macOS arm64 CI metadata belongs in the
external evidence artifact and `conformance/catalog.yaml`, never in corpus semantics.
An unsupported or failing runner fails the matrix; it does not rewrite or omit cases.

## Deterministic generation procedure

The project-owned generator writes or checks both frozen artifacts without adding a
newline or reading ambient platform state:

```sh
cargo run --locked --manifest-path kernel/Cargo.toml -p helix-plan-eligibility --example eligibility_corpus -- --write-fixtures contracts/fixtures/plan-eligibility-v1
cargo run --locked --manifest-path kernel/Cargo.toml -p helix-plan-eligibility --example eligibility_corpus -- --check-fixtures contracts/fixtures/plan-eligibility-v1
```

1. Freeze the checked context-build codes, `EligibilityDenialV1` codes, total evaluation
   order, replay binding format, and public summary schema before generating files.
2. Build one coherent synthetic `AuthenticPlanEnvelopeV1` and complete trusted
   `EligibilityContextV1` through reviewed constructors. Use only public fixture keys and
   identifiers; never production key material or real host data.
3. For each build case, change exactly one constructor input from the coherent model and
   assert the declared `CONTEXT_BUILD_*` result before an evaluator or claimant exists.
4. For each pre-claim runtime case, change exactly one trusted fact or terminal provider
   status and assert the declared first denial plus zero claimant calls.
5. For replay cases, keep every read-only fact coherent and select exactly one closed
   deterministic claimant profile. A wrong-binding receipt changes only its binding
   digest.
6. Sort manifest rows by ASCII `case_id`, reject duplicates, and serialize `cases.json`
   through RFC 8785 JCS with no BOM or trailing newline.
7. Run every case and project only the four public outcome fields. Sort them by
   `case_id`, serialize with RFC 8785 JCS, and write `expected-outcomes.json` without a
   BOM or trailing newline. Manual editing of the derived file is forbidden.
8. Re-run the generator from a clean checkout and require byte-identical files and
   identical SHA-256 digests before review.
9. Review every input/output for synthetic content and redaction sentinels, then run the
   unchanged corpus on the complete registered platform matrix.

The corpus generator must be a project-owned deterministic test/example added with the
implementation. Until that command exists, no hand-authored placeholder JSON may be
committed merely to satisfy the file names.

## Verification procedure

For each implementation and platform:

1. Read the files as bytes and reject a BOM, trailing newline, non-UTF-8 input, duplicate
   members, unknown fields, unsafe numbers, or noncanonical RFC 8785 bytes.
2. Validate the closed manifest enums, case-ID pattern, case ordering, uniqueness, and
   expected outcome/code/claimant relationships.
3. Reconstruct the coherent model and apply exactly the named single mutation.
4. Record actual outcome, stable code, and claimant probe without rendering trusted
   values or raw errors.
5. Sort and canonicalize the four-field actual summary, then compare its exact bytes and
   SHA-256 digest with `expected-outcomes.json`.
6. Fail on the first byte, code, order, call-probe, redaction, or fixture drift. Never
   update expected bytes automatically during a verification run.

Once the implementation task provides the runner, the targeted verification entry is:

```sh
cd kernel
cargo test --locked -p helix-plan-eligibility --test conformance
```

The complete commands, ignored contention/soak runs, benchmark metadata, and immutable
CI evidence procedure are maintained in
`specs/002-plan-eligibility/quickstart.md`.

## Test claimant versus production durability

The corpus and contention tests use a deterministic thread-safe in-memory claimant. It
must atomically enforce the stable `(instance_epoch, nonce)` namespace and operation
index, compare the full binding, and return a receipt with the exact binding digest. It
proves evaluation order, one process-level linearization point, conflict semantics, and
exactly one winner under contention.

It does **not** prove durable uniqueness across crashes/restarts, multi-process database
coordination, fsync behavior, bounded production completion, ambiguous-commit recovery,
or integration with durable operation state. The local p95 benchmark likewise measures
only evaluation plus the deterministic test claimant.

A conforming production claimant must durably compare/insert both indexes in one
transaction, make claims permanent, honor the monotonic completion deadline, preserve
ambiguous state for reconciliation, and never fall back to process-local memory. The
future durable coordinator, compare-before-prepare transaction, budget/recovery
reservation, signed `ExecutionGrant`, adapter inbox/receipt, and host-effect gates remain
mandatory before Tier 1 or dispatch.

## Authority and versioning

The corpus detects contract drift; it does not define broader authority than the
feature specification and in-process contract. Any change to closed fields, case
semantics, ordering, stable codes, redaction, replay namespace, outcome schema, or exact
summary bytes requires explicit contract review and a new corpus version when
incompatible. Platform-specific expectation patches are never a compatible change.
