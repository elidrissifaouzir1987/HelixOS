# Durable replay store v1 conformance corpus

This directory is the bounded, language-readable corpus for feature 003's production
implementation of `ReplayClaimantV1`. It covers replay outcomes, controlled deadlines,
thread/process contention, process-crash boundaries, initialization, corruption,
maintenance, online backup and clean restore. The same cases and expected summary run
unchanged on Windows x64, Linux x64 and macOS arm64.

The corpus contains no SQLite database, WAL/SHM file, native path, nonce, operation ID,
plan/binding digest, claim ID, credential, user content or provider diagnostic. A runner
constructs every temporary store and public synthetic binding locally from the closed
profiles below. These fixtures are evidence only: no row, receipt, backup or restore
case is approval, preparation, an `ExecutionGrant`, adapter input or host-effect
authority.

Normative sources:

- `specs/003-durable-replay-store/spec.md`;
- `specs/003-durable-replay-store/contracts/durable-replay-store-v1.md`;
- `specs/003-durable-replay-store/data-model.md`; and
- `specs/003-durable-replay-store/quickstart.md`.

## Frozen files and digests

| File | Role | Cases | SHA-256 |
|---|---|---:|---|
| `cases.json` | Closed executable case registry | 68 | `7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff` |
| `expected-outcomes.json` | Redacted expected projection | 68 | `687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac` |

Both JSON files are UTF-8 RFC 8785 JCS with no BOM, leading/trailing whitespace or
trailing newline. Object members and case rows are sorted deterministically. T044's
runner must compare exact bytes and SHA-256, not only parsed JSON equality.

## `cases.json` closed shape

The top-level object contains exactly `cases` and `schema`; `schema` is exactly
`helixos.durable-replay-store-cases/1`. Every case contains exactly:

```json
{
  "action": "claim",
  "case_id": "claim-fresh",
  "category": "claim",
  "expected_code": "CLAIMED",
  "expected_outcome": "claimed",
  "expected_state": "one-complete-claim",
  "fault": "none",
  "profile": "synthetic-v1",
  "setup": "empty-store"
}
```

Closed field rules:

- `case_id` is a unique ASCII token matching
  `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 96 bytes; rows are strictly ASCII-sorted.
- `category` is one of `backup`, `claim`, `contention`, `corruption`, `crash`,
  `deadline`, `initialization`, `maintenance`, `migration`, or `restore`.
- `profile` is exactly `synthetic-v1`.
- `setup`, `action`, and `fault` are reviewed registry tokens. The runner must match
  them exhaustively; no free-form path, SQL, provider text or environment lookup is
  allowed.
- `expected_outcome` is one of `claimed`, `already_claimed`, `binding_conflict`,
  `unavailable`, `ambiguous`, `rejected`, `verified`, or `recovered`.
- `expected_code` is a closed replay outcome, frozen configuration/open/maintenance
  code from the feature contract, or one of the positive corpus codes listed below.
- `expected_state` is one of `no-store`, `empty-store`, `one-complete-claim`,
  `two-complete-claims`, `existing-claim-unchanged`, `commit-unknown`, `healthy-store`,
  `store-unhealthy`, `source-unchanged`, `valid-backup`, or `verified-restore`.

Unknown or missing fields, duplicate JSON members, duplicate/unsorted IDs, an unknown
token, unsafe number, non-UTF-8 input or noncanonical bytes reject the whole corpus.
There is no OS/architecture include, skip, override or alternate expectation field.

## Coverage and boundedness

| Category | Cases | Required evidence |
|---|---:|---|
| backup | 3 | consistent online snapshot, deadline, incomplete staging |
| claim | 15 | fresh/repeat/both conflicts, independent claim, exhaustion, pre-write failure, phase/readback classification |
| contention | 5 | exact and conflicting keys across threads/processes plus independent bindings |
| corruption | 6 | wrong application, altered schema, integrity and row/metadata invariants |
| crash | 10 | every frozen claim and backup publication process-kill point |
| deadline | 6 | already expired, clock unavailable, held writer, pre/post-commit and late readback |
| initialization | 12 | empty/concurrent initialization, checked bounds, location, busy/unavailable store and durability profile |
| maintenance | 2 | full healthy verification and maintenance deadline |
| migration | 1 | explicit refusal of a newer unsupported schema |
| restore | 8 | clean positive restore and every closed package/destination failure |

The 68-row limit is frozen for corpus v1. Stress repetition counts remain in their
dedicated test targets; this manifest names semantic cases once and does not embed a
large generated workload.

Positive corpus-only codes are `STORE_INITIALIZED`, `STORE_VERIFIED`,
`ONE_DURABLE_WINNER`, `ALL_INDEPENDENT_COMMITTED`, `PROCESS_CRASH_RECOVERED`,
`BACKUP_VERIFIED`, and `RESTORE_VERIFIED`. Claim codes are `CLAIMED`,
`ALREADY_CLAIMED`, `BINDING_CONFLICT`, `UNAVAILABLE`, and `AMBIGUOUS`. Every other code
is one of the frozen payload-free configuration, open or maintenance codes in the
feature-003 contract.

## Exact outcome and durable-state rules

- A fresh claim creates one complete row and generation; an exact repeat returns
  `AlreadyClaimed` without advancing either; either occupied incompatible key returns
  `BindingConflict` and leaves the existing row unchanged.
- A definite pre-mutation failure or confirmed rollback is `Unavailable`. Once commit
  may have started, failed/late/inconsistent proof is `Ambiguous`; the mutation is never
  retried. A positive result is forbidden at or after the exclusive boot-monotonic
  deadline.
- Controlled contention produces one durable winner for each contested key. Exact
  losers are already claimed; incompatible losers conflict. Independent bindings may
  both commit.
- Claim crash points through `before-commit` reopen empty; `commit-returned` and
  `before-result-ack` reopen with one complete row. Backup publication is restorable
  only after `backup-published`.
- Corruption and incompatible schema are never repaired by a claim. A failed full
  verification latches the local view unhealthy.
- A valid backup is exactly one canonical `BACKUP_PACKAGE` role file, one quiescent
  verified database and one manifest published last. Restore accepts only a different
  empty destination, remains `RESTORE_PENDING`, and returns evidence requiring external
  `PAUSED` activation, trigger quarantine and new instance/fencing epochs.
  It never proves that claims after the backup generation did not exist.

## `expected-outcomes.json`

The top-level schema is exactly `helixos.durable-replay-store-summary/1`. Each row is the
four-field public projection:

```json
{"case_id":"claim-fresh","code":"CLAIMED","outcome":"claimed","state":"one-complete-claim"}
```

It contains no native or runtime identifier and is sorted exactly like the manifest.
The all-feature `conformance_execution` runner executes all 68 declared
setup/action/fault cases, asserts the public outcome and independently verifies the
durable state before producing this projection.
It fails on the first outcome, state, byte or digest drift and never rewrites
the committed files during verification.

## Runner and review procedure

1. Strictly decode both files with duplicate and unknown fields denied; verify schema,
   case-ID syntax/order/uniqueness, closed enums, JCS bytes and pinned SHA-256.
2. Create a fresh dedicated temporary local root and deterministic injected clock for
   each case. Construct only reviewed public synthetic bindings in the test process.
3. Apply the exact setup, action and one fault named by the registry. Process fixtures
   use the frozen readiness protocol and always kill/reap their children.
4. Reopen through a fresh connection/process where declared, then verify full SQLite
   integrity and the exact redacted durable state. Never infer a result from error text.
5. Project only `case_id`, `code`, `outcome`, and `state`; compare exact canonical bytes
   and digest to `expected-outcomes.json` on every registered platform.
6. Keep process-kill and controlled-lock evidence honestly labelled. This corpus is not
   Mac mini M4 power-loss, `F_FULLFSYNC`, network-filesystem or Tier 1 evidence.

Changing a field, token, case meaning, ordering rule, redaction rule or expected state
requires explicit contract review and a new corpus version when incompatible.
