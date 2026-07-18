# PLAN-006 User Story 1 — Human Request to One Retained Root Lease

**Captured**: 2026-07-18

**Branch**: `codex/plan-006-t025-t038-root-issuance`

**Working-tree base**: `d09e8055bc1f529c56bc380d9a7eda5779320872`

**Claim status**: `local-pass; immutable and cross-platform evidence pending`

This result closes the local `PLAN006-REQUEST` implementation slice for T025 through
T038. It covers FR-007 through FR-011, the root-issuance portions of FR-031, FR-032,
FR-035 and FR-036, SC-002, SC-003, and the root-issuance/lost-acknowledgement portion
of SC-007. The complete PLAN-006 durability fault matrix, immutable hosted evidence,
and cross-platform release claim remain pending later tasks.

## Implemented authority boundary

- A root request accepts an `AuthenticHumanRequestGrantV1`, never raw chat text,
  notification content, transport identity, or bearer material. The authentic marker
  can be constructed only by the closed canonical verifier after the request-surface
  purpose/domain signature, current-key status, and exact protected fields pass.
- The current human context is matched against issuer, audience, principal, exact
  message digest, channel, session, scope-template identity/digest/generation, and
  half-open validity before a lease signer or writer is invoked.
- Root bounds are the checked intersection of the authentic grant context, current
  scope/policy/catalogue observations, and the requested ceiling. Widening, stale
  observations, source non-currency, deadline equality, and signing failure stop
  before the SQLite writer.
- The signed candidate is constructed before the writer. One `BEGIN IMMEDIATE`
  transaction re-verifies clock, current key/trust/scope/revocation state and retains
  the exact grant wire, issuer-scoped one-shot claim, exact root lease wire, initial
  usage, attempt, generations, and redacted event.
- A stable retry reads the original complete graph and returns the original retained
  bytes without persisting the losing candidate or re-signing in the writer. Changed
  stable input retains one conflict attempt/event/tombstone and no second authority
  chain.
- Commit uncertainty transfers linear one-readback custody only after abandoning the
  writer connection. The lost-acknowledgement test reopens a fresh admitted connection,
  reconstructs the exact complete graph once, and does not reissue or re-sign.
- Key IDs are create-only. Rotation uses a distinct ID; an old key remains available
  only for historical verification. Current signer, grant and scope revocation checks
  happen again inside the root transaction before consumption.

## Exact local validation

Host and toolchain:

| Component | Exact identity |
|---|---|
| Host | `macOS 26.5.2 (25F84)`, Darwin `25.5.0`, `arm64` |
| Rust | `rustc 1.96.1 (31fca3adb 2026-06-26)` |
| Cargo | `cargo 1.96.1 (356927216 2026-06-26)` |
| Rust host / LLVM | `aarch64-apple-darwin` / `22.1.2` |
| Python | `3.9.6` |

The final default commands completed successfully:

```sh
cd kernel
cargo fmt -p helix-task-authority-contracts \
  -p helix-task-authority \
  -p helix-task-authority-sqlite -- --check
cargo test --locked -p helix-task-authority-contracts --all-targets
cargo test --locked -p helix-task-authority --all-targets
cargo test --locked -p helix-task-authority-sqlite --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked \
  -p helix-task-authority-contracts \
  -p helix-task-authority \
  -p helix-task-authority-sqlite \
  --all-targets -- -D warnings
cd ..
git diff --check
```

Final counts:

| Package / suite | Result |
|---|---:|
| `helix-task-authority-contracts` all targets | 71 passed |
| HumanRequestGrant contract | 6 passed |
| root TaskLease contract | 6 passed |
| US1 canonical fixture oracle | 2 passed |
| `helix-task-authority` all targets | 39 passed |
| core request/currentness integration | 6 passed |
| `helix-task-authority-sqlite` default all targets | 68 passed, 3 controlled profiles ignored |
| SQLite root contract integration | 9 passed |
| complete locked workspace, all targets | exit 0 |
| strict Clippy | exit 0 |
| scoped format and diff checks | exit 0 |

The three controlled SC-003 commands were also run explicitly, one at a time:

```sh
cd kernel
cargo test --locked -p helix-task-authority-sqlite --test contention \
  ten_thousand_sequential_retries_return_identical_bytes \
  -- --ignored --exact --nocapture
cargo test --locked -p helix-task-authority-sqlite --test contention \
  one_hundred_rounds_of_sixty_four_threads_return_identical_bytes \
  -- --ignored --exact --nocapture
cargo test --locked -p helix-task-authority-sqlite --test contention \
  twenty_rounds_of_eight_processes_return_identical_bytes \
  -- --ignored --exact --nocapture
```

| Controlled profile | Result | Test-binary elapsed |
|---|---:|---:|
| 10,000 sequential exact retries | 1 passed | 111.15 s |
| 100 rounds × 64 threads (6,400 retries) | 1 passed | 144.03 s |
| 20 rounds × 8 processes (160 retries) | 1 passed | 0.97 s |

Every returned root envelope was byte-identical to the first retained envelope. Each
profile reopened with exactly one grant, one claim, one root lease, one usage row, and
zero conflict tombstones.

## Canonical fixture identities

The four synthetic public fixtures contain no private key material and have exact
newline-free bytes:

| Fixture | SHA-256 |
|---|---|
| `human-request-grant.protected.jcs` | `76ec465a11d591f9b432898228f665306ac3ca1d692f2e3281c64bd8750aa8d7` |
| `human-request-grant.envelope.jcs` | `ab3a8edd3f5c0db6e1fed4d8e31603e86a3baf55631227de8c9a666a515d59a6` |
| `root-task-lease.protected.jcs` | `f016a5887bbeb08733933c5a054149fdc84be4c078104d6700b5399e0611f97a` |
| `root-task-lease.envelope.jcs` | `6fb551c2a79e845cd31d8d9423ea0ce7543085bff0658a448989d9233f6f6284` |

The fixture oracle independently checks exact JCS bytes, protected digests, production
Ed25519 verification, the root null-parent/source-grant branch, one-to-one case/outcome
coverage, redaction, and the declared mutation deltas.

## Exact durable mutation and generation deltas

The provisioned test root begins after its three trusted-key bootstrap transitions.
Generation order below is `(store, trust, grant, lease, allocation, counter, event)`.

| Operation | Row delta `(grant, claim, lease, usage, attempt, event, conflict)` | Generations before → after | Outcome |
|---|---|---|---|
| Invalid/widening/stale/expired/revoked before mutation | `(0,0,0,0,0,0,0)` | `(3,3,1,1,1,1,3)` → unchanged | definite refusal/denial |
| First exact current grant | `(+1,+1,+1,+1,+1,+1,0)` | `(3,3,1,1,1,1,3)` → `(4,3,4,4,4,4,4)` | `COMMITTED_RETAINED` |
| Exact stable retry | `(0,0,0,0,0,0,0)` | `(4,3,4,4,4,4,4)` → unchanged | original retained bytes |
| Conflicting grant reuse | `(0,0,0,0,+1,+1,+1)` | `(4,3,4,4,4,4,4)` → `(5,3,4,4,4,4,5)` | `CONFLICT_RETAINED` |

The successful graph is observed either entirely absent or entirely visible. After
first issuance the exact cardinalities are one grant, one claim, one lease, one usage,
four total bootstrap-plus-root attempts, and four total bootstrap-plus-root events.
Exact retry leaves all of those values unchanged. Conflicting reuse leaves the single
authority graph unchanged and adds only its redacted attempt, event, and tombstone.

## Requirement results

| Requirement | Local result and evidence |
|---|---|
| FR-007, FR-008, SC-002 | Closed 17-leaf grant contract, purpose/domain signature tests, forged wire and authenticated-context mutation tests, expiry/historical/revoked cases, redaction oracle, and authentic-marker-only root API all pass. Bare messages and notifications have no constructor or request input and produced zero authority. |
| FR-009, FR-032 | `root_issuance_graph_is_all_absent_or_all_visible_with_exact_generations` and the SQLite unit graph test prove one issuer-scoped claim and one atomic complete root graph. |
| FR-010, SC-003 | Default retry test and all three controlled contention profiles return the same retained bytes with exactly one root chain. Changed stable input creates no second lease. |
| FR-011 | Current/historical key tests, immutable key identity tests, source-currentness precedence, and signer-revocation integration deny new consumption while preserving historical bytes. |
| FR-031 | Exact signed grant/lease wires and digests, claim, derivation link, initial usage, generations, public key history, attempt and event are retained before the result is returned. |
| FR-035 | Closed outcomes distinguish refusal, definite denial, retained conflict, unavailable/ambiguous state and uncertain commit. Simulated lost acknowledgement transfers one fresh exact readback and no second signing or mutation. |
| FR-036 | Trusted injected monotonic samples, exclusive deadline equality, bounded SQLite admission, synchronous immediate transaction, and linear readback custody prevent renewed deadlines or detached post-result mutation. |
| SC-007 (root issuance slice) | Denied paths reopen absent, normal/lost-ack paths reopen as one coherent retained transition, and relational uncertainty remains explicit; duplicate root issuance is zero. The complete all-operation/process-kill boundary matrix remains assigned to T078–T092. |

## Nonclaims and remaining gates

- This result does not create a current projection marker, PLAN-002 eligibility,
  PLAN-004 preparation authority, PLAN-005 dispatch authority, or any host effect.
- `current_authority_marker_returned` remains `false` in every US1 fixture outcome.
  Retained signed evidence is not itself positive runtime authority.
- The process profile is contention evidence, not a process-kill or physical power-loss
  test. Full SC-007, backup/restore, corruption, migration, removal and durability gates
  remain later PLAN-006 work.
- These deterministic synthetic keys and fixtures are conformance-only. They make no
  production key-custody, user-verification, Tier 1, physical-M4, or immutable-CI claim.
- The overall catalog claim remains `pending-evidence` until the required immutable and
  cross-platform artifacts bind an exact release commit.
