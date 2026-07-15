# PLAN-004 evidence and supply-chain policy

This directory retains redacted evidence for Feature 004. Unless an artifact is listed
with an immutable commit, digest, platform and preservation URL in
`conformance/catalog.yaml`, its status is **pending evidence**. The immutable software
matrix, exact-lock supply-chain bundle and removal drill now pass for source commit
`69c15001284e613aca534fd8862dd001f9831fdc`; the complete run, artifact, attestation and
independent verification record is retained in
`ci-immutable-69c15001284e613aca534fd8862dd001f9831fdc.md`. Local and hosted synthetic
tests still do not establish production compensability, power-loss durability,
restored-system activation or Tier 1 readiness. A clean local physical-M4 result exists
for exact source commit `f7b021db52503aaedcc59b9c9c8d95d357555352`; it satisfies the local
synthetic latency thresholds but remains local-only execution evidence.

## Retained clean-source local evidence

The following two create-new artifacts were produced by the controlled benchmark from
a detached worktree that was clean at start:

- `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.json`,
  SHA-256 `ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12`;
- `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.recovery-transfer.json`,
  SHA-256 `da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e`.

The coordinator artifact contains 500 warmups, 10,000 raw sorted samples and 10,500
committed operations. It records p50 11,218,708 ns, p95 24,096,375 ns, p99 25,443,666
ns and maximum 26,528,459 ns; the 25 ms p95 and 100 ms p99 limits both pass. The
separate recovery artifact writes and verifies 16 MiB in 66,358,167 ns and is excluded
from coordinator percentiles. See `local-validation.md` for the complete Quickstart
§1–15 results, the first 239-operation dead end and its bounded `data_version`/hot-path
verification correction.

The local explicit-session process-kill release driver also passes all five selected
harness tests, covering 123 real fault boundaries and 167 controlled cases. That local
run remains synthetic and is not power-loss evidence. The final immutable hosted run
independently passes all 167 cases on Linux/macOS and the exact 150 reachable Windows
cases after proving the 17 restore cases refuse before capture. Its three platform
artifacts have uploaded-ZIP digest binding and attestations. The physical-M4 benchmark
execution itself remains local-only even though its two JSON files are retained inside
the attested release bundle.

The hosted run at source commit `b3132586245acea415104381b337d3fea3303444`
identified one Windows harness mismatch after every earlier Windows gate, including the
production restore-refusal oracle and release contention, had passed. The release
process-kill parent attempted a `restore` mutation boundary even though the reviewed
Windows v1 public contract had already returned `RESTORE_PLATFORM_UNSUPPORTED` before
package capture, PAUSE or destination mutation. The frozen 123-boundary/167-case
registry remains unchanged. The correction keeps all 167 cases on macOS/Linux and
partitions Windows to the exact 150 production-reachable cases after separately proving
the fail-closed refusal. The failed run, local correction evidence and hosted rerun
status are retained in `ci-remediation-local.md`. The corrected pull-request run
`29198018266` passed on macOS arm64, Linux x86_64 and Windows x64 at exact source
`2720fbe1042095d74db65f3d3fe71244cf38c810`; because it is validation-only and has no
artifact attestation, it is not promoted to immutable release evidence. The later
`workflow_dispatch` run `29202526816` passed the same matrix plus supply-chain/removal
jobs and four separate attestations at exact source
`69c15001284e613aca534fd8862dd001f9831fdc`.

The recorded at-rest label says only that FileVault was observed enabled on the local
internal APFS volume. It does not approve an at-rest profile or establish a
cryptographic qualification.

## Pinned build and native storage inputs

- Rust toolchain: `1.96.1`, minimal profile, with `rustfmt` and `clippy`, from
  `kernel/rust-toolchain.toml`.
- Dependency resolution authority: `kernel/Cargo.lock`; release and CI commands use
  `--locked`.
- SQLite adapter: `rusqlite 0.40.1`, `default-features=false`, features `backup`,
  `bundled`, `serialize`.
- Native binding: `libsqlite3-sys 0.38.1`, bundled static SQLite `3.53.2`, source ID
  `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.
- Required runtime profile: WAL, `synchronous=FULL`, disabled automatic checkpoint,
  foreign keys on, trusted schema off, cell-size checking on and recursive triggers on.
- Windows path identity preflight: `file-id 0.2.3` using a high-resolution volume
  serial plus 128-bit file ID. Because that safe API reopens a path rather than deriving
  identity from the retained handle, clean-root restore is explicitly unsupported on
  Windows v1 and refuses before PAUSE or destination mutation.

The direct Feature 004 leaf dependencies are pinned in
`kernel/helix-coordinator-sqlite/Cargo.toml`: `base64 0.22.1`, `ed25519-dalek 2.2.0`,
`getrandom 0.4.3`, `rusqlite 0.40.1`, `serde 1.0.228`, `serde_json 1.0.150`,
`serde_json_canonicalizer 0.3.2`, `sha2 0.10.9`, the three local Helix contract crates,
and the Windows-only `file-id 0.2.3`. The reviewed transitive graph is produced with:

```sh
cargo tree --locked -p helix-coordinator-sqlite -e normal --target all
```

No system SQLite, dynamic extension, network client, async runtime or production
fallback is admitted by this feature.

## License, advisory and SBOM evidence

An immutable PLAN-004 software record must retain all of the following for the exact
lockfile and commit:

1. a machine-readable CycloneDX or SPDX SBOM covering Rust packages, target-specific
   Windows packages and bundled SQLite source;
2. a license inventory plus source/license texts, including SQLite's public-domain
   notice and the MIT/Apache-2.0 choices used by the Rust dependency graph;
3. a RustSec advisory scan of the locked graph, with database revision, command version,
   timestamp and complete output;
4. provenance for the source commit, runner image, Rust toolchain, Cargo.lock, bundled
   SQLite amalgamation/source ID, workflow and produced artifact digest; and
5. an immutable artifact attestation whose subject is the upload-artifact digest, not
   merely an individual file inside the archive.

Run `29202526816` retains all five groups for the exact commit, and the catalog now binds
the four artifact IDs, uploaded-ZIP SHA-256 values, attestations and preservation URLs.
The RustSec result covers 213 locked dependencies with zero vulnerabilities and retains
the informational unmaintained warning `RUSTSEC-2025-0134`. Absence of a locally
installed advisory scanner is never treated as a passing scan. A new advisory after
evidence capture invalidates the release decision until it is triaged and the immutable
evidence is regenerated.

The release workflow implements this gate as one fourth, Linux-built artifact after
the unchanged three-platform conformance matrix. It pins `cargo-cyclonedx 0.5.9`,
`cargo-audit 0.22.2`, RustSec database revision
`6e3286f4efa8c142fb33e5ea4342c8db6693cf34` and SPDX license-list-data revision
`c4a7237ec8f4654e867546f9f409749300f1bf4c`. The normalized CycloneDX 1.5 document
rekeys all local workspace references so no checkout path is retained, removes the
generator UUID/timestamp, compares every normal/build dependency edge with Cargo
metadata, covers all target dependencies, and adds the exact bundled SQLite source as
an explicit native component. The bundle also retains package licence files, the applicable canonical
SPDX texts without silently choosing among `OR` alternatives, the verified
`libsqlite3-sys` crate archive and SQLite amalgamation, complete RustSec JSON/stderr,
runner/toolchain/workflow provenance, and an internal sorted SHA-256 manifest.

The two physical-M4 JSON files are copied into that bundle with the explicit status
`local-only-not-immutable-not-power-loss`. Uploading the directory produces the outer
artifact digest; a separate least-privilege job resolves that exact current-run
artifact through the GitHub API and attests the returned digest. The descriptor cannot
and does not self-reference the digest of its containing archive.

## Clean-root scope and retention

The backup contains only the Feature 004 coordinator root and recovery-provider
inventory/packages. Restore requires new dedicated approved roots, detached signed
provenance and matching independently durable `RESTORE_PENDING` metadata. It keeps the
supervisor paused, rotates boot/instance/fencing authority, terminally reconciles old
nonterminal preparations and exports no activation capability.

This is subsystem clean-root evidence, not full clean-machine restore. Replay,
supervisor, policy, catalogue, secrets, workload runtime and effect adapters are outside
the artifact. A later activation feature must establish new authority and a newly
authorized signed plan plus replay claim.

V1 performs no automatic pruning. Canonical plans and recovery material retain their
source classification. Failed/released/delivered/quarantine/retirement records are
permanent tombstones; material retirement requires the guarded operation-bound or true
orphan protocol. No secure-erasure claim is made.

## Evidence still pending

- immutable physical-run provenance for the clean-source Mac mini M4 latency and
  separate recovery-transfer executions; their exact JSON bytes are preserved in the
  attested release bundle, but both remain explicitly
  `local-only-not-immutable-not-power-loss`;
- an approved at-rest profile; FileVault is currently only a local observation;
- production recovery-provider durability/corruption/clean-restore qualification;
- power-loss, sector-loss, directory-fsync and secure-erasure evidence;
- complete full-machine restore and any activation/dispatch evidence; and
- Tier 1 readiness and sovereign host-maintenance authorization.

## Rollback and removal rule

Rollback never opens a newer/unknown schema or converts `RESTORE_PENDING` to `ACTIVE`.
Removal is source-level and non-destructive: remove the PLAN-004 crates, catalog entry,
workflow and fixtures only after running the documented cross-crate removal gates. Do
not rewrite, downgrade or reuse an existing coordinator/recovery root. Retained evidence
remains historical and must not be relabelled as evidence for another commit.

The automated drill runs from the exact commit in an isolated detached worktree. It
removes both Feature 004 crates, the PLAN-004 catalogue block, workflow and fixtures,
uses locked/offline Cargo metadata to prove that both Feature 004 workspace members
were present, and restores the frozen pre-Feature-004 workspace manifest and lockfile.
The semantic metadata projection follows Cargo's `workspace_members` identities and
binds every required package to its exact `kernel/<name>/Cargo.toml` path rather than
scanning TOML text, so quoted keys, comments, multiline strings or decoy manifests
cannot hide or impersonate a member. The manifest restoration is bound to SHA-256
`070602901680b8921d89084db4af31d98e2a23346447fbc6a4eba511295c21eb`, requires exactly
the six baseline packages, records any later dependent workspace members that were
detached only inside the isolated copy, and compares 146 protected files before and
after removal.
It then runs the complete default, non-ignored PLAN-001 and PLAN-003 suites, the
default PLAN-002 semantic suite, and the three legacy MVP-0 packages. Release/soak
tests that are already explicitly ignored remain ignored. Exactly one PLAN-002
structural consumer-list test is explicitly skipped because its reviewed expectation
names the intentionally removed preparation crate; the drill first proves that exact
test still exists once, and its source bytes remain protected and unchanged. This is
software removal evidence, not secure erasure or production-machine decommission
evidence. The immutable run completed this drill successfully before PLAN-005 added
downstream workspace members; its original report remains valid under the verifier's
explicit legacy-compatible empty-downstream rule. Its report, command logs and digests
are inside release artifact `8262995815` and summarized in the immutable evidence
record. The later workspace-manifest binding is additive post-evidence remediation and
does not relabel or replace that immutable run.
