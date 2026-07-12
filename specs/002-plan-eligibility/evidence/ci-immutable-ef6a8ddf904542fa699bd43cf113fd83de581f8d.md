# PLAN-002 immutable three-host CI evidence

**Recorded**: 2026-07-12

**Commit**: `ef6a8ddf904542fa699bd43cf113fd83de581f8d`

**Workflow run**: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589`

**Event / attempt**: `workflow_dispatch` / `1`

**Result**: Linux x86_64, macOS arm64 and Windows x64 all passed unchanged

The run executed `.github/workflows/plan-eligibility.yml` from the commit above. Each
conformance job passed package formatting, strict all-target/all-feature Clippy,
feature-001 contract regression, all eligibility targets and the unchanged corpus,
release replay contention, the deterministic 100,000-context soak, corpus-drift
verification and evidence upload. Three dedicated least-privilege jobs then attested
the uploaded archive digests for this non-pull-request run.

## Shared reviewed inputs

- expected outcomes SHA-256:
  `258fcd002c335a1f25070e593ae97eb7472b2fe55342134058e2e4e470af7bbb`
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`
- Cargo: `cargo 1.96.1 (356927216 2026-06-26)`
- evidence descriptor schema: `helixos.plan-eligibility-ci-evidence/1`

## Linux x86_64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/job/86639323398`
- runner: `ubuntu-24.04`; image `ubuntu24` version `20260705.232.1`
- OS / architecture: `Ubuntu 24.04.4 LTS` / `X64`
- rustc host: `x86_64-unknown-linux-gnu`
- artifact: `plan-002-linux-x86_64-ef6a8ddf904542fa699bd43cf113fd83de581f8d`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/artifacts/8258816762`
- uploaded ZIP SHA-256:
  `54e94789b97ca9799b7854a0f4ba95881bc3f9afa202aa908ae7db72be60bfdf`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34941187`

## macOS arm64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/job/86639323420`
- runner: `macos-26`; image `macos26` version `20260630.0213.1`
- OS / architecture: `macOS 26.4.0` / `ARM64`
- rustc host: `aarch64-apple-darwin`
- artifact: `plan-002-macos-arm64-ef6a8ddf904542fa699bd43cf113fd83de581f8d`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/artifacts/8258821832`
- uploaded ZIP SHA-256:
  `9e9d76dd9f8023601c53c7b4d7fc0019658831bf95d6ed4c52256b754e85dec4`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34941186`

## Windows x64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/job/86639323395`
- runner: `windows-2022`; image `win22` version `20260706.237.1`
- OS / architecture: `Microsoft Windows 10.0.20348` / `X64`
- rustc host: `x86_64-pc-windows-msvc`
- artifact: `plan-002-windows-x64-ef6a8ddf904542fa699bd43cf113fd83de581f8d`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29188649589/artifacts/8258822450`
- uploaded ZIP SHA-256:
  `5499b9c142f149e257f5c55146ca08a5421e1e0708fcbc782d905c9c92289495`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34941188`

## Independent preservation and provenance verification

All three raw ZIP archives were downloaded independently. Their locally recomputed
SHA-256 digests matched the GitHub Actions artifact API values above. Each archive then
passed `gh attestation verify` with the expected repository, signer workflow, source
commit and source ref, while denying self-hosted runners.

GitHub retains the three artifacts for 90 days, until
`2026-10-10T10:09:07Z`. The run and per-artifact URLs above are the preservation
locations; the attestations bind the uploaded archive digests rather than an individual
descriptor file.

## Evidence boundary

This closes T035's unchanged hosted three-platform matrix requirement. It does not turn
the eligibility marker into preparation or dispatch authority, does not establish a
physical Mac mini M4 result, and does not satisfy any deferred durable replay or
preparation gate. `PLAN-002` therefore remains `pending-evidence` in the conformance
catalog.
