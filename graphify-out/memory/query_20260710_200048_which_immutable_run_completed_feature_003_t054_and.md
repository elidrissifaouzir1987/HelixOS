---
type: "query"
date: "2026-07-10T20:00:48.943269+00:00"
question: "Which immutable run completed Feature 003 T054 and what Windows portability correction followed?"
contributor: "graphify"
outcome: "useful"
---

# Q: Which immutable run completed Feature 003 T054 and what Windows portability correction followed?

## Answer

T054 is completed by the unchanged push run 29118903798 at commit d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3: PLAN-003 passed on ubuntu-24.04 x86_64, macos-26 arm64, and windows-2022 x64. GitHub preserved per-platform artifacts with SHA-256 e764e6470f5a6c7a292fc366a10c25aafffc51178c147da5fdbb24b4697dc6e1, 45bbc565b257b878c62a85c561522a88fcea67f2bd36ac3331204de89ab0e694, and 94a45b9c63fce6e28c247909d2a5048e584cf7ab134817e10b62b02c9c16e11d, each with a repository Sigstore/Rekor attestation. Hosted macOS remains distinct from the physical Mac mini M4 and power-loss gate T055. The same commit's portable workspace run exposed an unrelated Windows checkout issue: the intentionally LF-terminated PLAN-001 negative wire fixture was converted to CRLF, then the byte-exact generator restored LF and reported false drift. A targeted text eol=lf attribute pins only that fixture without changing contract bytes or generator semantics, and `.gitattributes` changes now trigger the portable workflow.

## Outcome

- Signal: useful
