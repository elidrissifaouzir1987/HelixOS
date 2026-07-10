---
type: "query"
date: "2026-07-10T22:21:14.291036+00:00"
question: "What corrected the macOS baseline certificate failure and formatting mismatch?"
contributor: "graphify"
outcome: "corrected"
correction: "The original failure was not merely a LibreSSL/OpenSSL tool mismatch: LibreSSL exposed an invalid CA DNS SAN. Fix the certificate itself, then distinguish the named OpenSSL 3 oracle from LibreSSL."
source_nodes: ["generate_pki", "is_openssl_3_banner", "openssl_strict_verify_accepts_chain"]
---

# Q: What corrected the macOS baseline certificate failure and formatting mismatch?

## Answer

The macOS verifier exposed a real certificate defect: CertificateParams::new had encoded the display label HelixOS Local CA as the invalid DNS SAN DNS:HelixOS Local CA. The CA now has an empty SAN set and keeps its identity only in the Common Name, with a deterministic no-CA-SAN regression. The external oracle now accepts only an OpenSSL major-version-3 banner, rejects an invalid explicit OPENSSL override, and clearly skips PATH-only LibreSSL while structural x509-parser assertions still run. Portable CI explicitly selects OpenSSL 3 and covers provision-only changes. Feature-003 quickstart formatting now matches the immutable package-scoped CI gate and preserves legacy formatting debt separately. Scoped format, workspace check, strict Clippy including all features, unfiltered workspace tests, and all-target/all-feature tests pass locally.

## Outcome

- Signal: corrected
- Correction: The original failure was not merely a LibreSSL/OpenSSL tool mismatch: LibreSSL exposed an invalid CA DNS SAN. Fix the certificate itself, then distinguish the named OpenSSL 3 oracle from LibreSSL.

## Source Nodes

- generate_pki
- is_openssl_3_banner
- openssl_strict_verify_accepts_chain