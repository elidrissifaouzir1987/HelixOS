---
type: "implementation"
date: "2026-07-11T17:36:48.950471+00:00"
question: "How was RestorePackageCustodyV1 hardened against same-inode same-length content mutation and path substitution?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["RestorePackageCustodyV1", "RestorePackageFileBindingV1", "root_safety.rs"]
---

# Q: How was RestorePackageCustodyV1 hardened against same-inode same-length content mutation and path substitution?

## Answer

Each restore-package regular file now retains its opened File handle, filesystem identity, exact length, and a streaming SHA-256 captured through positional handle reads. Every custody revalidation checks the path and retained handle identities and lengths before and after recomputing the captured handle digest. Bounded read and hash methods refuse bytes or digests that differ from the captured binding, while member_path refuses mutated or substituted bindings. Unit tests cover in-place same-length mutation and same-length path inode substitution; all 109 library tests pass.

## Outcome

- Signal: useful

## Source Nodes

- RestorePackageCustodyV1
- RestorePackageFileBindingV1
- root_safety.rs