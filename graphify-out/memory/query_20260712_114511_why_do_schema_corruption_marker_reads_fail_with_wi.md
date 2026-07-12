---
type: "query"
date: "2026-07-12T11:45:11.997784+00:00"
question: "Why do schema_corruption marker reads fail with Windows lock error 33, and which test handle can be released?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep the lease continuously held and route test marker reads/writes through its existing handle; never drop the custody or bypass Windows locking."
source_nodes: ["empty_and_existing_roles_hold_one_exclusive_redacted_root_lease()", "CoordinatorRootLeaseV1", "root_safety.rs", "schema_corruption.rs"]
---

# Q: Why do schema_corruption marker reads fail with Windows lock error 33, and which test handle can be released?

## Answer

Expanded from the graph vocabulary via [schema, corruption, marker, reads, windows, lock, lease, initialization, existing, empty, handle, release]. No custody handle should be released: both tests intentionally require one continuous CoordinatorRootLeaseV1. Their fs::read/fs::write path reopen created a second handle that Windows byte-range locking correctly rejected. Add cfg(test)-only exact-read and replacement helpers on CoordinatorRootLeaseV1 that revalidate identity and use its retained File; update the tests to assert and inject the partial marker through that handle. Production lease, root identity, and marker semantics remain unchanged.

## Outcome

- Signal: corrected
- Correction: Keep the lease continuously held and route test marker reads/writes through its existing handle; never drop the custody or bypass Windows locking.

## Source Nodes

- empty_and_existing_roles_hold_one_exclusive_redacted_root_lease()
- CoordinatorRootLeaseV1
- root_safety.rs
- schema_corruption.rs