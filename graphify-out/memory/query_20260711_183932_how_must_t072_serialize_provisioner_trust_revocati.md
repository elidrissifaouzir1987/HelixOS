---
type: "implementation"
date: "2026-07-11T18:39:32.367274+00:00"
question: "How must T072 serialize provisioner trust revocation during restore?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["ProvisionerTrustCustodyV1", "ProvisionerTrustViewV1", "AcceptedPreparationRestorePackageV1", "restore_preparation_to_pending_v1"]
---

# Q: How must T072 serialize provisioner trust revocation during restore?

## Answer

Acquire ProvisionerTrustCustodyV1 before the first provenance decision, resolve pinned trust only through the custody-owned view, retain it through the entire accepted restore and refusal cleanup, and require every revocation/rotation/profile update to wait for Drop. Periodic rechecks are not sufficient because they leave a TOCTOU window. Production conformance starts a late revocation and proves it remains blocked until the full restore returns.

## Outcome

- Signal: useful

## Source Nodes

- ProvisionerTrustCustodyV1
- ProvisionerTrustViewV1
- AcceptedPreparationRestorePackageV1
- restore_preparation_to_pending_v1