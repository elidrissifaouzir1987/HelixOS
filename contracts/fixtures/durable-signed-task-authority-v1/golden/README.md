# PLAN-006 Golden US1 Fixtures

The four `.jcs` files are exact RFC 8785 bytes with no trailing newline:

- `human-request-grant.protected.jcs`: protected SHA-256 `76ec465a11d591f9b432898228f665306ac3ca1d692f2e3281c64bd8750aa8d7`;
- `human-request-grant.envelope.jcs`: exact signed grant envelope;
- `root-task-lease.protected.jcs`: protected SHA-256 `f016a5887bbeb08733933c5a054149fdc84be4c078104d6700b5399e0611f97a`;
- `root-task-lease.envelope.jcs`: exact signed root lease envelope.

Only the synthetic public keys are retained in `../public-keys.json`. No private key,
seed, bearer value or authentication assertion belongs in this corpus. These bytes are
historical/test evidence and are never a caller-constructible current-authority marker.
