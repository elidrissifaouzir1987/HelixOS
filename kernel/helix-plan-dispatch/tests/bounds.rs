use std::fs;
use std::path::PathBuf;

const GRANT_LIFETIME_CEILING_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapacityVector {
    max_cost_micro_units: u64,
    action_limit: u64,
    egress_bytes_limit: u64,
    recovery_bytes: u64,
}

fn capacity_is_held(required: CapacityVector, held: CapacityVector) -> bool {
    required.max_cost_micro_units <= held.max_cost_micro_units
        && required.action_limit <= held.action_limit
        && required.egress_bytes_limit <= held.egress_bytes_limit
        && required.recovery_bytes <= held.recovery_bytes
}

fn exclusive_effective_deadline(
    issued_at_monotonic_ms: u64,
    authority_deadline_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
) -> Option<u64> {
    issued_at_monotonic_ms
        .checked_add(GRANT_LIFETIME_CEILING_MS)
        .map(|ceiling| {
            ceiling
                .min(authority_deadline_monotonic_ms)
                .min(caller_deadline_monotonic_ms)
        })
}

fn is_before_exclusive_deadline(now_monotonic_ms: u64, deadline_monotonic_ms: u64) -> bool {
    now_monotonic_ms < deadline_monotonic_ms
}

#[test]
fn exact_capacity_is_accepted_and_one_over_each_dimension_is_denied() {
    let held = CapacityVector {
        max_cost_micro_units: 10_000,
        action_limit: 40,
        egress_bytes_limit: 4_096,
        recovery_bytes: 2_048,
    };

    assert!(capacity_is_held(held, held), "exact held capacity is valid");

    for required in [
        CapacityVector {
            max_cost_micro_units: held.max_cost_micro_units + 1,
            ..held
        },
        CapacityVector {
            action_limit: held.action_limit + 1,
            ..held
        },
        CapacityVector {
            egress_bytes_limit: held.egress_bytes_limit + 1,
            ..held
        },
        CapacityVector {
            recovery_bytes: held.recovery_bytes + 1,
            ..held
        },
    ] {
        assert!(
            !capacity_is_held(required, held),
            "over-by-one capacity must fail componentwise: {required:?}"
        );
    }
}

#[test]
fn deadline_equality_denies_and_the_issue_time_ceiling_is_exactly_5000_ms() {
    let issue = 10_000;
    let deadline = exclusive_effective_deadline(issue, 99_000, 88_000)
        .expect("the test issue time can be bounded");
    assert_eq!(deadline, 15_000);
    assert!(is_before_exclusive_deadline(14_999, deadline));
    assert!(!is_before_exclusive_deadline(deadline, deadline));
    assert!(!is_before_exclusive_deadline(15_001, deadline));

    assert_eq!(
        exclusive_effective_deadline(issue, 12_345, 88_000),
        Some(12_345),
        "an earlier authority deadline wins"
    );
    assert_eq!(
        exclusive_effective_deadline(issue, 99_000, 11_234),
        Some(11_234),
        "an earlier caller deadline wins"
    );
    assert_eq!(
        exclusive_effective_deadline(u64::MAX - 4_999, u64::MAX, u64::MAX),
        None,
        "deadline arithmetic must fail closed on overflow"
    );
}

#[test]
fn t029_must_apply_bounds_during_final_authority_comparison() {
    // These pure boundary oracles remain useful before and after T029. When T029 exposes its
    // crate-owned comparison seam, add direct behavioral calls proving the same four cases.
    let compare_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/compare.rs");
    let source = fs::read_to_string(&compare_path).unwrap_or_else(|error| {
        panic!(
            "T029 RED: {} must enforce capacity and exclusive grant-deadline bounds: {error}",
            compare_path.display()
        )
    });

    assert!(
        source.contains("5_000") || source.contains("5000"),
        "T029 compare.rs must enforce the exact 5,000 ms grant lifetime ceiling"
    );
    assert!(
        source.contains("deadline") && (source.contains(".min(") || source.contains("cmp::min")),
        "T029 compare.rs must choose the minimum authority/caller/issue-plus-ceiling deadline"
    );
    assert!(
        source.contains("capacity") || source.contains("reservation_vector"),
        "T029 compare.rs must compare required capacity with the held reservation vector"
    );
    assert!(
        source.contains("<") && source.contains("<="),
        "T029 compare.rs must distinguish exclusive deadline equality from inclusive exact capacity"
    );
}
