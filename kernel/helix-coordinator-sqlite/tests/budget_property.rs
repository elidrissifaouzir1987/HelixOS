//! T040 deterministic checked-oracle coverage for four-dimensional budget arithmetic.
//!
//! The oracle deliberately uses signed subtraction and `u128` addition instead of the
//! coordinator implementation. This keeps arithmetic-invalid classification separate
//! from ordinary capacity exhaustion across an aggregate four-dimensional vector.

#[path = "../src/budget.rs"]
mod budget;

use budget::{checked_budget_release_v1, checked_budget_reservation_v1, BudgetVectorCheckErrorV1};
use helix_contracts::MAX_SAFE_U64;

const GENERATED_VECTOR_COUNT: u64 = 100_000;
type Vector = [u64; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleError {
    ArithmeticInvalid,
    Exhausted,
}

#[derive(Clone, Copy, Debug)]
struct VectorCase {
    total: Vector,
    held: Vector,
    requested: Vector,
    released: Vector,
}

fn observe(result: Result<Vector, BudgetVectorCheckErrorV1>) -> Result<Vector, OracleError> {
    result.map_err(|error| match error {
        BudgetVectorCheckErrorV1::ArithmeticInvalid => OracleError::ArithmeticInvalid,
        BudgetVectorCheckErrorV1::Exhausted => OracleError::Exhausted,
    })
}

fn oracle_reservation(
    total: Vector,
    held: Vector,
    requested: Vector,
) -> Result<Vector, OracleError> {
    let mut next_held = [0; 4];
    let mut remaining = [0; 4];

    // Arithmetic is one aggregate predicate and therefore precedes every capacity
    // decision, even when the invalid dimension follows an exhausted one.
    for dimension in 0..4 {
        if [total[dimension], held[dimension], requested[dimension]]
            .into_iter()
            .any(|value| value > MAX_SAFE_U64)
        {
            return Err(OracleError::ArithmeticInvalid);
        }

        let signed_remaining = i128::from(total[dimension]) - i128::from(held[dimension]);
        if signed_remaining < 0 {
            return Err(OracleError::ArithmeticInvalid);
        }
        remaining[dimension] =
            u64::try_from(signed_remaining).expect("nonnegative safe difference fits u64");

        let wide_sum = u128::from(held[dimension]) + u128::from(requested[dimension]);
        if wide_sum > u128::from(MAX_SAFE_U64) {
            return Err(OracleError::ArithmeticInvalid);
        }
        next_held[dimension] = u64::try_from(wide_sum).expect("safe sum fits u64");
    }

    if (0..4).any(|dimension| requested[dimension] > remaining[dimension]) {
        return Err(OracleError::Exhausted);
    }
    Ok(next_held)
}

fn oracle_release(held: Vector, released: Vector) -> Result<Vector, OracleError> {
    let mut next_held = [0; 4];
    for dimension in 0..4 {
        if held[dimension] > MAX_SAFE_U64 || released[dimension] > MAX_SAFE_U64 {
            return Err(OracleError::ArithmeticInvalid);
        }
        let signed_difference = i128::from(held[dimension]) - i128::from(released[dimension]);
        if signed_difference < 0 {
            return Err(OracleError::ArithmeticInvalid);
        }
        next_held[dimension] =
            u64::try_from(signed_difference).expect("nonnegative safe difference fits u64");
    }
    Ok(next_held)
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn safe_sample(state: &mut u64) -> u64 {
    splitmix64(state) % (MAX_SAFE_U64 + 1)
}

fn generated_case(index: u64) -> VectorCase {
    let mut state = index ^ 0x4845_4c49_584f_5304;
    let mut total = [0; 4];
    let mut held = [0; 4];
    let mut requested = [0; 4];
    let mut released = [0; 4];

    for dimension in 0..4 {
        total[dimension] = safe_sample(&mut state);
        held[dimension] = safe_sample(&mut state) % (total[dimension] + 1);
        let remaining = total[dimension] - held[dimension];
        requested[dimension] = safe_sample(&mut state) % (remaining + 1);
        released[dimension] = safe_sample(&mut state) % (held[dimension] + 1);
    }

    let dimension = usize::try_from((index / 8) % 4).expect("dimension fits usize");
    match index % 8 {
        0 => {
            total = [0; 4];
            held = [0; 4];
            requested = [0; 4];
            released = [0; 4];
        }
        1 => {
            total = [MAX_SAFE_U64; 4];
            held = [0; 4];
            requested = [MAX_SAFE_U64; 4];
            released = [0; 4];
        }
        2 => {
            // Signed `total - held` underflow.
            total[dimension] = 0;
            held[dimension] = 1;
            requested[dimension] = 0;
        }
        3 => {
            // Both capacity and held+request fail, but arithmetic has priority.
            total[dimension] = MAX_SAFE_U64;
            held[dimension] = MAX_SAFE_U64;
            requested[dimension] = 1;
        }
        4 => {
            // Capacity only: the sum is within the safe range.
            total[dimension] = 10;
            held[dimension] = 3;
            requested[dimension] = 8;
        }
        5 => {
            // Out-of-range inputs are arithmetic failures, never exhaustion.
            requested[dimension] = MAX_SAFE_U64 + 1;
        }
        6 => {
            // Release subtraction underflow.
            held[dimension] = 0;
            released[dimension] = 1;
        }
        7 => {
            // Keep the seeded fully valid case assembled above.
        }
        _ => unreachable!("modulo eight is closed"),
    }

    VectorCase {
        total,
        held,
        requested,
        released,
    }
}

#[test]
fn boundary_classifications_are_exact_in_every_dimension() {
    assert_eq!(oracle_reservation([0; 4], [0; 4], [0; 4]), Ok([0; 4]));
    assert_eq!(
        oracle_reservation([MAX_SAFE_U64; 4], [0; 4], [MAX_SAFE_U64; 4]),
        Ok([MAX_SAFE_U64; 4])
    );

    for dimension in 0..4 {
        let mut total = [0; 4];
        let mut held = [0; 4];
        let mut requested = [0; 4];

        held[dimension] = 1;
        assert_eq!(
            observe(checked_budget_reservation_v1(total, held, requested)),
            Err(OracleError::ArithmeticInvalid),
            "dimension {dimension} held exceeds total"
        );

        total[dimension] = MAX_SAFE_U64;
        held[dimension] = MAX_SAFE_U64;
        requested[dimension] = 1;
        assert_eq!(
            observe(checked_budget_reservation_v1(total, held, requested)),
            Err(OracleError::ArithmeticInvalid),
            "dimension {dimension} held plus request exceeds safe range"
        );

        total[dimension] = 10;
        held[dimension] = 3;
        requested[dimension] = 8;
        assert_eq!(
            observe(checked_budget_reservation_v1(total, held, requested)),
            Err(OracleError::Exhausted),
            "dimension {dimension} is exhausted without arithmetic failure"
        );

        let mut released = [0; 4];
        held = [0; 4];
        released[dimension] = 1;
        assert_eq!(
            observe(checked_budget_release_v1(held, released)),
            Err(OracleError::ArithmeticInvalid),
            "dimension {dimension} release underflows"
        );
    }
}

#[test]
fn one_hundred_thousand_deterministic_vectors_match_the_independent_oracle() {
    let mut saw_accepted = false;
    let mut saw_arithmetic_invalid = false;
    let mut saw_exhausted = false;
    let mut saw_release_underflow = false;

    for index in 0..GENERATED_VECTOR_COUNT {
        let case = generated_case(index);
        let expected_reservation = oracle_reservation(case.total, case.held, case.requested);
        let actual_reservation = observe(checked_budget_reservation_v1(
            case.total,
            case.held,
            case.requested,
        ));
        assert_eq!(
            actual_reservation, expected_reservation,
            "reservation vector {index}: {case:?}"
        );

        match expected_reservation {
            Ok(_) => saw_accepted = true,
            Err(OracleError::ArithmeticInvalid) => saw_arithmetic_invalid = true,
            Err(OracleError::Exhausted) => saw_exhausted = true,
        }

        let expected_release = oracle_release(case.held, case.released);
        let actual_release = observe(checked_budget_release_v1(case.held, case.released));
        assert_eq!(
            actual_release, expected_release,
            "release vector {index}: {case:?}"
        );
        saw_release_underflow |= expected_release == Err(OracleError::ArithmeticInvalid);
    }

    assert_eq!(GENERATED_VECTOR_COUNT, 100_000);
    assert!(
        saw_accepted,
        "corpus must contain accepted aggregate vectors"
    );
    assert!(
        saw_arithmetic_invalid,
        "corpus must contain arithmetic-invalid aggregate vectors"
    );
    assert!(
        saw_exhausted,
        "corpus must contain exhausted aggregate vectors"
    );
    assert!(
        saw_release_underflow,
        "corpus must contain aggregate release underflow"
    );
}
