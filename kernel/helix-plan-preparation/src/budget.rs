//! Portable budget-contract boundary.
//!
//! Budget values cover only the four signed v1 dimensions and use checked arithmetic.
//! Scope provisioning, reservation persistence, and aggregate serialization belong to
//! the trusted store adapter.

use helix_contracts::SafeU64;
use std::fmt;

pub const PREPARATION_BUDGET_CONTRACT_VERSION_V1: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum BudgetVectorBuildErrorV1 {
    IntegerOutOfRange,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BudgetVectorArithmeticErrorV1 {
    ArithmeticInvalid,
}

pub struct BudgetVectorInputV1 {
    pub max_cost_micro_units: u64,
    pub action_limit: u64,
    pub egress_bytes_limit: u64,
    pub recovery_bytes: u64,
}

impl fmt::Debug for BudgetVectorInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetVectorInputV1")
            .finish_non_exhaustive()
    }
}

/// Exact checked v1 preparation request; no unsigned dimension is inferred or widened.
#[derive(PartialEq, Eq)]
pub struct BudgetVectorV1 {
    max_cost_micro_units: SafeU64,
    action_limit: SafeU64,
    egress_bytes_limit: SafeU64,
    recovery_bytes: SafeU64,
}

impl BudgetVectorV1 {
    pub fn try_new(input: BudgetVectorInputV1) -> Result<Self, BudgetVectorBuildErrorV1> {
        Ok(Self {
            max_cost_micro_units: safe(input.max_cost_micro_units)?,
            action_limit: safe(input.action_limit)?,
            egress_bytes_limit: safe(input.egress_bytes_limit)?,
            recovery_bytes: safe(input.recovery_bytes)?,
        })
    }

    pub const fn max_cost_micro_units(&self) -> u64 {
        self.max_cost_micro_units.get()
    }

    pub const fn action_limit(&self) -> u64 {
        self.action_limit.get()
    }

    pub const fn egress_bytes_limit(&self) -> u64 {
        self.egress_bytes_limit.get()
    }

    pub const fn recovery_bytes(&self) -> u64 {
        self.recovery_bytes.get()
    }

    /// Adds two exact v1 vectors without widening past the reviewed safe-integer range.
    pub fn checked_add_v1(&self, other: &Self) -> Result<Self, BudgetVectorArithmeticErrorV1> {
        let left = self.components_v1();
        let right = other.components_v1();
        let mut sum = [0_u64; 4];
        for index in 0..4 {
            sum[index] = left[index]
                .checked_add(right[index])
                .filter(|value| *value <= helix_contracts::MAX_SAFE_U64)
                .ok_or(BudgetVectorArithmeticErrorV1::ArithmeticInvalid)?;
        }
        Self::from_components_v1(sum)
    }

    /// Subtracts one exact v1 vector component-by-component and refuses underflow.
    pub fn checked_subtract_v1(&self, other: &Self) -> Result<Self, BudgetVectorArithmeticErrorV1> {
        let left = self.components_v1();
        let right = other.components_v1();
        let mut difference = [0_u64; 4];
        for index in 0..4 {
            difference[index] = left[index]
                .checked_sub(right[index])
                .ok_or(BudgetVectorArithmeticErrorV1::ArithmeticInvalid)?;
        }
        Self::from_components_v1(difference)
    }

    pub(crate) const fn components_v1(&self) -> [u64; 4] {
        [
            self.max_cost_micro_units(),
            self.action_limit(),
            self.egress_bytes_limit(),
            self.recovery_bytes(),
        ]
    }

    fn from_components_v1(components: [u64; 4]) -> Result<Self, BudgetVectorArithmeticErrorV1> {
        Self::try_new(BudgetVectorInputV1 {
            max_cost_micro_units: components[0],
            action_limit: components[1],
            egress_bytes_limit: components[2],
            recovery_bytes: components[3],
        })
        .map_err(|_| BudgetVectorArithmeticErrorV1::ArithmeticInvalid)
    }
}

impl fmt::Debug for BudgetVectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetVectorV1")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BudgetReservationStateV1 {
    Held,
    Released,
}

pub struct BudgetReservationReceiptInputV1 {
    pub contract_version: u16,
    pub state: BudgetReservationStateV1,
    pub reservation_generation: u64,
}

impl fmt::Debug for BudgetReservationReceiptInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetReservationReceiptInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BudgetReservationReceiptBuildErrorV1 {
    VersionUnsupported,
    IntegerOutOfRange,
}

/// Opaque in-process status evidence; it is neither spend nor adapter authority.
pub struct BudgetReservationReceiptV1 {
    contract_version: u16,
    state: BudgetReservationStateV1,
    reservation_generation: SafeU64,
}

impl BudgetReservationReceiptV1 {
    pub fn try_new(
        input: BudgetReservationReceiptInputV1,
    ) -> Result<Self, BudgetReservationReceiptBuildErrorV1> {
        if input.contract_version != PREPARATION_BUDGET_CONTRACT_VERSION_V1 {
            return Err(BudgetReservationReceiptBuildErrorV1::VersionUnsupported);
        }
        Ok(Self {
            contract_version: input.contract_version,
            state: input.state,
            reservation_generation: SafeU64::new(input.reservation_generation)
                .map_err(|_| BudgetReservationReceiptBuildErrorV1::IntegerOutOfRange)?,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }

    pub const fn state(&self) -> &BudgetReservationStateV1 {
        &self.state
    }

    pub const fn reservation_generation(&self) -> u64 {
        self.reservation_generation.get()
    }
}

impl fmt::Debug for BudgetReservationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetReservationReceiptV1")
            .finish_non_exhaustive()
    }
}

fn safe(value: u64) -> Result<SafeU64, BudgetVectorBuildErrorV1> {
    SafeU64::new(value).map_err(|_| BudgetVectorBuildErrorV1::IntegerOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_contracts::MAX_SAFE_U64;

    fn vector(values: [u64; 4]) -> BudgetVectorV1 {
        BudgetVectorV1::try_new(BudgetVectorInputV1 {
            max_cost_micro_units: values[0],
            action_limit: values[1],
            egress_bytes_limit: values[2],
            recovery_bytes: values[3],
        })
        .expect("test vector is safe")
    }

    #[test]
    fn portable_vector_addition_and_subtraction_are_exact_and_checked() {
        let left = vector([1, 2, 3, 4]);
        let right = vector([4, 3, 2, 1]);
        assert_eq!(
            left.checked_add_v1(&right)
                .expect("safe addition")
                .components_v1(),
            [5, 5, 5, 5]
        );
        assert_eq!(
            left.checked_subtract_v1(&vector([1, 1, 1, 1]))
                .expect("safe subtraction")
                .components_v1(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            vector([MAX_SAFE_U64, 0, 0, 0]).checked_add_v1(&vector([1, 0, 0, 0])),
            Err(BudgetVectorArithmeticErrorV1::ArithmeticInvalid)
        );
        assert_eq!(
            vector([0, 0, 0, 0]).checked_subtract_v1(&vector([1, 0, 0, 0])),
            Err(BudgetVectorArithmeticErrorV1::ArithmeticInvalid)
        );
    }
}
