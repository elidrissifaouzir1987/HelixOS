//! Independent adapter inbox receive and readback boundaries.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchPreReceiveRefusalV1 {
    DestinationMismatch,
    ProtocolUnsupported,
    CapabilityMismatch,
    InboxCapacityExhausted,
}

impl DispatchPreReceiveRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DestinationMismatch => "DESTINATION_MISMATCH",
            Self::ProtocolUnsupported => "PROTOCOL_UNSUPPORTED",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::InboxCapacityExhausted => "INBOX_CAPACITY_EXHAUSTED",
        }
    }
}

impl fmt::Debug for DispatchPreReceiveRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

pub enum DispatchInboxReceiveOutcomeV1<S, R> {
    DurablyReceived(S),
    RetainedState(S),
    RetainedReceipt(R),
    RefusedBeforeReceive(DispatchPreReceiveRefusalV1),
    Conflict,
    Quarantined,
    Unavailable,
    Unhealthy,
}

impl<S, R> fmt::Debug for DispatchInboxReceiveOutcomeV1<S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurablyReceived(_) => {
                formatter.write_str("DispatchInboxReceiveOutcomeV1::DurablyReceived(..)")
            }
            Self::RetainedState(_) => {
                formatter.write_str("DispatchInboxReceiveOutcomeV1::RetainedState(..)")
            }
            Self::RetainedReceipt(_) => {
                formatter.write_str("DispatchInboxReceiveOutcomeV1::RetainedReceipt(..)")
            }
            Self::RefusedBeforeReceive(_) => {
                formatter.write_str("DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(..)")
            }
            Self::Conflict => formatter.write_str("DispatchInboxReceiveOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("DispatchInboxReceiveOutcomeV1::Quarantined"),
            Self::Unavailable => formatter.write_str("DispatchInboxReceiveOutcomeV1::Unavailable"),
            Self::Unhealthy => formatter.write_str("DispatchInboxReceiveOutcomeV1::Unhealthy"),
        }
    }
}

pub trait DispatchInboxV1: Send + Sync {
    type RetainedState: Send;
    type RetainedReceipt: Send;

    fn receive_exact_grant_v1(
        &self,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt>;
}

/// Closed result of trying to consume one already-durable inbox entry.
///
/// Receipt construction and signing belong to the adapter implementation. The
/// portable caller receives only the opaque retained receipt and cannot obtain
/// adapter signing authority through this boundary.
pub enum DispatchInboxConsumeOutcomeV1<R> {
    Consumed(R),
    DefinitelyRefused(R),
    RetainedReceipt(R),
    Conflict,
    Quarantined,
    Unavailable,
    Unhealthy,
}

impl<R> fmt::Debug for DispatchInboxConsumeOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed(_) => formatter.write_str("DispatchInboxConsumeOutcomeV1::Consumed(..)"),
            Self::DefinitelyRefused(_) => {
                formatter.write_str("DispatchInboxConsumeOutcomeV1::DefinitelyRefused(..)")
            }
            Self::RetainedReceipt(_) => {
                formatter.write_str("DispatchInboxConsumeOutcomeV1::RetainedReceipt(..)")
            }
            Self::Conflict => formatter.write_str("DispatchInboxConsumeOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("DispatchInboxConsumeOutcomeV1::Quarantined"),
            Self::Unavailable => formatter.write_str("DispatchInboxConsumeOutcomeV1::Unavailable"),
            Self::Unhealthy => formatter.write_str("DispatchInboxConsumeOutcomeV1::Unhealthy"),
        }
    }
}

/// Adapter-owned one-shot consumption boundary for a state returned by
/// [`DispatchInboxV1::receive_exact_grant_v1`].
///
/// Implementations must linearize duplicate calls against their own durable
/// state. A state already closed by another caller returns the original retained
/// receipt; it must never authorize another consumption.
pub trait DispatchInboxConsumerV1: DispatchInboxV1 {
    fn consume_received_once_v1(
        &self,
        retained_state: Self::RetainedState,
    ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt>;
}

/// Closed result of the deterministic receive-then-consume orchestration.
///
/// Receive and consume unavailability remain distinct so callers do not erase
/// whether a durable `RECEIVED` acknowledgement was already observed.
pub enum DispatchInboxAdapterOutcomeV1<R> {
    Consumed(R),
    DefinitelyRefused(R),
    RetainedReceipt(R),
    RefusedBeforeReceive(DispatchPreReceiveRefusalV1),
    Conflict,
    Quarantined,
    ReceiveUnavailable,
    ReceiveUnhealthy,
    ConsumeUnavailable,
    ConsumeUnhealthy,
}

impl<R> fmt::Debug for DispatchInboxAdapterOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed(_) => formatter.write_str("DispatchInboxAdapterOutcomeV1::Consumed(..)"),
            Self::DefinitelyRefused(_) => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::DefinitelyRefused(..)")
            }
            Self::RetainedReceipt(_) => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::RetainedReceipt(..)")
            }
            Self::RefusedBeforeReceive(_) => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::RefusedBeforeReceive(..)")
            }
            Self::Conflict => formatter.write_str("DispatchInboxAdapterOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("DispatchInboxAdapterOutcomeV1::Quarantined"),
            Self::ReceiveUnavailable => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::ReceiveUnavailable")
            }
            Self::ReceiveUnhealthy => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::ReceiveUnhealthy")
            }
            Self::ConsumeUnavailable => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::ConsumeUnavailable")
            }
            Self::ConsumeUnhealthy => {
                formatter.write_str("DispatchInboxAdapterOutcomeV1::ConsumeUnhealthy")
            }
        }
    }
}

pub enum DispatchInboxReadbackOutcomeV1<S, R> {
    Absent,
    Received(S),
    RetainedReceipt(R),
    Conflict,
    Quarantined,
    Unavailable,
    Unhealthy,
}

impl<S, R> fmt::Debug for DispatchInboxReadbackOutcomeV1<S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("DispatchInboxReadbackOutcomeV1::Absent"),
            Self::Received(_) => {
                formatter.write_str("DispatchInboxReadbackOutcomeV1::Received(..)")
            }
            Self::RetainedReceipt(_) => {
                formatter.write_str("DispatchInboxReadbackOutcomeV1::RetainedReceipt(..)")
            }
            Self::Conflict => formatter.write_str("DispatchInboxReadbackOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("DispatchInboxReadbackOutcomeV1::Quarantined"),
            Self::Unavailable => formatter.write_str("DispatchInboxReadbackOutcomeV1::Unavailable"),
            Self::Unhealthy => formatter.write_str("DispatchInboxReadbackOutcomeV1::Unhealthy"),
        }
    }
}

pub trait DispatchInboxReadbackV1: Send + Sync {
    type RetainedState: Send;
    type RetainedReceipt: Send;

    fn readback_grant_v1(
        &self,
        grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt>;
}
