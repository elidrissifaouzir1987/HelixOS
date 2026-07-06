#![forbid(unsafe_code)]
pub mod card;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Decision { Approve, Reject }
