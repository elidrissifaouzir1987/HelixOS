#![forbid(unsafe_code)]
pub mod card;
pub mod server;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Decision { Approve, Reject }
