use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const BYTE_LEN: usize = 32;
    pub const HEX_LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn digest(input: &[u8]) -> Self {
        Self(Sha256::digest(input).into())
    }

    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != Self::HEX_LEN || !value.bytes().all(is_lower_hex) {
            return Err(ContractError::InvalidEncoding { kind: "sha256" });
        }
        let mut bytes = [0_u8; Self::BYTE_LEN];
        decode_lower_hex(value.as_bytes(), &mut bytes)
            .ok_or(ContractError::InvalidEncoding { kind: "sha256" })?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        encode_lower_hex(&self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse_hex(&raw).map_err(de::Error::custom)
    }
}

pub(crate) fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) fn decode_lower_hex(input: &[u8], output: &mut [u8]) -> Option<()> {
    if input.len() != output.len() * 2 {
        return None;
    }
    for (index, chunk) in input.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(())
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
