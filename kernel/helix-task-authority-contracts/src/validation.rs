use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

pub const MAX_SAFE_U64: u64 = 9_007_199_254_740_991;

const MAX_ROOT_ID_BYTES: usize = 64;
const MAX_RESOURCE_COMPONENTS: usize = 128;
const MAX_RESOURCE_COMPONENT_BYTES: usize = 255;
const MAX_RESOURCE_COMPONENT_BYTES_PER_ROOT: usize = 4_096;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeU64(u64);

impl SafeU64 {
    pub fn new(value: u64) -> Result<Self> {
        if value > MAX_SAFE_U64 {
            return Err(ContractError::InvalidField);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .filter(|value| *value <= MAX_SAFE_U64)
            .map(Self)
            .ok_or(ContractError::InvalidField)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(ContractError::InvalidField)
    }
}

impl fmt::Debug for SafeU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SafeU64").finish_non_exhaustive()
    }
}

impl TryFrom<u64> for SafeU64 {
    type Error = ContractError;

    fn try_from(value: u64) -> Result<Self> {
        Self::new(value)
    }
}

impl Serialize for SafeU64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SafeU64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SafeU64Visitor;

        impl<'de> de::Visitor<'de> for SafeU64Visitor {
            type Value = SafeU64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative I-JSON safe integer")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                SafeU64::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(SafeU64Visitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(SafeU64);

impl Generation {
    pub fn new(value: u64) -> Result<Self> {
        let value = SafeU64::new(value)?;
        if value.get() != 0 {
            return Ok(Self(value));
        }
        Err(ContractError::InvalidField)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub fn checked_next(self) -> Result<Self> {
        let one = SafeU64::new(1)?;
        Self::new(self.0.checked_add(one)?.get())
    }
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Generation").finish_non_exhaustive()
    }
}

impl TryFrom<u64> for Generation {
    type Error = ContractError;

    fn try_from(value: u64) -> Result<Self> {
        Self::new(value)
    }
}

impl Serialize for Generation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SafeU64::deserialize(deserializer)?;
        Self::new(value.get()).map_err(de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':')
            })
        {
            return Err(ContractError::InvalidField);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Identifier").finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce128([u8; 16]);

impl Nonce128 {
    pub const HEX_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != Self::HEX_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidEncoding);
        }

        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(Self::HEX_LEN);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for Nonce128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Nonce128").finish_non_exhaustive()
    }
}

impl Serialize for Nonce128 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Nonce128 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_hex(&value).map_err(de::Error::custom)
    }
}

fn lower_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ContractError::InvalidEncoding),
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CurrencyCodeV1(String);

impl CurrencyCodeV1 {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(ContractError::InvalidField);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CurrencyCodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrencyCodeV1")
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for CurrencyCodeV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DelegationDepthV1(u8);

impl DelegationDepthV1 {
    pub const MAX: u8 = 32;

    pub fn new(value: u64) -> Result<Self> {
        if value > u64::from(Self::MAX) {
            return Err(ContractError::InvalidField);
        }
        Ok(Self(value as u8))
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for DelegationDepthV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegationDepthV1")
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for DelegationDepthV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SafeU64::deserialize(deserializer)?;
        Self::new(value.get()).map_err(de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRootV1 {
    root_id: String,
    components: Vec<String>,
}

impl ResourceRootV1 {
    pub fn try_new(root_id: impl Into<String>, components: Vec<String>) -> Result<Self> {
        let value = Self {
            root_id: root_id.into(),
            components,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_root_id(&self.root_id)?;
        if self.components.len() > MAX_RESOURCE_COMPONENTS {
            return Err(ContractError::InvalidField);
        }

        let mut total = 0_usize;
        for component in &self.components {
            validate_resource_component(component)?;
            total = total
                .checked_add(component.len())
                .ok_or(ContractError::InvalidField)?;
        }
        if total > MAX_RESOURCE_COMPONENT_BYTES_PER_ROOT {
            return Err(ContractError::InvalidField);
        }
        Ok(())
    }
}

impl fmt::Debug for ResourceRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceRootV1")
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for ResourceRootV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawResourceRootV1 {
            root_id: String,
            components: Vec<String>,
        }

        let raw = RawResourceRootV1::deserialize(deserializer)?;
        Self::try_new(raw.root_id, raw.components).map_err(de::Error::custom)
    }
}

fn validate_root_id(root_id: &str) -> Result<()> {
    let bytes = root_id.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ROOT_ID_BYTES
        || !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        || !bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidField);
    }
    Ok(())
}

fn validate_resource_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component.len() > MAX_RESOURCE_COMPONENT_BYTES
        || matches!(component, "." | "..")
        || component.nfc().ne(component.chars())
        || component.ends_with([' ', '.'])
        || component.chars().any(forbidden_component_character)
        || is_windows_device_basename(component)
    {
        return Err(ContractError::InvalidField);
    }
    Ok(())
}

fn forbidden_component_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
        )
        || is_default_ignorable(character)
}

fn is_windows_device_basename(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        basename.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || basename
        .strip_prefix("COM")
        .or_else(|| basename.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

fn is_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseSourceKindV1 {
    #[serde(rename = "HUMAN_REQUEST_GRANT")]
    HumanRequestGrant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskIntentionV1 {
    #[serde(rename = "host.file.patch")]
    HostFilePatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationModeV1 {
    #[serde(rename = "DELEGABLE")]
    Delegable,
    #[serde(rename = "NON_DELEGABLE")]
    NonDelegable,
}

impl DelegationModeV1 {
    pub const fn is_delegable(self) -> bool {
        matches!(self, Self::Delegable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevelV1 {
    #[serde(rename = "L0")]
    L0,
    #[serde(rename = "L1")]
    L1,
    #[serde(rename = "L2")]
    L2,
}

impl RiskLevelV1 {
    const fn rank(self) -> u8 {
        match self {
            Self::L0 => 0,
            Self::L1 => 1,
            Self::L2 => 2,
        }
    }

    pub const fn permits(self, candidate: Self) -> bool {
        candidate.rank() <= self.rank()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinimumAuthenticationProfileV1 {
    #[serde(rename = "SESSION_AUTHENTICATED_V1")]
    SessionAuthenticatedV1,
    #[serde(rename = "USER_VERIFICATION_V1")]
    UserVerificationV1,
}

impl MinimumAuthenticationProfileV1 {
    pub const fn permits(self, candidate: Self) -> bool {
        matches!(
            (self, candidate),
            (Self::SessionAuthenticatedV1, _)
                | (Self::UserVerificationV1, Self::UserVerificationV1)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationProfileV1 {
    #[serde(rename = "SESSION_AUTHENTICATED_V1")]
    SessionAuthenticatedV1,
    #[serde(rename = "USER_VERIFICATION_V1")]
    UserVerificationV1,
    #[serde(rename = "SYNTHETIC_CONFORMANCE_V1")]
    SyntheticConformanceV1,
}

impl AuthenticationProfileV1 {
    pub const fn is_production_eligible(self) -> bool {
        !matches!(self, Self::SyntheticConformanceV1)
    }

    pub const fn satisfies(self, minimum: MinimumAuthenticationProfileV1) -> bool {
        match (self, minimum) {
            (Self::SyntheticConformanceV1, _) => false,
            (
                Self::SessionAuthenticatedV1,
                MinimumAuthenticationProfileV1::SessionAuthenticatedV1,
            ) => true,
            (Self::UserVerificationV1, _) => true,
            (Self::SessionAuthenticatedV1, MinimumAuthenticationProfileV1::UserVerificationV1) => {
                false
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecisionValueV1 {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "DENIED")]
    Denied,
}

impl ApprovalDecisionValueV1 {
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }
}

pub(crate) fn require_strictly_before(earlier: SafeU64, later: SafeU64) -> Result<()> {
    if earlier.get() < later.get() {
        return Ok(());
    }
    Err(ContractError::InvalidField)
}

pub(crate) fn require_at_most(value: SafeU64, maximum: SafeU64) -> Result<()> {
    if value.get() <= maximum.get() {
        return Ok(());
    }
    Err(ContractError::InvalidField)
}

pub(crate) fn require_grant_time_bounds(
    issued_at_utc_ms: SafeU64,
    expires_at_utc_ms: SafeU64,
) -> Result<()> {
    require_strictly_before(issued_at_utc_ms, expires_at_utc_ms)
}

pub(crate) fn require_lease_time_bounds(
    issued_at_utc_ms: SafeU64,
    not_before_utc_ms: SafeU64,
    expires_at_utc_ms: SafeU64,
    issued_at_monotonic_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
) -> Result<()> {
    require_at_most(issued_at_utc_ms, not_before_utc_ms)?;
    require_strictly_before(not_before_utc_ms, expires_at_utc_ms)?;
    require_strictly_before(issued_at_monotonic_ms, deadline_monotonic_ms)
}

pub(crate) fn require_decision_time_bounds(
    issued_at_utc_ms: SafeU64,
    expires_at_utc_ms: SafeU64,
    issued_at_monotonic_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
) -> Result<()> {
    require_strictly_before(issued_at_utc_ms, expires_at_utc_ms)?;
    require_strictly_before(issued_at_monotonic_ms, deadline_monotonic_ms)
}

pub(crate) fn require_sorted_unique_identifiers(
    values: &[Identifier],
    minimum: usize,
    maximum: usize,
) -> Result<()> {
    if minimum > maximum || values.len() < minimum || values.len() > maximum {
        return Err(ContractError::InvalidField);
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(ContractError::InvalidField);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test value must be safe")
    }

    #[test]
    fn safe_integer_and_generation_bounds_are_checked() {
        assert_eq!(SafeU64::new(0).unwrap().get(), 0);
        assert_eq!(SafeU64::new(MAX_SAFE_U64).unwrap().get(), MAX_SAFE_U64);
        assert_eq!(
            SafeU64::new(MAX_SAFE_U64 + 1),
            Err(ContractError::InvalidField)
        );
        assert_eq!(
            safe(MAX_SAFE_U64 - 1).checked_add(safe(1)).unwrap().get(),
            MAX_SAFE_U64
        );
        assert_eq!(
            safe(MAX_SAFE_U64).checked_add(safe(1)),
            Err(ContractError::InvalidField)
        );
        assert_eq!(safe(1).checked_sub(safe(1)).unwrap().get(), 0);
        assert_eq!(
            safe(0).checked_sub(safe(1)),
            Err(ContractError::InvalidField)
        );

        assert_eq!(Generation::new(0), Err(ContractError::InvalidField));
        assert_eq!(Generation::new(1).unwrap().get(), 1);
        assert_eq!(Generation::new(MAX_SAFE_U64).unwrap().get(), MAX_SAFE_U64);
        assert_eq!(Generation::new(1).unwrap().checked_next().unwrap().get(), 2);
        assert_eq!(
            Generation::new(MAX_SAFE_U64).unwrap().checked_next(),
            Err(ContractError::InvalidField)
        );
    }

    #[test]
    fn safe_integer_serde_rejects_alternate_json_domains() {
        assert_eq!(serde_json::from_str::<SafeU64>("0").unwrap(), safe(0));
        assert_eq!(
            serde_json::from_str::<SafeU64>(&MAX_SAFE_U64.to_string()).unwrap(),
            safe(MAX_SAFE_U64)
        );
        for invalid in [
            "-1",
            "-0",
            "1.0",
            "1e0",
            "9007199254740992",
            "\"1\"",
            "true",
            "null",
        ] {
            assert!(
                serde_json::from_str::<SafeU64>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn identifiers_are_exact_ascii_and_debug_is_opaque() {
        let alphabet = "-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:";
        assert_eq!(Identifier::new(alphabet).unwrap().as_str(), alphabet);
        assert!(Identifier::new("a".repeat(128)).is_ok());
        for invalid in [String::new(), "a".repeat(129), "a/b".into(), "é".into()] {
            assert_eq!(Identifier::new(invalid), Err(ContractError::InvalidField));
        }
        let identifier = Identifier::new("private-correlation").unwrap();
        let debug = format!("{identifier:?}");
        assert_eq!(debug, "Identifier { .. }");
        assert!(!debug.contains(identifier.as_str()));
    }

    #[test]
    fn nonce_currency_and_depth_use_closed_encodings() {
        let nonce = Nonce128::from_bytes([0xab; 16]);
        assert_eq!(nonce.to_hex(), "ab".repeat(16));
        assert_eq!(Nonce128::parse_hex(&nonce.to_hex()).unwrap(), nonce);
        assert!(Nonce128::parse_hex(&nonce.to_hex().to_uppercase()).is_err());
        assert_eq!(CurrencyCodeV1::new("EUR").unwrap().as_str(), "EUR");
        assert!(CurrencyCodeV1::new("eur").is_err());
        assert_eq!(DelegationDepthV1::new(32).unwrap().get(), 32);
        assert!(DelegationDepthV1::new(33).is_err());
    }

    #[test]
    fn resource_roots_accept_the_opaque_root_and_enforce_byte_limits() {
        assert!(ResourceRootV1::try_new("root-1", Vec::new()).is_ok());
        assert!(ResourceRootV1::try_new("r", vec!["x".to_owned(); 128]).is_ok());
        assert!(ResourceRootV1::try_new("r", vec!["x".to_owned(); 129]).is_err());

        let exact_component = format!("{}a", "é".repeat(127));
        assert_eq!(exact_component.len(), 255);
        assert!(ResourceRootV1::try_new("r", vec![exact_component]).is_ok());
        assert!(ResourceRootV1::try_new("r", vec!["é".repeat(128)]).is_err());

        let mut exact_total = vec!["a".repeat(255); 16];
        exact_total.push("b".repeat(16));
        assert!(ResourceRootV1::try_new("r", exact_total.clone()).is_ok());
        exact_total[16].push('b');
        assert!(ResourceRootV1::try_new("r", exact_total).is_err());
    }

    #[test]
    fn resource_roots_reject_non_nfc_nonportable_and_device_components() {
        for invalid_root in ["", ".root", "Root", "r:", "a".repeat(65).as_str()] {
            assert!(ResourceRootV1::try_new(invalid_root, Vec::new()).is_err());
        }
        for invalid_component in [
            ".",
            "..",
            "e\u{301}",
            "trail.",
            "trail ",
            "a/b",
            "a\\b",
            "a:b",
            "a\u{200b}b",
            "Com1.log",
            "lpt9.txt",
            "COM¹",
        ] {
            assert!(
                ResourceRootV1::try_new("r", vec![invalid_component.to_owned()]).is_err(),
                "{invalid_component}"
            );
        }
        for accepted in ["é", "console.md", "COM0", "COM10.txt", "LPT0", "LPT10"] {
            assert!(
                ResourceRootV1::try_new("r", vec![accepted.to_owned()]).is_ok(),
                "{accepted}"
            );
        }
    }

    #[test]
    fn resource_serde_cannot_bypass_validation() {
        let root: ResourceRootV1 =
            serde_json::from_str(r#"{"root_id":"approved-root","components":[]}"#).unwrap();
        assert_eq!(root.root_id(), "approved-root");
        assert!(root.components().is_empty());
        assert!(serde_json::from_str::<ResourceRootV1>(
            r#"{"root_id":"approved-root","components":[],"extra":true}"#,
        )
        .is_err());
    }

    #[test]
    fn enum_decoding_is_exact_and_synthetic_is_never_production() {
        assert_eq!(
            serde_json::from_str::<DelegationModeV1>("\"DELEGABLE\"").unwrap(),
            DelegationModeV1::Delegable
        );
        assert!(serde_json::from_str::<DelegationModeV1>("\"delegable\"").is_err());
        assert!(serde_json::from_str::<TaskIntentionV1>("\"host.file.read\"").is_err());
        assert!(RiskLevelV1::L2.permits(RiskLevelV1::L1));
        assert!(!RiskLevelV1::L1.permits(RiskLevelV1::L2));
        assert!(MinimumAuthenticationProfileV1::SessionAuthenticatedV1
            .permits(MinimumAuthenticationProfileV1::UserVerificationV1));
        assert!(!MinimumAuthenticationProfileV1::UserVerificationV1
            .permits(MinimumAuthenticationProfileV1::SessionAuthenticatedV1));
        assert!(!AuthenticationProfileV1::SyntheticConformanceV1.is_production_eligible());
        assert!(!AuthenticationProfileV1::SyntheticConformanceV1
            .satisfies(MinimumAuthenticationProfileV1::SessionAuthenticatedV1));
        assert!(AuthenticationProfileV1::UserVerificationV1
            .satisfies(MinimumAuthenticationProfileV1::UserVerificationV1));
        assert!(ApprovalDecisionValueV1::Approved.is_approved());
        assert!(!ApprovalDecisionValueV1::Denied.is_approved());
    }

    #[test]
    fn time_and_parent_bounds_use_checked_exclusive_semantics() {
        assert!(require_grant_time_bounds(safe(1), safe(2)).is_ok());
        assert!(require_grant_time_bounds(safe(1), safe(1)).is_err());
        assert!(require_lease_time_bounds(safe(1), safe(1), safe(2), safe(3), safe(4)).is_ok());
        assert!(require_lease_time_bounds(safe(2), safe(1), safe(3), safe(3), safe(4)).is_err());
        assert!(require_lease_time_bounds(safe(1), safe(2), safe(2), safe(3), safe(4)).is_err());
        assert!(require_lease_time_bounds(safe(1), safe(2), safe(3), safe(4), safe(4)).is_err());
        assert!(require_decision_time_bounds(safe(1), safe(2), safe(3), safe(4)).is_ok());
        assert!(require_decision_time_bounds(safe(1), safe(1), safe(3), safe(4)).is_err());
        assert!(require_decision_time_bounds(safe(1), safe(2), safe(4), safe(4)).is_err());
        assert!(require_at_most(safe(4), safe(4)).is_ok());
        assert!(require_at_most(safe(5), safe(4)).is_err());
    }

    #[test]
    fn identifier_sets_require_strict_ascii_order_and_cardinality() {
        let sorted = [Identifier::new("a").unwrap(), Identifier::new("b").unwrap()];
        assert!(require_sorted_unique_identifiers(&sorted, 1, 256).is_ok());
        let duplicate = [Identifier::new("a").unwrap(), Identifier::new("a").unwrap()];
        assert!(require_sorted_unique_identifiers(&duplicate, 1, 256).is_err());
        let reversed = [Identifier::new("b").unwrap(), Identifier::new("a").unwrap()];
        assert!(require_sorted_unique_identifiers(&reversed, 1, 256).is_err());
        assert!(require_sorted_unique_identifiers(&[], 1, 256).is_err());
    }
}
