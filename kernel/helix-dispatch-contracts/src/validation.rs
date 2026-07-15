use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

pub const MAX_SAFE_U64: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeU64(u64);

impl SafeU64 {
    pub fn new(value: u64) -> Result<Self> {
        (value <= MAX_SAFE_U64)
            .then_some(Self(value))
            .ok_or(ContractError::InvalidField)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for SafeU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SafeU64(<redacted>)")
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
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(SafeU64);

impl Generation {
    pub fn new(value: u64) -> Result<Self> {
        let value = SafeU64::new(value)?;
        (value.get() != 0)
            .then_some(Self(value))
            .ok_or(ContractError::InvalidField)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Generation(<redacted>)")
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
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRefV1 {
    root_id: String,
    components: Vec<String>,
}

impl fmt::Debug for ResourceRefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceRefV1")
            .finish_non_exhaustive()
    }
}

impl ResourceRefV1 {
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
        let root = self.root_id.as_bytes();
        if root.is_empty()
            || root.len() > 64
            || !root[0].is_ascii_lowercase() && !root[0].is_ascii_digit()
            || !root.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(ContractError::InvalidField);
        }
        if self.components.is_empty() || self.components.len() > 128 {
            return Err(ContractError::InvalidField);
        }
        let mut total = 0_usize;
        for component in &self.components {
            total = total
                .checked_add(component.len())
                .ok_or(ContractError::InvalidField)?;
            if !valid_component(component) {
                return Err(ContractError::InvalidField);
            }
        }
        (total <= 4_096)
            .then_some(())
            .ok_or(ContractError::InvalidField)
    }
}

fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || component.len() > 255
        || matches!(component, "." | "..")
        || component.nfc().ne(component.chars())
        || component.ends_with([' ', '.'])
        || component.chars().any(forbidden_component_character)
    {
        return false;
    }
    let basename = component.split('.').next().unwrap_or_default();
    !matches!(
        basename.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) && !basename
        .strip_prefix("COM")
        .or_else(|| basename.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

fn forbidden_component_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
        )
        || is_default_ignorable(character)
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

pub(crate) fn valid_media_type(value: &str) -> bool {
    if value.len() < 3 || value.len() > 127 {
        return false;
    }
    let mut parts = value.split('/');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !kind.is_empty()
        && kind.len() <= 63
        && !subtype.is_empty()
        && subtype.len() <= 63
        && kind.bytes().chain(subtype.bytes()).all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}
