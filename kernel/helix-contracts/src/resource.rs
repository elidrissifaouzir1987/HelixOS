use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

const MAX_ROOT_ID_LEN: usize = 64;
const MAX_COMPONENTS: usize = 128;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_TOTAL_COMPONENT_BYTES: usize = 4096;

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRefV1 {
    root_id: String,
    components: Vec<String>,
}

impl fmt::Debug for ResourceRefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_component_bytes = self.components.iter().map(String::len).sum::<usize>();
        formatter
            .debug_struct("ResourceRefV1")
            .field("root_id_length", &self.root_id.len())
            .field("component_count", &self.components.len())
            .field("total_component_bytes", &total_component_bytes)
            .finish_non_exhaustive()
    }
}

impl ResourceRefV1 {
    pub fn new<I, S>(root_id: impl Into<String>, components: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let root_id = root_id.into();
        validate_root_id(&root_id)?;
        let components: Vec<String> = components.into_iter().map(Into::into).collect();
        if components.is_empty() || components.len() > MAX_COMPONENTS {
            return Err(ContractError::invalid(
                "target.components",
                "must contain a bounded non-empty relative path",
            ));
        }
        let mut total = 0_usize;
        for component in &components {
            validate_component(component)?;
            total = total.saturating_add(component.len());
            if total > MAX_TOTAL_COMPONENT_BYTES {
                return Err(ContractError::invalid(
                    "target.components",
                    "combined component bytes exceed the portable bound",
                ));
            }
        }
        Ok(Self {
            root_id,
            components,
        })
    }

    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub fn canonical_uri(&self) -> String {
        let encoded = self
            .components
            .iter()
            .map(|component| percent_encode(component.as_bytes()))
            .collect::<Vec<_>>()
            .join("/");
        format!("helixfs://{}/{encoded}", self.root_id)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.root_id.clone(), self.components.clone()).map(|_| ())
    }
}

impl<'de> Deserialize<'de> for ResourceRefV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawResourceRef {
            root_id: String,
            components: Vec<String>,
        }

        let raw = RawResourceRef::deserialize(deserializer)?;
        Self::new(raw.root_id, raw.components).map_err(de::Error::custom)
    }
}

fn validate_root_id(root_id: &str) -> Result<()> {
    if root_id.is_empty() || root_id.len() > MAX_ROOT_ID_LEN {
        return Err(ContractError::invalid(
            "target.root_id",
            "empty or exceeds 64 ASCII characters",
        ));
    }
    let mut bytes = root_id.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ContractError::invalid(
            "target.root_id",
            "must be a lowercase portable ASCII token",
        ));
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<()> {
    if component.is_empty() || component.len() > MAX_COMPONENT_BYTES {
        return Err(ContractError::invalid(
            "target.components",
            "component is empty or exceeds 255 UTF-8 bytes",
        ));
    }
    if matches!(component, "." | "..") {
        return Err(ContractError::invalid(
            "target.components",
            "dot traversal is forbidden",
        ));
    }
    if component.nfc().ne(component.chars()) {
        return Err(ContractError::invalid(
            "target.components",
            "component is not Unicode NFC",
        ));
    }
    if component.ends_with([' ', '.']) {
        return Err(ContractError::invalid(
            "target.components",
            "trailing space or dot is not portable",
        ));
    }
    if component.chars().any(|character| {
        character.is_control()
            || is_default_ignorable(character)
            || matches!(
                character,
                '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
            )
    }) {
        return Err(ContractError::invalid(
            "target.components",
            "component contains a separator, control, bidi, ADS, or forbidden character",
        ));
    }
    if is_windows_device_name(component) {
        return Err(ContractError::invalid(
            "target.components",
            "Windows device basename is not portable",
        ));
    }
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or(component)
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
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{00b9}"
                    | "\u{00b2}"
                    | "\u{00b3}"
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

fn percent_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}
