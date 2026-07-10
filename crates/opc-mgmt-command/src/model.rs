use std::fmt;

use crate::ModelError;

const MAX_COMMAND_ID_BYTES: usize = 160;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_ARGUMENT_VALUE_BYTES: usize = 256;
const MAX_HELP_BYTES: usize = 4096;
const MAX_SCHEMA_PATH_BYTES: usize = 1024;

/// Stable namespaced command identity used by audit and compatibility.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandId(String);

impl CommandId {
    /// Constructs a dot-namespaced ID such as `opc.show-health`.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("command_id", &value, MAX_COMMAND_ID_BYTES)?;
        if !value.contains('.') || !value.split('.').all(valid_identifier) {
            return Err(ModelError::Malformed {
                field: "command_id",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable wire/audit form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic version of one stable command identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandVersion(u32);

impl CommandVersion {
    /// Constructs a non-zero command version.
    pub const fn new(value: u32) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::Zero {
                field: "command_version",
            });
        }
        Ok(Self(value))
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One visible literal token in the command grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandToken(String);

impl CommandToken {
    /// Constructs a lowercase CLI token.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("command_token", &value, MAX_TOKEN_BYTES)?;
        if !valid_identifier(&value) {
            return Err(ModelError::Malformed {
                field: "command_token",
            });
        }
        Ok(Self(value))
    }

    /// Returns the token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Name of a typed grammar argument.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgumentName(String);

impl ArgumentName {
    /// Constructs a lowercase argument name.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("argument_name", &value, MAX_TOKEN_BYTES)?;
        if !valid_identifier(&value) {
            return Err(ModelError::Malformed {
                field: "argument_name",
            });
        }
        Ok(Self(value))
    }

    /// Returns the argument name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One static enumeration or completion value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgumentValue(String);

impl ArgumentValue {
    /// Constructs a bounded, terminal-safe static value.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("argument_value", &value, MAX_ARGUMENT_VALUE_BYTES)?;
        if value.trim() != value || value.chars().any(unsafe_terminal_char) {
            return Err(ModelError::Malformed {
                field: "argument_value",
            });
        }
        Ok(Self(value))
    }

    /// Returns the static value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Plain terminal-safe help, heading, or example text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HelpText(String);

impl HelpText {
    /// Constructs bounded text with no control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("help_text", &value, MAX_HELP_BYTES)?;
        if value.trim() != value || value.chars().any(unsafe_terminal_char) {
            return Err(ModelError::Malformed { field: "help_text" });
        }
        Ok(Self(value))
    }

    /// Returns the text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Static predicate-free schema or action path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaPath(String);

impl SchemaPath {
    /// Constructs an absolute, predicate-free path.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("schema_path", &value, MAX_SCHEMA_PATH_BYTES)?;
        if !valid_schema_path(&value) {
            return Err(ModelError::Malformed {
                field: "schema_path",
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical schema path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable capability/model requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Constructs a bounded capability identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded("capability_id", &value, MAX_COMMAND_ID_BYTES)?;
        if !value.split('.').all(valid_identifier) {
            return Err(ModelError::Malformed {
                field: "capability_id",
            });
        }
        Ok(Self(value))
    }

    /// Returns the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_bounded(field: &'static str, value: &str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field, max });
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn valid_schema_path(value: &str) -> bool {
    if !value.starts_with('/')
        || value.ends_with('/')
        || value.contains('[')
        || value.contains(']')
        || value.chars().any(char::is_control)
    {
        return false;
    }

    value[1..].split('/').all(|segment| {
        if segment.is_empty() {
            return false;
        }
        match segment.split_once(':') {
            Some((prefix, name)) => {
                !name.contains(':')
                    && valid_schema_identifier(prefix)
                    && valid_schema_identifier(name)
            }
            None => valid_schema_identifier(segment),
        }
    })
}

fn unsafe_terminal_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn valid_schema_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_command_identifiers() {
        assert_eq!(
            CommandId::new("epdg.show-ike").expect("valid id").as_str(),
            "epdg.show-ike"
        );
        for invalid in ["show", "EPDG.show", "epdg..show", "epdg.show_ike"] {
            assert!(CommandId::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn schema_paths_are_absolute_and_predicate_free() {
        assert!(SchemaPath::new("/epdg:state/epdg:peers").is_ok());
        for invalid in [
            "epdg:state",
            "/epdg:state/",
            "/epdg:state//epdg:peers",
            "/epdg:state/epdg:peer[id='one']",
            "/epdg:state/9peer",
            "/epdg:state/peer name",
        ] {
            assert!(SchemaPath::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn text_rejects_terminal_controls() {
        assert!(HelpText::new("Display health").is_ok());
        assert!(HelpText::new("Display\u{1b}[31mhealth").is_err());
        assert!(HelpText::new("Display \u{202e}health").is_err());
        assert!(ArgumentValue::new("peer\nname").is_err());
    }
}
