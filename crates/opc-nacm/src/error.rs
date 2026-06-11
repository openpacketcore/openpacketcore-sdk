use thiserror::Error;

/// Parse or evaluation failure for the OpenPacketCore NACM model.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}: {message}")]
pub struct NacmError {
    kind: &'static str,
    message: String,
}

impl NacmError {
    pub(crate) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the stable category label associated with the failure.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the human-readable validation or evaluation message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
