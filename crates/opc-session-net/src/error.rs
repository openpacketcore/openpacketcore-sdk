#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: u32, remote: u32 },
    #[error("session protocol contract profile mismatch")]
    ContractMismatch,
    #[error("session protocol value is outside the fixed-width contract")]
    InvalidWireValue,
    #[error("peer authentication failed")]
    Authentication,
    #[error("unexpected protocol response")]
    UnexpectedResponse,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
}
