//! Error types for the persistence layer.

use thiserror::Error;

/// Bounded consensus RPC families used in timeout diagnostics.
///
/// These values are intentionally independent of request data so they are safe
/// to use as low-cardinality telemetry labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusRpcFamily {
    /// Raft vote request.
    RequestVote,
    /// Raft log replication or heartbeat request.
    AppendEntries,
    /// Raft snapshot installation request.
    InstallSnapshot,
    /// Read the latest committed configuration.
    LoadLatest,
    /// Read a selected rollback configuration.
    LoadRollback,
    /// Raft leadership-transfer trigger.
    TimeoutNow,
}

impl ConsensusRpcFamily {
    pub(crate) const ALL: [Self; 6] = [
        Self::RequestVote,
        Self::AppendEntries,
        Self::InstallSnapshot,
        Self::LoadLatest,
        Self::LoadRollback,
        Self::TimeoutNow,
    ];

    pub(crate) const fn metric_index(self) -> usize {
        match self {
            Self::RequestVote => 0,
            Self::AppendEntries => 1,
            Self::InstallSnapshot => 2,
            Self::LoadLatest => 3,
            Self::LoadRollback => 4,
            Self::TimeoutNow => 5,
        }
    }

    /// Returns the stable, low-cardinality telemetry label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestVote => "request_vote",
            Self::AppendEntries => "append_entries",
            Self::InstallSnapshot => "install_snapshot",
            Self::LoadLatest => "load_latest",
            Self::LoadRollback => "load_rollback",
            Self::TimeoutNow => "timeout_now",
        }
    }
}

impl std::fmt::Display for ConsensusRpcFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded consensus transport stages used in timeout diagnostics.
///
/// Values do not contain endpoints, identities, request fields, or other
/// untrusted/high-cardinality data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusRpcStage {
    /// Establish and validate the absolute deadline.
    DeadlineSetup,
    /// Read the peer authentication configuration.
    AuthenticationSetup,
    /// Serialize and frame the request.
    RequestSerialization,
    /// Read or build the current client TLS configuration.
    TlsConfiguration,
    /// Establish the TCP connection.
    TcpConnect,
    /// Complete the mutual-TLS handshake.
    TlsHandshake,
    /// Write the framed request.
    RequestWrite,
    /// Read the response frame length.
    ResponseLength,
    /// Read the response frame body.
    ResponseBody,
    /// Decode the authenticated response.
    ResponseDecode,
    /// Wait before a retry.
    RetryBackoff,
}

impl ConsensusRpcStage {
    pub(crate) const ALL: [Self; 11] = [
        Self::DeadlineSetup,
        Self::AuthenticationSetup,
        Self::RequestSerialization,
        Self::TlsConfiguration,
        Self::TcpConnect,
        Self::TlsHandshake,
        Self::RequestWrite,
        Self::ResponseLength,
        Self::ResponseBody,
        Self::ResponseDecode,
        Self::RetryBackoff,
    ];

    pub(crate) const fn metric_index(self) -> usize {
        match self {
            Self::DeadlineSetup => 0,
            Self::AuthenticationSetup => 1,
            Self::RequestSerialization => 2,
            Self::TlsConfiguration => 3,
            Self::TcpConnect => 4,
            Self::TlsHandshake => 5,
            Self::RequestWrite => 6,
            Self::ResponseLength => 7,
            Self::ResponseBody => 8,
            Self::ResponseDecode => 9,
            Self::RetryBackoff => 10,
        }
    }

    /// Returns the stable, low-cardinality telemetry label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeadlineSetup => "deadline_setup",
            Self::AuthenticationSetup => "authentication_setup",
            Self::RequestSerialization => "request_serialization",
            Self::TlsConfiguration => "tls_configuration",
            Self::TcpConnect => "tcp_connect",
            Self::TlsHandshake => "tls_handshake",
            Self::RequestWrite => "request_write",
            Self::ResponseLength => "response_length",
            Self::ResponseBody => "response_body",
            Self::ResponseDecode => "response_decode",
            Self::RetryBackoff => "retry_backoff",
        }
    }
}

impl std::fmt::Display for ConsensusRpcStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent error kinds that survive serialization to logs and telemetry.
#[derive(Debug, Clone, Error)]
pub enum PersistErrorKind {
    /// Storage preflight failed — deployment does not meet durability requirements.
    #[error("preflight failed: {0}")]
    PreflightFailed(String),
    /// The requested rollback target does not exist.
    #[error("rollback target not found")]
    RollbackNotFound,
    /// WAL recovery failed — the database is corrupt or from an incompatible version.
    #[error("WAL recovery failed — database may be corrupt")]
    WalRecoveryFailed,
    /// The encrypted blob is corrupt or fails AEAD authentication.
    #[error("encrypted blob is corrupt or authentication failed")]
    CorruptBlob,
    /// The audit hash chain is broken or an entry fails HMAC verification.
    #[error("audit hash chain is broken or HMAC verification failed")]
    AuditChainBroken,
    /// The database is in an inconsistent state requiring manual recovery.
    #[error("inconsistent state: {0}")]
    InconsistentState(String),
    /// A foreign-key constraint was violated.
    #[error("foreign key constraint violated")]
    ForeignKeyViolation,
    /// A database constraint (unique, check) was violated.
    #[error("constraint violated: {0}")]
    ConstraintViolation(String),
    /// The storage path is not writable or does not exist.
    #[error("path not writable: {0}")]
    PathNotWritable(String),
    /// The database is locked by another writer.
    #[error("database is locked by another writer")]
    DatabaseLocked,
    /// Free space is below the configured threshold.
    #[error("out of space: {available} bytes available, {required} required")]
    OutOfSpace { available: u64, required: u64 },
    /// An I/O error occurred (fsync, read, write).
    #[error("I/O error: {0}")]
    Io(String),
    /// One logical consensus RPC exhausted its single end-to-end deadline.
    #[error("consensus RPC logical timeout family={family} stage={stage}")]
    ConsensusRpcTimeout {
        /// Bounded request family for diagnostics.
        family: ConsensusRpcFamily,
        /// Bounded stage at which the deadline was observed.
        stage: ConsensusRpcStage,
    },
    /// The schema version in the database does not match the expected version.
    #[error("schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch { expected: String, found: String },
    /// The stored schema digest does not match the live SQLite schema.
    #[error("schema digest mismatch: expected {expected}, found {found}")]
    SchemaDigestMismatch { expected: String, found: String },
    /// A rusqlite error that does not fit another category.
    #[error("SQLite error: {0}")]
    Sqlite(String),
}

/// Stable, domain-typed persistence error.
///
/// Error strings MUST NOT contain raw config blobs, secret key material, or
/// unredacted principal identities. All internal detail is captured in
/// `PersistErrorKind`; `Display` output is kept stable and sanitized.
#[derive(Debug, Clone)]
pub struct PersistError {
    kind: PersistErrorKind,
}

fn sanitize_error_message(msg: &str) -> String {
    let mut sanitized = Vec::new();
    let mut redacting_sql_tail = false;

    for token in msg.split_whitespace() {
        if token.is_empty() {
            continue;
        }

        let lower = token.to_ascii_lowercase();
        if redacting_sql_tail || token_needs_redaction(token, &lower) {
            if sanitized.last().is_none_or(|last| last != "<redacted>") {
                sanitized.push("<redacted>".to_string());
            }
            if is_sql_start(&lower) {
                redacting_sql_tail = true;
            }
            continue;
        }

        if is_sql_start(&lower) {
            redacting_sql_tail = true;
            if sanitized.last().is_none_or(|last| last != "<redacted>") {
                sanitized.push("<redacted>".to_string());
            }
            continue;
        }

        sanitized.push(token.to_string());
    }

    sanitized.join(" ")
}

fn token_needs_redaction(token: &str, lower: &str) -> bool {
    let clean = token.trim_matches(|c: char| {
        c == '\''
            || c == '"'
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
            || c == ','
            || c == '.'
            || c == ';'
            || c == ':'
    });
    let clean_lower = clean.to_ascii_lowercase();

    clean.contains('/')
        || clean.contains('\\')
        || clean_lower.contains(".db")
        || clean_lower.contains(".sqlite")
        || clean_lower.contains("spiffe://")
        || clean_lower.contains("-----begin")
        || clean_lower.contains("secret")
        || clean_lower.contains("sensitive")
        || clean_lower.contains("password")
        || clean_lower.contains("token")
        || clean_lower.starts_with("path=")
        || clean_lower.starts_with("sql=")
        || clean_lower.starts_with("key=")
        || looks_like_sensitive_identifier(clean, &clean_lower)
        || looks_like_ipv4(clean)
        || is_sql_start(lower)
}

fn is_sql_start(lower: &str) -> bool {
    let clean = lower.trim_matches(|c: char| {
        c == '\''
            || c == '"'
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
            || c == ','
            || c == '.'
            || c == ';'
            || c == ':'
    });
    matches!(
        clean,
        "select" | "insert" | "update" | "delete" | "pragma" | "from" | "where"
    ) || clean.starts_with("sql=")
}

fn looks_like_sensitive_identifier(clean: &str, clean_lower: &str) -> bool {
    const ID_MARKERS: [&str; 6] = ["supi", "gpsi", "imsi", "msisdn", "guti", "pei"];
    if ID_MARKERS.iter().any(|marker| {
        clean_lower == *marker
            || clean_lower.starts_with(&format!("{marker}-"))
            || clean_lower.starts_with(&format!("{marker}_"))
            || clean_lower
                .strip_prefix(marker)
                .and_then(|suffix| suffix.chars().next())
                .is_some_and(|c| c.is_ascii_digit())
    }) {
        return true;
    }

    clean.len() >= 8 && clean.chars().all(|c| c.is_ascii_digit())
}

fn looks_like_ipv4(clean: &str) -> bool {
    let parts = clean.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|c| c.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = format!("{}", self.kind);
        let sanitized = sanitize_error_message(&raw);
        write!(f, "persist error: {sanitized}")
    }
}

impl std::error::Error for PersistError {}

impl PersistError {
    /// Construct a typed persistence error.
    pub fn new(kind: PersistErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable error kind.
    pub fn kind(&self) -> &PersistErrorKind {
        &self.kind
    }

    pub fn preflight_failed(msg: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::PreflightFailed(msg.into()))
    }

    pub fn rollback_not_found() -> Self {
        Self::new(PersistErrorKind::RollbackNotFound)
    }

    pub fn wal_recovery_failed() -> Self {
        Self::new(PersistErrorKind::WalRecoveryFailed)
    }

    pub fn corrupt_blob() -> Self {
        Self::new(PersistErrorKind::CorruptBlob)
    }

    pub fn audit_chain_broken() -> Self {
        Self::new(PersistErrorKind::AuditChainBroken)
    }

    pub fn inconsistent_state(msg: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::InconsistentState(msg.into()))
    }

    pub fn foreign_key_violation() -> Self {
        Self::new(PersistErrorKind::ForeignKeyViolation)
    }

    pub fn constraint_violation(name: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::ConstraintViolation(name.into()))
    }

    pub fn path_not_writable(path: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::PathNotWritable(path.into()))
    }

    pub fn database_locked() -> Self {
        Self::new(PersistErrorKind::DatabaseLocked)
    }

    pub fn out_of_space(available: u64, required: u64) -> Self {
        Self::new(PersistErrorKind::OutOfSpace {
            available,
            required,
        })
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::Io(msg.into()))
    }

    /// Construct a typed logical consensus RPC timeout.
    pub fn consensus_rpc_timeout(family: ConsensusRpcFamily, stage: ConsensusRpcStage) -> Self {
        Self::new(PersistErrorKind::ConsensusRpcTimeout { family, stage })
    }

    /// Returns the bounded family/stage labels for a logical RPC timeout.
    pub fn consensus_rpc_timeout_context(&self) -> Option<(ConsensusRpcFamily, ConsensusRpcStage)> {
        match self.kind() {
            PersistErrorKind::ConsensusRpcTimeout { family, stage } => Some((*family, *stage)),
            _ => None,
        }
    }

    /// Returns whether this error represents expiry of one logical RPC deadline.
    pub fn is_consensus_rpc_timeout(&self) -> bool {
        self.consensus_rpc_timeout_context().is_some()
    }

    pub fn schema_version_mismatch(expected: impl Into<String>, found: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::SchemaVersionMismatch {
            expected: expected.into(),
            found: found.into(),
        })
    }

    pub fn schema_digest_mismatch(expected: impl Into<String>, found: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::SchemaDigestMismatch {
            expected: expected.into(),
            found: found.into(),
        })
    }

    pub fn sqlite(msg: impl Into<String>) -> Self {
        Self::new(PersistErrorKind::Sqlite(msg.into()))
    }
}

impl From<rusqlite::Error> for PersistError {
    fn from(err: rusqlite::Error) -> Self {
        match &err {
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::DatabaseLocked
                    || code.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                Self::database_locked()
            }
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::DiskFull =>
            {
                Self::out_of_space(0, 1)
            }
            rusqlite::Error::SqliteFailure(_code, msg) => {
                let msg = msg.as_deref().unwrap_or("");
                if msg.contains("FOREIGN KEY constraint failed") {
                    Self::foreign_key_violation()
                } else if msg.contains("UNIQUE constraint failed")
                    || msg.contains("CHECK constraint failed")
                {
                    Self::constraint_violation(msg)
                } else {
                    Self::sqlite(err.to_string())
                }
            }
            _ => Self::sqlite(err.to_string()),
        }
    }
}

impl From<std::io::Error> for PersistError {
    fn from(err: std::io::Error) -> Self {
        Self::io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusRpcFamily, ConsensusRpcStage, PersistError};

    #[test]
    fn display_redacts_sensitive_storage_details() {
        let err = PersistError::sqlite(
            "database disk image is malformed: path=/var/lib/opc/tenant-a/secret-key.db \
             sql=SELECT * FROM config_history WHERE tenant_id='imsi-001010123456789' \
             token=super-secret-token host=10.0.0.1",
        );
        let displayed = err.to_string();

        assert!(displayed.starts_with("persist error: SQLite error:"));
        for leak in [
            "/var/lib",
            "secret-key",
            ".db",
            "SELECT",
            "config_history",
            "tenant_id",
            "imsi-001010123456789",
            "super-secret-token",
            "10.0.0.1",
        ] {
            assert!(
                !displayed.contains(leak),
                "displayed error leaked {leak}: {displayed}"
            );
        }
        assert!(displayed.contains("<redacted>"));
    }

    #[test]
    fn display_preserves_safe_operational_context() {
        let err = PersistError::inconsistent_state("majority consensus quorum not reached");
        assert_eq!(
            err.to_string(),
            "persist error: inconsistent state: majority consensus quorum not reached"
        );
    }

    #[test]
    fn logical_rpc_timeout_exposes_only_bounded_safe_labels() {
        let err = PersistError::consensus_rpc_timeout(
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcStage::ResponseBody,
        );

        assert_eq!(
            err.to_string(),
            "persist error: consensus RPC logical timeout family=install_snapshot stage=response_body"
        );
    }
}
