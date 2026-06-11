use std::{fmt, str::FromStr};

use crate::NacmError;

/// Distinct NACM operations evaluated independently for a normalized YANG path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NacmAction {
    Read,
    Create,
    Update,
    Replace,
    Delete,
    Exec,
    Subscribe,
    SecurityAdmin,
    Request,
    Approve,
    Activate,
    Revoke,
}

impl NacmAction {
    pub const ALL: [Self; 12] = [
        Self::Read,
        Self::Create,
        Self::Update,
        Self::Replace,
        Self::Delete,
        Self::Exec,
        Self::Subscribe,
        Self::SecurityAdmin,
        Self::Request,
        Self::Approve,
        Self::Activate,
        Self::Revoke,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Update => "update",
            Self::Replace => "replace",
            Self::Delete => "delete",
            Self::Exec => "exec",
            Self::Subscribe => "subscribe",
            Self::SecurityAdmin => "security-admin",
            Self::Request => "request",
            Self::Approve => "approve",
            Self::Activate => "activate",
            Self::Revoke => "revoke",
        }
    }
}

impl fmt::Display for NacmAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NacmAction {
    type Err = NacmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "replace" => Ok(Self::Replace),
            "delete" => Ok(Self::Delete),
            "exec" => Ok(Self::Exec),
            "subscribe" => Ok(Self::Subscribe),
            "security-admin" => Ok(Self::SecurityAdmin),
            "request" => Ok(Self::Request),
            "approve" => Ok(Self::Approve),
            "activate" => Ok(Self::Activate),
            "revoke" => Ok(Self::Revoke),
            _ => Err(NacmError::new(
                "nacm action",
                format!("unknown action '{value}'"),
            )),
        }
    }
}
