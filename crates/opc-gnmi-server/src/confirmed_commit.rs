//! OpenPacketCore gNMI commit-confirmed registered extension.
//!
//! OpenConfig gNMI v0.10.0 defines the registered extension envelope but does
//! not standardize confirmed-commit semantics. OpenPacketCore therefore uses
//! the experimental registered extension ID with a protobuf payload whose name
//! is advertised in the SDK docs/specs, not in the OpenConfig proto enum.

#![allow(clippy::derive_partial_eq_without_eq)]

use std::time::Duration;

use prost::Message;

use crate::{
    proto::gnmi_ext::{self, extension::Ext},
    GnmiError,
};

/// OpenPacketCore commit-confirmed extension ID.
///
/// The vendored OpenConfig proto exposes no production registered ID for this
/// behavior, so OpenPacketCore deliberately uses `EID_EXPERIMENTAL` (999) until
/// a real upstream allocation exists.
pub const OPC_COMMIT_CONFIRMED_EXTENSION_ID: u32 = 999;

/// Capability/registry name for the OpenPacketCore commit-confirmed extension.
pub const OPC_COMMIT_CONFIRMED_EXTENSION_NAME: &str = "openpacketcore.commit-confirmed.v1";

/// Default timeout used when a begin-confirmed payload omits `timeout_nanos`.
pub const DEFAULT_COMMIT_CONFIRMED_TIMEOUT: Duration = Duration::from_secs(600);

/// Protobuf payload carried in `gnmi_ext.RegisteredExtension.msg`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CommitConfirmedExtension {
    /// Requested confirmed-commit action.
    #[prost(enumeration = "CommitConfirmedAction", tag = "1")]
    pub action: i32,
    /// Optional timeout for `BEGIN`, in nanoseconds. Zero means the SDK default.
    #[prost(uint64, tag = "2")]
    pub timeout_nanos: u64,
}

impl CommitConfirmedExtension {
    /// Builds a begin-confirmed payload.
    pub fn begin(timeout: Duration) -> Result<Self, GnmiError> {
        let timeout_nanos = timeout.as_nanos().try_into().map_err(|_| {
            GnmiError::invalid("OpenPacketCore commit-confirmed timeout is too large")
        })?;
        Ok(Self {
            action: CommitConfirmedAction::Begin as i32,
            timeout_nanos,
        })
    }

    /// Builds a confirm-pending payload.
    pub const fn confirm() -> Self {
        Self {
            action: CommitConfirmedAction::Confirm as i32,
            timeout_nanos: 0,
        }
    }

    /// Builds a cancel-pending payload.
    pub const fn cancel() -> Self {
        Self {
            action: CommitConfirmedAction::Cancel as i32,
            timeout_nanos: 0,
        }
    }

    /// Encodes this payload for `gnmi_ext.RegisteredExtension.msg`.
    pub fn encode_payload(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

/// Commit-confirmed action carried by [`CommitConfirmedExtension`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CommitConfirmedAction {
    /// Invalid/default action.
    Unspecified = 0,
    /// Apply the Set request as a pending confirmed commit.
    Begin = 1,
    /// Confirm the currently pending confirmed commit.
    Confirm = 2,
    /// Cancel and roll back the currently pending confirmed commit.
    Cancel = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetCommitExtension {
    Normal,
    Begin { timeout: Duration },
    Confirm,
    Cancel,
}

pub(crate) fn parse_set_commit_extension(
    extensions: &[gnmi_ext::Extension],
) -> Result<SetCommitExtension, GnmiError> {
    let mut parsed = SetCommitExtension::Normal;
    for extension in extensions {
        let Some(registered) = commit_confirmed_registered_extension(extension) else {
            continue;
        };
        if parsed != SetCommitExtension::Normal {
            return Err(GnmiError::invalid(
                "duplicate OpenPacketCore gNMI commit-confirmed extension",
            ));
        }
        parsed = parse_payload(&registered.msg)?;
    }
    Ok(parsed)
}

pub(crate) fn reject_set_only_extension(
    extensions: &[gnmi_ext::Extension],
) -> Result<(), GnmiError> {
    if extensions
        .iter()
        .any(|extension| commit_confirmed_registered_extension(extension).is_some())
    {
        return Err(GnmiError::unimplemented(
            "OpenPacketCore gNMI commit-confirmed extension is only supported on Set",
        ));
    }
    Ok(())
}

pub(crate) fn is_implemented_extension(id: u32, name: &str) -> bool {
    id == OPC_COMMIT_CONFIRMED_EXTENSION_ID && name == OPC_COMMIT_CONFIRMED_EXTENSION_NAME
}

fn commit_confirmed_registered_extension(
    extension: &gnmi_ext::Extension,
) -> Option<&gnmi_ext::RegisteredExtension> {
    let Some(Ext::RegisteredExt(registered)) = extension.ext.as_ref() else {
        return None;
    };
    (registered.id == OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32).then_some(registered)
}

fn parse_payload(payload: &[u8]) -> Result<SetCommitExtension, GnmiError> {
    let message = CommitConfirmedExtension::decode(payload)
        .map_err(|_| GnmiError::invalid("invalid OpenPacketCore commit-confirmed payload"))?;
    let action = CommitConfirmedAction::try_from(message.action)
        .map_err(|_| GnmiError::invalid("invalid OpenPacketCore commit-confirmed action"))?;
    match action {
        CommitConfirmedAction::Unspecified => Err(GnmiError::invalid(
            "invalid OpenPacketCore commit-confirmed action",
        )),
        CommitConfirmedAction::Begin => Ok(SetCommitExtension::Begin {
            timeout: timeout_from_nanos(message.timeout_nanos),
        }),
        CommitConfirmedAction::Confirm if message.timeout_nanos == 0 => {
            Ok(SetCommitExtension::Confirm)
        }
        CommitConfirmedAction::Cancel if message.timeout_nanos == 0 => {
            Ok(SetCommitExtension::Cancel)
        }
        CommitConfirmedAction::Confirm | CommitConfirmedAction::Cancel => Err(GnmiError::invalid(
            "OpenPacketCore commit-confirmed timeout is only valid for begin",
        )),
    }
}

fn timeout_from_nanos(nanos: u64) -> Duration {
    if nanos == 0 {
        DEFAULT_COMMIT_CONFIRMED_TIMEOUT
    } else {
        Duration::from_nanos(nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered(payload: CommitConfirmedExtension) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(Ext::RegisteredExt(gnmi_ext::RegisteredExtension {
                id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                msg: payload.encode_payload(),
            })),
        }
    }

    #[test]
    fn parses_begin_confirm_and_cancel_payloads() {
        assert_eq!(
            parse_set_commit_extension(&[registered(
                CommitConfirmedExtension::begin(Duration::from_secs(30)).expect("payload")
            )])
            .expect("begin"),
            SetCommitExtension::Begin {
                timeout: Duration::from_secs(30)
            }
        );
        assert_eq!(
            parse_set_commit_extension(&[registered(CommitConfirmedExtension::confirm())])
                .expect("confirm"),
            SetCommitExtension::Confirm
        );
        assert_eq!(
            parse_set_commit_extension(&[registered(CommitConfirmedExtension::cancel())])
                .expect("cancel"),
            SetCommitExtension::Cancel
        );
    }

    #[test]
    fn defaults_begin_timeout_when_omitted() {
        let payload = CommitConfirmedExtension {
            action: CommitConfirmedAction::Begin as i32,
            timeout_nanos: 0,
        };
        assert_eq!(
            parse_set_commit_extension(&[registered(payload)]).expect("begin"),
            SetCommitExtension::Begin {
                timeout: DEFAULT_COMMIT_CONFIRMED_TIMEOUT
            }
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_payloads_without_leak() {
        let malformed = gnmi_ext::Extension {
            ext: Some(Ext::RegisteredExt(gnmi_ext::RegisteredExtension {
                id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                msg: b"secret-bad-payload".to_vec(),
            })),
        };
        let err = parse_set_commit_extension(&[malformed]).unwrap_err();
        assert_eq!(err.status().as_str(), "INVALID_ARGUMENT");
        assert!(!err.to_string().contains("secret-bad-payload"));

        let err = parse_set_commit_extension(&[
            registered(CommitConfirmedExtension::confirm()),
            registered(CommitConfirmedExtension::cancel()),
        ])
        .unwrap_err();
        assert_eq!(err.status().as_str(), "INVALID_ARGUMENT");
    }

    #[test]
    fn rejects_set_only_extension_outside_set() {
        let err = reject_set_only_extension(&[registered(CommitConfirmedExtension::confirm())])
            .unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
    }
}
