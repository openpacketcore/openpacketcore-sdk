//! gNMI master-arbitration support.
//!
//! OpenConfig master arbitration is a well-known gNMI extension, not a
//! registered extension. OpenPacketCore keeps it behind an explicit server
//! configuration switch: disabled servers reject the extension, optional
//! servers honor it when present, and required servers deny all Set writes that
//! omit it.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Mutex;

use opc_config_model::{AuthStrength, TrustedPrincipal, WorkloadIdentity};

use crate::metrics::{record_extension, ExtensionMetricOutcome};
use crate::proto::gnmi_ext;
use crate::GnmiError;

const MASTER_ARBITRATION_METRIC_LABEL: &str = "master-arbitration";
const MAX_ROLE_ID_BYTES: usize = 256;

/// gNMI master-arbitration operating mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GnmiArbitrationMode {
    /// Reject `MasterArbitration` extensions and do not require them.
    #[default]
    Disabled,
    /// Accept and enforce `MasterArbitration` when present; allow writes that
    /// omit it.
    Optional,
    /// Require `MasterArbitration` on every Set write.
    Required,
}

/// Explicit gNMI master-arbitration configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GnmiArbitrationConfig {
    mode: GnmiArbitrationMode,
}

impl GnmiArbitrationConfig {
    /// Builds a disabled arbitration config.
    pub const fn disabled() -> Self {
        Self {
            mode: GnmiArbitrationMode::Disabled,
        }
    }

    /// Builds an optional arbitration config.
    pub const fn optional() -> Self {
        Self {
            mode: GnmiArbitrationMode::Optional,
        }
    }

    /// Builds a required arbitration config.
    pub const fn required() -> Self {
        Self {
            mode: GnmiArbitrationMode::Required,
        }
    }

    /// Returns the configured mode.
    pub const fn mode(self) -> GnmiArbitrationMode {
        self.mode
    }

    /// Whether the server supports and advertises master arbitration.
    pub const fn is_enabled(self) -> bool {
        matches!(
            self.mode,
            GnmiArbitrationMode::Optional | GnmiArbitrationMode::Required
        )
    }

    /// Whether Set requests must carry master arbitration.
    pub const fn is_required(self) -> bool {
        matches!(self.mode, GnmiArbitrationMode::Required)
    }
}

/// Unsigned 128-bit gNMI election ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GnmiElectionId {
    /// High 64 bits.
    pub high: u64,
    /// Low 64 bits.
    pub low: u64,
}

impl GnmiElectionId {
    /// Builds an election ID.
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }
}

/// One parsed master-arbitration extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedMasterArbitration {
    pub(crate) role_id: String,
    pub(crate) election_id: GnmiElectionId,
}

/// Per-server arbitration state.
#[derive(Debug, Default)]
pub struct GnmiArbitrationState {
    config: GnmiArbitrationConfig,
    masters: Mutex<BTreeMap<ArbitrationKey, MasterRecord>>,
}

impl GnmiArbitrationState {
    /// Builds arbitration state for the supplied config.
    pub fn new(config: GnmiArbitrationConfig) -> Self {
        Self {
            config,
            masters: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the configured arbitration mode.
    pub const fn config(&self) -> GnmiArbitrationConfig {
        self.config
    }

    /// Whether Capabilities should advertise master arbitration support.
    pub const fn advertised(&self) -> bool {
        self.config.is_enabled()
    }

    /// Applies Set arbitration before any mutation path is reached.
    pub(crate) fn authorize_set(
        &self,
        principal: &TrustedPrincipal,
        extensions: &[gnmi_ext::Extension],
    ) -> Result<(), GnmiError> {
        let parsed = match parse_set_arbitration_extension(extensions) {
            Ok(parsed) => parsed,
            Err(err) => {
                record_extension(
                    MASTER_ARBITRATION_METRIC_LABEL,
                    ExtensionMetricOutcome::Rejected,
                );
                return Err(err);
            }
        };

        match (self.config.mode(), parsed) {
            (GnmiArbitrationMode::Disabled, None) => Ok(()),
            (GnmiArbitrationMode::Disabled, Some(_)) => {
                record_extension(
                    MASTER_ARBITRATION_METRIC_LABEL,
                    ExtensionMetricOutcome::Rejected,
                );
                Err(GnmiError::unimplemented(
                    "gNMI master-arbitration extension is not enabled",
                ))
            }
            (GnmiArbitrationMode::Optional, None) => Ok(()),
            (GnmiArbitrationMode::Required, None) => {
                record_extension(
                    MASTER_ARBITRATION_METRIC_LABEL,
                    ExtensionMetricOutcome::Rejected,
                );
                Err(GnmiError::PermissionDenied)
            }
            (GnmiArbitrationMode::Optional | GnmiArbitrationMode::Required, Some(parsed)) => {
                self.authorize_present(principal, parsed)
            }
        }
    }

    /// Ensures OpenPacketCore commit-confirmed Set requests are protected by
    /// gNMI master arbitration. The caller invokes this after ordinary Set
    /// arbitration authorization, so this method only checks that the server is
    /// arbitration-capable and that the request carried the already-authorized
    /// arbitration extension.
    pub(crate) fn ensure_commit_confirmed_fenced(
        &self,
        extensions: &[gnmi_ext::Extension],
    ) -> Result<(), GnmiError> {
        if !self.config.is_enabled() {
            return Err(GnmiError::unimplemented(
                "OpenPacketCore commit-confirmed requires gNMI master arbitration",
            ));
        }
        if parse_set_arbitration_extension(extensions)?.is_none() {
            record_extension(
                MASTER_ARBITRATION_METRIC_LABEL,
                ExtensionMetricOutcome::Rejected,
            );
            return Err(GnmiError::PermissionDenied);
        }
        Ok(())
    }

    fn authorize_present(
        &self,
        principal: &TrustedPrincipal,
        parsed: ParsedMasterArbitration,
    ) -> Result<(), GnmiError> {
        let key = ArbitrationKey {
            tenant: principal.tenant.to_string(),
            role_id: parsed.role_id,
        };
        let candidate = MasterRecord {
            election_id: parsed.election_id,
            principal: LogicalPrincipal::from(principal),
        };

        let mut masters = self
            .masters
            .lock()
            .map_err(|_| GnmiError::schema("gNMI arbitration state lock failed"))?;
        match masters.get(&key) {
            None => {
                masters.insert(key, candidate);
                record_extension(
                    MASTER_ARBITRATION_METRIC_LABEL,
                    ExtensionMetricOutcome::Accepted,
                );
                Ok(())
            }
            Some(current) => match candidate.election_id.cmp(&current.election_id) {
                Ordering::Greater => {
                    masters.insert(key, candidate);
                    record_extension(
                        MASTER_ARBITRATION_METRIC_LABEL,
                        ExtensionMetricOutcome::Accepted,
                    );
                    Ok(())
                }
                Ordering::Equal if candidate.principal == current.principal => {
                    record_extension(
                        MASTER_ARBITRATION_METRIC_LABEL,
                        ExtensionMetricOutcome::Accepted,
                    );
                    Ok(())
                }
                Ordering::Equal | Ordering::Less => {
                    record_extension(
                        MASTER_ARBITRATION_METRIC_LABEL,
                        ExtensionMetricOutcome::Rejected,
                    );
                    Err(GnmiError::PermissionDenied)
                }
            },
        }
    }
}

pub(crate) fn parse_set_arbitration_extension(
    extensions: &[gnmi_ext::Extension],
) -> Result<Option<ParsedMasterArbitration>, GnmiError> {
    let mut parsed = None;
    for extension in extensions {
        let Some(gnmi_ext::extension::Ext::MasterArbitration(arbitration)) = extension.ext.as_ref()
        else {
            continue;
        };
        if parsed.is_some() {
            return Err(GnmiError::invalid(
                "duplicate gNMI master-arbitration extension",
            ));
        }
        parsed = Some(parse_master_arbitration(arbitration)?);
    }
    Ok(parsed)
}

fn parse_master_arbitration(
    arbitration: &gnmi_ext::MasterArbitration,
) -> Result<ParsedMasterArbitration, GnmiError> {
    let role_id = arbitration
        .role
        .as_ref()
        .map(|role| role.id.as_str())
        .unwrap_or_default();
    validate_role_id(role_id)?;
    let election = arbitration
        .election_id
        .as_ref()
        .ok_or_else(|| GnmiError::invalid("gNMI master-arbitration election ID is required"))?;
    Ok(ParsedMasterArbitration {
        role_id: role_id.to_string(),
        election_id: GnmiElectionId::new(election.high, election.low),
    })
}

fn validate_role_id(role_id: &str) -> Result<(), GnmiError> {
    if role_id.len() > MAX_ROLE_ID_BYTES
        || role_id.trim() != role_id
        || role_id.chars().any(char::is_control)
    {
        return Err(GnmiError::invalid("invalid gNMI master-arbitration role"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ArbitrationKey {
    tenant: String,
    role_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterRecord {
    election_id: GnmiElectionId,
    principal: LogicalPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalPrincipal {
    identity: WorkloadIdentity,
    auth_strength: AuthStrength,
}

impl From<&TrustedPrincipal> for LogicalPrincipal {
    fn from(principal: &TrustedPrincipal) -> Self {
        Self {
            identity: principal.identity.clone(),
            auth_strength: principal.auth_strength,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::{TrustedPrincipal, WorkloadIdentity};
    use opc_types::TenantId;

    fn principal(name: &str, tenant: &str) -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::User(name.to_string()),
            TenantId::new(tenant).expect("tenant"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
    }

    fn extension(role_id: Option<&str>, high: u64, low: u64) -> gnmi_ext::Extension {
        gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
                gnmi_ext::MasterArbitration {
                    role: role_id.map(|id| gnmi_ext::Role { id: id.to_string() }),
                    election_id: Some(gnmi_ext::Uint128 { high, low }),
                },
            )),
        }
    }

    #[test]
    fn election_ids_compare_as_unsigned_128_bit_pairs() {
        assert!(GnmiElectionId::new(1, 0) > GnmiElectionId::new(0, u64::MAX));
        assert!(GnmiElectionId::new(1, 2) > GnmiElectionId::new(1, 1));
        assert_eq!(GnmiElectionId::new(7, 8), GnmiElectionId::new(7, 8));
    }

    #[test]
    fn parser_uses_empty_role_default_and_rejects_invalid_shapes() {
        let parsed = parse_set_arbitration_extension(&[extension(None, 1, 2)])
            .expect("parse")
            .expect("extension");
        assert_eq!(parsed.role_id, "");
        assert_eq!(parsed.election_id, GnmiElectionId::new(1, 2));

        let duplicate = parse_set_arbitration_extension(&[
            extension(Some("ops"), 1, 0),
            extension(Some("ops"), 2, 0),
        ])
        .unwrap_err();
        assert_eq!(duplicate.status().as_str(), "INVALID_ARGUMENT");

        let missing_election = parse_set_arbitration_extension(&[gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::MasterArbitration(
                gnmi_ext::MasterArbitration {
                    role: Some(gnmi_ext::Role {
                        id: "ops".to_string(),
                    }),
                    election_id: None,
                },
            )),
        }])
        .unwrap_err();
        assert_eq!(missing_election.status().as_str(), "INVALID_ARGUMENT");
    }

    #[test]
    fn optional_mode_allows_missing_extension() {
        let state = GnmiArbitrationState::new(GnmiArbitrationConfig::optional());
        state
            .authorize_set(&principal("a", "tenant-a"), &[])
            .expect("missing arbitration allowed");
    }

    #[test]
    fn required_mode_denies_missing_extension() {
        let state = GnmiArbitrationState::new(GnmiArbitrationConfig::required());
        let err = state
            .authorize_set(&principal("a", "tenant-a"), &[])
            .unwrap_err();
        assert_eq!(err.status().as_str(), "PERMISSION_DENIED");
    }

    #[test]
    fn disabled_mode_rejects_present_extension() {
        let state = GnmiArbitrationState::new(GnmiArbitrationConfig::disabled());
        let err = state
            .authorize_set(&principal("a", "tenant-a"), &[extension(Some("ops"), 1, 0)])
            .unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
    }

    #[test]
    fn first_writer_higher_takeover_lower_denial_and_equal_rules() {
        let state = GnmiArbitrationState::new(GnmiArbitrationConfig::required());
        let a = principal("a", "tenant-a");
        let b = principal("b", "tenant-a");

        state
            .authorize_set(&a, &[extension(Some("ops"), 1, 0)])
            .expect("first writer");
        state
            .authorize_set(&b, &[extension(Some("ops"), 2, 0)])
            .expect("higher takeover");

        let lower = state
            .authorize_set(&a, &[extension(Some("ops"), 1, u64::MAX)])
            .unwrap_err();
        assert_eq!(lower.status().as_str(), "PERMISSION_DENIED");

        state
            .authorize_set(&b, &[extension(Some("ops"), 2, 0)])
            .expect("same election same principal");

        let same_different = state
            .authorize_set(&a, &[extension(Some("ops"), 2, 0)])
            .unwrap_err();
        assert_eq!(same_different.status().as_str(), "PERMISSION_DENIED");
    }

    #[test]
    fn tenant_and_role_are_independent_fences() {
        let state = GnmiArbitrationState::new(GnmiArbitrationConfig::required());
        let tenant_a = principal("a", "tenant-a");
        let tenant_b = principal("b", "tenant-b");

        state
            .authorize_set(&tenant_a, &[extension(Some("ops"), 9, 0)])
            .expect("tenant a master");
        state
            .authorize_set(&tenant_b, &[extension(Some("ops"), 1, 0)])
            .expect("tenant b independent");
        state
            .authorize_set(&tenant_a, &[extension(Some("readonly"), 1, 0)])
            .expect("role independent");
    }
}
