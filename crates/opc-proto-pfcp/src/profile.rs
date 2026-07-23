#![forbid(unsafe_code)]

//! PFCP Production Profile v1 validation helpers.
//!
//! The profile validator checks message-level PFCP semantics that sit above the
//! structural wire decoder. It is intentionally scoped to the N4 codec and
//! validation profile documented in `CONFORMANCE.md`; it does not implement PFCP
//! transport, transactions, SMF policy, or UPF behavior.

use std::collections::{HashMap, HashSet};

use opc_protocol::{DecodeContext, DecodeError, DecodeErrorCode, EncodeError, SpecRef};
use thiserror::Error;

use crate::ie::{decode_typed_ie_sequence, TypedIe};
use crate::{Header, InformationElement, MessageType};

/// Validation result for PFCP Production Profile v1.
pub type ProfileResult<T> = Result<T, ProfileValidationError>;

/// Build result for Production Profile v1 message constructors.
pub type ProfileBuildResult<T> = Result<T, ProfileBuildError>;

/// Error returned when a Production Profile v1 constructor cannot build a
/// profile-valid message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileBuildError {
    /// A typed IE failed to encode into the raw IE layer.
    #[error("failed to encode typed IE for profile message: {source}")]
    Encode {
        /// Underlying encode error.
        source: EncodeError,
    },
    /// The constructed message failed semantic profile validation.
    #[error("constructed message violates PFCP Production Profile v1: {source}")]
    Validate {
        /// Underlying profile validation error.
        source: ProfileValidationError,
    },
}

impl From<EncodeError> for ProfileBuildError {
    fn from(source: EncodeError) -> Self {
        Self::Encode { source }
    }
}

impl From<ProfileValidationError> for ProfileBuildError {
    fn from(source: ProfileValidationError) -> Self {
        Self::Validate { source }
    }
}

/// Error returned when a structurally decoded PFCP message violates the
/// Production Profile v1 semantic contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileValidationError {
    /// A raw IE could not be decoded into the typed IE layer required for
    /// semantic validation.
    #[error("failed to decode typed IE while validating {scope}: {source}")]
    TypedDecode {
        /// Validation scope in which typed decoding failed.
        scope: &'static str,
        /// Underlying decode error.
        source: DecodeError,
    },
    /// A raw IE decoded from the wire could not be re-encoded for typed
    /// dispatch. This indicates an internal invariant violation.
    #[error("failed to re-encode raw IE while validating {scope}")]
    RawEncode {
        /// Validation scope in which raw IE re-encode failed.
        scope: &'static str,
    },
    /// The PFCP message type is outside Production Profile v1.
    #[error("message type {message_type} is not in PFCP Production Profile v1")]
    UnsupportedMessageType {
        /// Numeric PFCP message type.
        message_type: u8,
    },
    /// The PFCP message header has the wrong SEID presence for its procedure.
    #[error("message type {message_type} SEID presence mismatch: expected {expected_present}")]
    SeidPresence {
        /// Numeric PFCP message type.
        message_type: u8,
        /// Whether the profile requires SEID to be present.
        expected_present: bool,
    },
    /// A mandatory IE is missing from the message or grouped IE.
    #[error("missing mandatory {ie} in {scope}")]
    MissingIe {
        /// Validation scope that is missing the IE.
        scope: &'static str,
        /// Human-readable IE name.
        ie: &'static str,
    },
    /// A singleton IE appears more than once in a scope.
    #[error("duplicate singleton {ie} in {scope}")]
    DuplicateIe {
        /// Validation scope that contains the duplicate IE.
        scope: &'static str,
        /// Human-readable IE name.
        ie: &'static str,
    },
    /// A message that must contain at least one rule operation has none.
    #[error("message type {message_type} contains no profile-owned rule operation")]
    MissingOperation {
        /// Numeric PFCP message type.
        message_type: u8,
    },
    /// A PDI does not contain any profile-owned traffic-match primitive.
    #[error("{scope} does not contain a profile-owned traffic-match IE")]
    MissingTrafficMatch {
        /// Validation scope that lacks a traffic match.
        scope: &'static str,
    },
    /// A FAR with forwarding action lacks forwarding parameters.
    #[error("{scope} forwards traffic without Forwarding Parameters")]
    MissingForwardingParameters {
        /// Validation scope that lacks forwarding parameters.
        scope: &'static str,
    },
    /// Forwarding Parameters are missing Destination Interface.
    #[error("{scope} is missing Destination Interface")]
    MissingDestinationInterface {
        /// Validation scope that lacks Destination Interface.
        scope: &'static str,
    },
    /// A rule references an ID that is not created or updated in the same
    /// message.
    #[error("{scope} references missing {reference} id {id}")]
    MissingRuleReference {
        /// Validation scope containing the unresolved reference.
        scope: &'static str,
        /// Referenced rule family.
        reference: &'static str,
        /// Referenced rule ID.
        id: u32,
    },
    /// Session Report Request includes a Usage Report flag but no Usage Report
    /// grouped IE.
    #[error("Session Report Request has usage-report flag but no Usage Report IE")]
    MissingUsageReport,
}

/// Validate a structurally decoded message against PFCP Production Profile v1.
pub fn validate_production_v1(
    header: &Header,
    ies: &[InformationElement],
    ctx: DecodeContext,
) -> ProfileResult<()> {
    let typed_ies = decode_typed_ies("message", ies, ctx)?;
    validate_seid_presence(header)?;

    match header.message_type {
        value if value == MessageType::HeartbeatRequest as u8 => {
            validate_heartbeat_request(&typed_ies)
        }
        value if value == MessageType::HeartbeatResponse as u8 => {
            validate_heartbeat_response(&typed_ies)
        }
        value if value == MessageType::AssociationSetupRequest as u8 => {
            validate_association_setup_request(&typed_ies)
        }
        value if value == MessageType::AssociationSetupResponse as u8 => {
            validate_association_setup_response(&typed_ies)
        }
        value if value == MessageType::AssociationReleaseRequest as u8 => Ok(()),
        value if value == MessageType::AssociationReleaseResponse as u8 => {
            validate_association_release_response(&typed_ies)
        }
        value if value == MessageType::SessionEstablishmentRequest as u8 => {
            validate_session_establishment_request(&typed_ies)
        }
        value if value == MessageType::SessionEstablishmentResponse as u8 => {
            validate_cause_response("Session Establishment Response", &typed_ies)
        }
        value if value == MessageType::SessionModificationRequest as u8 => {
            validate_session_modification_request(&typed_ies)
        }
        value if value == MessageType::SessionModificationResponse as u8 => {
            validate_cause_response("Session Modification Response", &typed_ies)
        }
        value if value == MessageType::SessionDeletionRequest as u8 => Ok(()),
        value if value == MessageType::SessionDeletionResponse as u8 => {
            validate_cause_response("Session Deletion Response", &typed_ies)
        }
        value if value == MessageType::SessionReportRequest as u8 => {
            validate_session_report_request(&typed_ies)
        }
        value if value == MessageType::SessionReportResponse as u8 => {
            validate_cause_response("Session Report Response", &typed_ies)
        }
        message_type => Err(ProfileValidationError::UnsupportedMessageType { message_type }),
    }
}

fn decode_typed_ies(
    scope: &'static str,
    ies: &[InformationElement],
    ctx: DecodeContext,
) -> ProfileResult<Vec<TypedIe>> {
    if ies.len() > ctx.max_ies {
        return Err(ProfileValidationError::TypedDecode {
            scope,
            source: DecodeError::new(DecodeErrorCode::IeCountExceeded, 0)
                .with_spec_ref(SpecRef::new("3gpp", "TS29244", "8.1.1")),
        });
    }

    let mut typed_ies = Vec::new();
    for ie in ies {
        // Do not preallocate from a manually constructed raw IE. `encode`
        // validates the u16 wire-length bound before its first buffer write.
        let mut encoded = bytes::BytesMut::new();
        ie.encode(&mut encoded)
            .map_err(|_| ProfileValidationError::RawEncode { scope })?;
        let mut decoded = decode_typed_ie_sequence(&encoded, ctx, 0)
            .map_err(|source| ProfileValidationError::TypedDecode { scope, source })?;
        typed_ies.append(&mut decoded);
    }
    Ok(typed_ies)
}

fn validate_seid_presence(header: &Header) -> ProfileResult<()> {
    let expected_present = match header.message_type {
        value if value == MessageType::HeartbeatRequest as u8 => false,
        value if value == MessageType::HeartbeatResponse as u8 => false,
        value if value == MessageType::AssociationSetupRequest as u8 => false,
        value if value == MessageType::AssociationSetupResponse as u8 => false,
        value if value == MessageType::AssociationReleaseRequest as u8 => false,
        value if value == MessageType::AssociationReleaseResponse as u8 => false,
        value if value == MessageType::SessionEstablishmentRequest as u8 => true,
        value if value == MessageType::SessionEstablishmentResponse as u8 => true,
        value if value == MessageType::SessionModificationRequest as u8 => true,
        value if value == MessageType::SessionModificationResponse as u8 => true,
        value if value == MessageType::SessionDeletionRequest as u8 => true,
        value if value == MessageType::SessionDeletionResponse as u8 => true,
        value if value == MessageType::SessionReportRequest as u8 => true,
        value if value == MessageType::SessionReportResponse as u8 => true,
        _ => return Ok(()),
    };

    if header.s == expected_present && header.seid.is_some() == expected_present {
        Ok(())
    } else {
        Err(ProfileValidationError::SeidPresence {
            message_type: header.message_type,
            expected_present,
        })
    }
}

fn validate_heartbeat_request(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Heartbeat Request", typed_ies, IeKind::RecoveryTimeStamp)?;
    reject_duplicates("Heartbeat Request", typed_ies, &[IeKind::RecoveryTimeStamp])
}

fn validate_heartbeat_response(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Heartbeat Response", typed_ies, IeKind::RecoveryTimeStamp)?;
    reject_duplicates(
        "Heartbeat Response",
        typed_ies,
        &[IeKind::RecoveryTimeStamp],
    )
}

fn validate_association_setup_request(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Association Setup Request", typed_ies, IeKind::NodeId)?;
    require_one(
        "Association Setup Request",
        typed_ies,
        IeKind::RecoveryTimeStamp,
    )?;
    reject_duplicates(
        "Association Setup Request",
        typed_ies,
        &[IeKind::NodeId, IeKind::RecoveryTimeStamp],
    )
}

fn validate_association_setup_response(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Association Setup Response", typed_ies, IeKind::NodeId)?;
    require_one(
        "Association Setup Response",
        typed_ies,
        IeKind::RecoveryTimeStamp,
    )?;
    validate_cause_response("Association Setup Response", typed_ies)?;
    reject_duplicates(
        "Association Setup Response",
        typed_ies,
        &[IeKind::NodeId, IeKind::RecoveryTimeStamp, IeKind::Cause],
    )
}

fn validate_association_release_response(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    validate_cause_response("Association Release Response", typed_ies)
}

fn validate_cause_response(scope: &'static str, typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one(scope, typed_ies, IeKind::Cause)?;
    reject_duplicates(scope, typed_ies, &[IeKind::Cause])
}

fn validate_session_establishment_request(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Session Establishment Request", typed_ies, IeKind::FSeid)?;
    require_one(
        "Session Establishment Request",
        typed_ies,
        IeKind::CreatePdr,
    )?;
    require_one(
        "Session Establishment Request",
        typed_ies,
        IeKind::CreateFar,
    )?;
    reject_duplicates("Session Establishment Request", typed_ies, &[IeKind::FSeid])?;
    validate_rule_graph("Session Establishment Request", typed_ies)
}

fn validate_session_modification_request(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    if !typed_ies.iter().any(is_rule_operation) {
        return Err(ProfileValidationError::MissingOperation {
            message_type: MessageType::SessionModificationRequest as u8,
        });
    }
    validate_rule_graph("Session Modification Request", typed_ies)
}

fn validate_session_report_request(typed_ies: &[TypedIe]) -> ProfileResult<()> {
    require_one("Session Report Request", typed_ies, IeKind::ReportType)?;
    reject_duplicates("Session Report Request", typed_ies, &[IeKind::ReportType])?;

    let usage_report_required = typed_ies.iter().any(
        |typed_ie| matches!(typed_ie, TypedIe::ReportType(report_type) if report_type.usage_report),
    );
    if usage_report_required
        && !typed_ies
            .iter()
            .any(|typed_ie| matches!(typed_ie, TypedIe::UsageReport(_)))
    {
        return Err(ProfileValidationError::MissingUsageReport);
    }
    Ok(())
}

fn validate_rule_graph(scope: &'static str, typed_ies: &[TypedIe]) -> ProfileResult<()> {
    let mut created_fars = HashSet::new();
    let mut created_qers = HashSet::new();
    let mut created_urrs = HashSet::new();
    let mut far_references = Vec::new();
    let mut qer_references = Vec::new();
    let mut urr_references = Vec::new();

    for typed_ie in typed_ies {
        match typed_ie {
            TypedIe::CreatePdr(create_pdr) => {
                validate_create_pdr(&create_pdr.members)?;
                collect_rule_references(
                    &create_pdr.members,
                    &mut far_references,
                    &mut qer_references,
                    &mut urr_references,
                );
            }
            TypedIe::UpdatePdr(update_pdr) => {
                validate_update_pdr(&update_pdr.members)?;
                collect_rule_references(
                    &update_pdr.members,
                    &mut far_references,
                    &mut qer_references,
                    &mut urr_references,
                );
            }
            TypedIe::CreateFar(create_far) => {
                validate_create_far(&create_far.members)?;
                collect_rule_id(&create_far.members, IeKind::FarId, &mut created_fars);
            }
            TypedIe::UpdateFar(update_far) => {
                validate_update_far(&update_far.members)?;
                collect_rule_id(&update_far.members, IeKind::FarId, &mut created_fars);
            }
            TypedIe::CreateQer(create_qer) => {
                require_one("Create QER", &create_qer.members, IeKind::QerId)?;
                reject_duplicates("Create QER", &create_qer.members, &[IeKind::QerId])?;
                collect_rule_id(&create_qer.members, IeKind::QerId, &mut created_qers);
            }
            TypedIe::UpdateQer(update_qer) => {
                require_one("Update QER", &update_qer.members, IeKind::QerId)?;
                reject_duplicates("Update QER", &update_qer.members, &[IeKind::QerId])?;
                collect_rule_id(&update_qer.members, IeKind::QerId, &mut created_qers);
            }
            TypedIe::CreateUrr(create_urr) => {
                require_one("Create URR", &create_urr.members, IeKind::UrrId)?;
                reject_duplicates("Create URR", &create_urr.members, &[IeKind::UrrId])?;
                collect_rule_id(&create_urr.members, IeKind::UrrId, &mut created_urrs);
            }
            TypedIe::UpdateUrr(update_urr) => {
                require_one("Update URR", &update_urr.members, IeKind::UrrId)?;
                reject_duplicates("Update URR", &update_urr.members, &[IeKind::UrrId])?;
                collect_rule_id(&update_urr.members, IeKind::UrrId, &mut created_urrs);
            }
            _ => {}
        }
    }

    validate_references(scope, "FAR", &far_references, &created_fars)?;
    validate_references(scope, "QER", &qer_references, &created_qers)?;
    validate_references(scope, "URR", &urr_references, &created_urrs)
}

fn validate_create_pdr(members: &[TypedIe]) -> ProfileResult<()> {
    require_one("Create PDR", members, IeKind::PdrId)?;
    require_one("Create PDR", members, IeKind::Precedence)?;
    require_one("Create PDR", members, IeKind::Pdi)?;
    reject_duplicates(
        "Create PDR",
        members,
        &[IeKind::PdrId, IeKind::Precedence, IeKind::Pdi],
    )?;

    for member in members {
        if let TypedIe::Pdi(pdi) = member {
            validate_pdi("Create PDR PDI", &pdi.members)?;
        }
    }
    Ok(())
}

fn validate_update_pdr(members: &[TypedIe]) -> ProfileResult<()> {
    require_one("Update PDR", members, IeKind::PdrId)?;
    reject_duplicates("Update PDR", members, &[IeKind::PdrId, IeKind::Pdi])?;

    for member in members {
        if let TypedIe::Pdi(pdi) = member {
            validate_pdi("Update PDR PDI", &pdi.members)?;
        }
    }
    Ok(())
}

fn validate_pdi(scope: &'static str, members: &[TypedIe]) -> ProfileResult<()> {
    require_one(scope, members, IeKind::SourceInterface)?;
    reject_duplicates(scope, members, &[IeKind::SourceInterface])?;

    if members.iter().any(is_traffic_match) {
        Ok(())
    } else {
        Err(ProfileValidationError::MissingTrafficMatch { scope })
    }
}

fn validate_create_far(members: &[TypedIe]) -> ProfileResult<()> {
    require_one("Create FAR", members, IeKind::FarId)?;
    require_one("Create FAR", members, IeKind::ApplyAction)?;
    reject_duplicates("Create FAR", members, &[IeKind::FarId, IeKind::ApplyAction])?;
    validate_forwarding_parameters("Create FAR", members)
}

fn validate_update_far(members: &[TypedIe]) -> ProfileResult<()> {
    require_one("Update FAR", members, IeKind::FarId)?;
    reject_duplicates("Update FAR", members, &[IeKind::FarId, IeKind::ApplyAction])?;
    validate_forwarding_parameters("Update FAR", members)
}

fn validate_forwarding_parameters(scope: &'static str, members: &[TypedIe]) -> ProfileResult<()> {
    let forwards = members
        .iter()
        .any(|member| matches!(member, TypedIe::ApplyAction(action) if action.forward));
    if !forwards {
        return Ok(());
    }

    let forwarding_parameters = members.iter().find_map(|member| match member {
        TypedIe::ForwardingParameters(parameters) => Some(&parameters.members),
        TypedIe::UpdateForwardingParameters(parameters) => Some(&parameters.members),
        _ => None,
    });

    let Some(parameters) = forwarding_parameters else {
        return Err(ProfileValidationError::MissingForwardingParameters { scope });
    };

    if parameters
        .iter()
        .any(|member| matches!(member, TypedIe::DestinationInterface(_)))
    {
        Ok(())
    } else {
        Err(ProfileValidationError::MissingDestinationInterface { scope })
    }
}

fn collect_rule_references(
    members: &[TypedIe],
    far_references: &mut Vec<u32>,
    qer_references: &mut Vec<u32>,
    urr_references: &mut Vec<u32>,
) {
    for member in members {
        match member {
            TypedIe::FarId(id) => far_references.push(id.value),
            TypedIe::QerId(id) => qer_references.push(id.value),
            TypedIe::UrrId(id) => urr_references.push(id.value),
            _ => {}
        }
    }
}

fn collect_rule_id(members: &[TypedIe], kind: IeKind, output: &mut HashSet<u32>) {
    for member in members {
        match (kind, member) {
            (IeKind::FarId, TypedIe::FarId(id)) => {
                output.insert(id.value);
            }
            (IeKind::QerId, TypedIe::QerId(id)) => {
                output.insert(id.value);
            }
            (IeKind::UrrId, TypedIe::UrrId(id)) => {
                output.insert(id.value);
            }
            _ => {}
        }
    }
}

fn validate_references(
    scope: &'static str,
    reference: &'static str,
    references: &[u32],
    created: &HashSet<u32>,
) -> ProfileResult<()> {
    for id in references {
        if !created.contains(id) {
            return Err(ProfileValidationError::MissingRuleReference {
                scope,
                reference,
                id: *id,
            });
        }
    }
    Ok(())
}

fn require_one(scope: &'static str, typed_ies: &[TypedIe], kind: IeKind) -> ProfileResult<()> {
    if typed_ies.iter().any(|typed_ie| kind.matches(typed_ie)) {
        Ok(())
    } else {
        Err(ProfileValidationError::MissingIe {
            scope,
            ie: kind.name(),
        })
    }
}

fn reject_duplicates(
    scope: &'static str,
    typed_ies: &[TypedIe],
    singleton_kinds: &[IeKind],
) -> ProfileResult<()> {
    let mut counts: HashMap<IeKind, usize> = HashMap::new();
    for typed_ie in typed_ies {
        for kind in singleton_kinds {
            if kind.matches(typed_ie) {
                let count = counts.entry(*kind).or_insert(0);
                *count += 1;
                if *count > 1 {
                    return Err(ProfileValidationError::DuplicateIe {
                        scope,
                        ie: kind.name(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn is_rule_operation(typed_ie: &TypedIe) -> bool {
    matches!(
        typed_ie,
        TypedIe::CreatePdr(_)
            | TypedIe::CreateFar(_)
            | TypedIe::CreateQer(_)
            | TypedIe::CreateUrr(_)
            | TypedIe::UpdatePdr(_)
            | TypedIe::UpdateFar(_)
            | TypedIe::UpdateQer(_)
            | TypedIe::UpdateUrr(_)
            | TypedIe::RemovePdr(_)
            | TypedIe::RemoveFar(_)
            | TypedIe::RemoveQer(_)
            | TypedIe::RemoveUrr(_)
    )
}

fn is_traffic_match(typed_ie: &TypedIe) -> bool {
    matches!(
        typed_ie,
        TypedIe::FTeid(_)
            | TypedIe::NetworkInstance(_)
            | TypedIe::UeIpAddress(_)
            | TypedIe::Qfi(_)
            | TypedIe::OuterHeaderRemoval(_)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IeKind {
    Cause,
    NodeId,
    FSeid,
    CreatePdr,
    CreateFar,
    Pdi,
    ApplyAction,
    SourceInterface,
    PdrId,
    FarId,
    QerId,
    UrrId,
    Precedence,
    RecoveryTimeStamp,
    ReportType,
}

impl IeKind {
    fn matches(self, typed_ie: &TypedIe) -> bool {
        matches!(
            (self, typed_ie),
            (Self::Cause, TypedIe::Cause(_))
                | (Self::NodeId, TypedIe::NodeId(_))
                | (Self::FSeid, TypedIe::FSeid(_))
                | (Self::CreatePdr, TypedIe::CreatePdr(_))
                | (Self::CreateFar, TypedIe::CreateFar(_))
                | (Self::Pdi, TypedIe::Pdi(_))
                | (Self::ApplyAction, TypedIe::ApplyAction(_))
                | (Self::SourceInterface, TypedIe::SourceInterface(_))
                | (Self::PdrId, TypedIe::PdrId(_))
                | (Self::FarId, TypedIe::FarId(_))
                | (Self::QerId, TypedIe::QerId(_))
                | (Self::UrrId, TypedIe::UrrId(_))
                | (Self::Precedence, TypedIe::Precedence(_))
                | (Self::RecoveryTimeStamp, TypedIe::RecoveryTimeStamp(_))
                | (Self::ReportType, TypedIe::ReportType(_))
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Cause => "Cause",
            Self::NodeId => "Node ID",
            Self::FSeid => "F-SEID",
            Self::CreatePdr => "Create PDR",
            Self::CreateFar => "Create FAR",
            Self::Pdi => "PDI",
            Self::ApplyAction => "Apply Action",
            Self::SourceInterface => "Source Interface",
            Self::PdrId => "PDR ID",
            Self::FarId => "FAR ID",
            Self::QerId => "QER ID",
            Self::UrrId => "URR ID",
            Self::Precedence => "Precedence",
            Self::RecoveryTimeStamp => "Recovery Time Stamp",
            Self::ReportType => "Report Type",
        }
    }
}
