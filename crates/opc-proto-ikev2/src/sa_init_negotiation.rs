//! Product-neutral IKE_SA_INIT proposal selection.
//!
//! IKEv2 proposals combine alternatives by Transform Type: transforms of the
//! same type are alternatives, while different types form one suite.  This
//! module selects one complete, executable SDK crypto profile without relying
//! on transform wire order or silently choosing the first transform.
//!
//! @spec IETF RFC7296 2.7, 3.3.2, 3.3.5, 3.3.6; IETF RFC5282 8
//! @req REQ-IETF-RFC7296-SA-INIT-NEGOTIATION-001

use std::{collections::HashSet, error::Error, fmt};

use crate::{
    sa_init::{
        Ikev2SaInitPayloads, Ikev2SaPayloadBuild, Ikev2SaProposal, Ikev2SaProposalBuild,
        Ikev2SaTransform, Ikev2SaTransformBuild, Ikev2TransformAttributeBuild,
        Ikev2TransformAttributeBuildValue, Ikev2TransformAttributeValue,
    },
    sa_init_crypto::{Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile},
};

const PROTOCOL_ID_IKE: u8 = 1;
const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_PRF: u8 = 2;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const TRANSFORM_TYPE_DH: u8 = 4;
const TRANSFORM_ATTRIBUTE_KEY_LENGTH: u16 = 14;

/// Ordered, executable IKE-SA capabilities accepted by a responder.
///
/// Profiles are tried in caller preference order. Proposal order breaks ties
/// between two offers of the same profile. Construction validates every
/// profile up front so configuration can fail before traffic is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2SaInitNegotiationPolicy {
    preferred_profiles: Vec<Ikev2SaInitCryptoProfile>,
}

impl Ikev2SaInitNegotiationPolicy {
    /// Build a responder policy from most-preferred to least-preferred profile.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitNegotiationError`] when the policy is empty,
    /// repeats a profile, or contains a profile that is not executable by the
    /// SDK protected-payload provider.
    pub fn new(
        preferred_profiles: Vec<Ikev2SaInitCryptoProfile>,
    ) -> Result<Self, Ikev2SaInitNegotiationError> {
        let policy = Self { preferred_profiles };
        policy.validate_capabilities()?;
        Ok(policy)
    }

    /// Profiles in responder preference order.
    pub fn preferred_profiles(&self) -> &[Ikev2SaInitCryptoProfile] {
        &self.preferred_profiles
    }

    /// Validate this policy as an SDK capability boundary.
    ///
    /// This is useful during startup validation when policy was restored from
    /// an already-typed configuration representation.
    ///
    /// # Errors
    ///
    /// Returns the same policy errors as [`Self::new`].
    pub fn validate_capabilities(&self) -> Result<(), Ikev2SaInitNegotiationError> {
        if self.preferred_profiles.is_empty() {
            return Err(Ikev2SaInitNegotiationError::NoConfiguredProfiles);
        }
        let mut seen = HashSet::with_capacity(self.preferred_profiles.len());
        for profile in self.preferred_profiles.iter().copied() {
            profile
                .validate_executable()
                .map_err(Ikev2SaInitNegotiationError::UnsupportedConfiguredProfile)?;
            if !seen.insert(profile) {
                return Err(Ikev2SaInitNegotiationError::DuplicateConfiguredProfile);
            }
        }
        Ok(())
    }
}

/// One complete IKE_SA_INIT selection ready for an SA response payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2SaInitNegotiation {
    profile: Ikev2SaInitCryptoProfile,
    selected_proposal: Ikev2SaProposalBuild,
}

impl Ikev2SaInitNegotiation {
    /// Executable crypto profile represented by the selected transforms.
    pub const fn profile(&self) -> Ikev2SaInitCryptoProfile {
        self.profile
    }

    /// Exact selected proposal, with selected attributes copied unchanged.
    ///
    /// Transform order follows the initiator's proposal. This is not required
    /// for semantic matching, but retaining it makes diagnostics and fixture
    /// comparisons deterministic.
    pub const fn selected_proposal(&self) -> &Ikev2SaProposalBuild {
        &self.selected_proposal
    }

    /// Build the single-proposal SA payload required in the response.
    pub fn response_security_association(&self) -> Ikev2SaPayloadBuild {
        Ikev2SaPayloadBuild {
            proposals: vec![self.selected_proposal.clone()],
        }
    }
}

/// Stable failure returned by IKE_SA_INIT capability validation and selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2SaInitNegotiationError {
    /// Responder policy did not contain any executable profiles.
    NoConfiguredProfiles,
    /// Responder policy repeated an identical profile.
    DuplicateConfiguredProfile,
    /// A configured profile is not executable by the SDK.
    UnsupportedConfiguredProfile(Ikev2SaInitCryptoError),
    /// Proposal numbers were zero, repeated, or not consecutive from one.
    InvalidProposalNumber {
        /// Proposal number observed on the wire.
        actual: u8,
        /// Consecutive proposal number required at this position.
        expected: usize,
    },
    /// An IKE proposal carried an SPI, which IKE_SA_INIT prohibits.
    UnexpectedIkeProposalSpi {
        /// Proposal number containing the SPI.
        proposal_number: u8,
        /// Redaction-safe SPI length only.
        spi_len: usize,
    },
    /// One transform repeated an attribute type.
    DuplicateTransformAttribute {
        /// Proposal number containing the transform.
        proposal_number: u8,
        /// Transform Type.
        transform_type: u8,
        /// Repeated Transform Attribute type.
        attribute_type: u16,
    },
    /// A proposal repeated an identical transform and attributes.
    DuplicateTransform {
        /// Proposal number containing the duplicate.
        proposal_number: u8,
        /// Transform Type.
        transform_type: u8,
        /// Transform ID.
        transform_id: u16,
    },
    /// A supported proposal selected a DH group different from the KE payload.
    KeyExchangeDhGroupMismatch {
        /// DH group carried by the KE payload.
        received: u16,
        /// Responder-preferred offered group.
        preferred: u16,
    },
    /// KE public value length did not match the selected group.
    InvalidKeyExchangeLength {
        /// Selected DH group Transform ID.
        dh_group: u16,
        /// Exact public-value length required by that group.
        expected: usize,
        /// Public-value length received.
        actual: usize,
    },
    /// No complete offered suite matched responder capabilities.
    NoAcceptableProposal,
}

impl Ikev2SaInitNegotiationError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoConfiguredProfiles => "ike_sa_init_negotiation_no_configured_profiles",
            Self::DuplicateConfiguredProfile => {
                "ike_sa_init_negotiation_duplicate_configured_profile"
            }
            Self::UnsupportedConfiguredProfile(_) => {
                "ike_sa_init_negotiation_unsupported_configured_profile"
            }
            Self::InvalidProposalNumber { .. } => "ike_sa_init_negotiation_invalid_proposal_number",
            Self::UnexpectedIkeProposalSpi { .. } => {
                "ike_sa_init_negotiation_unexpected_ike_proposal_spi"
            }
            Self::DuplicateTransformAttribute { .. } => {
                "ike_sa_init_negotiation_duplicate_transform_attribute"
            }
            Self::DuplicateTransform { .. } => "ike_sa_init_negotiation_duplicate_transform",
            Self::KeyExchangeDhGroupMismatch { .. } => {
                "ike_sa_init_negotiation_ke_dh_group_mismatch"
            }
            Self::InvalidKeyExchangeLength { .. } => "ike_sa_init_negotiation_invalid_ke_length",
            Self::NoAcceptableProposal => "ike_sa_init_negotiation_no_acceptable_proposal",
        }
    }

    /// Whether the failure maps to an unauthenticated `NO_PROPOSAL_CHOSEN`
    /// response rather than `INVALID_KE_PAYLOAD` or a malformed-request drop.
    pub const fn is_no_acceptable_proposal(&self) -> bool {
        matches!(self, Self::NoAcceptableProposal)
    }
}

impl fmt::Display for Ikev2SaInitNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SaInitNegotiationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnsupportedConfiguredProfile(error) => Some(error),
            _ => None,
        }
    }
}

/// Select one complete IKE_SA_INIT proposal against responder capabilities.
///
/// Transform order is ignored. Alternatives of one Transform Type are tested
/// independently and one exact transform per required type is returned.
/// Unknown transform types make only that proposal unacceptable, as required
/// for forward compatibility. Unknown attributes make only that transform
/// unusable. Duplicate transforms and duplicate attribute types are rejected
/// as ambiguous input instead of being silently collapsed.
///
/// The selected DH transform must match the request KE payload. A supported
/// offered suite with a different KE group returns a typed mismatch suitable
/// for an `INVALID_KE_PAYLOAD` response; an unsupported suite, including DH1,
/// returns [`Ikev2SaInitNegotiationError::NoAcceptableProposal`].
///
/// # Errors
///
/// Returns [`Ikev2SaInitNegotiationError`] for invalid policy, ambiguous
/// proposals, KE correlation/length failures, or no acceptable complete suite.
pub fn negotiate_ike_sa_init(
    payloads: &Ikev2SaInitPayloads<'_>,
    policy: &Ikev2SaInitNegotiationPolicy,
) -> Result<Ikev2SaInitNegotiation, Ikev2SaInitNegotiationError> {
    policy.validate_capabilities()?;
    validate_proposals(&payloads.security_association.proposals)?;

    let mut mismatched_preferred_group = None;
    for profile in policy.preferred_profiles.iter().copied() {
        for proposal in &payloads.security_association.proposals {
            let Some(selected_indices) = select_profile_transforms(profile, proposal) else {
                continue;
            };

            let selected_group = profile.dh_group().transform_id();
            if payloads.key_exchange.dh_group != selected_group {
                mismatched_preferred_group.get_or_insert(selected_group);
                continue;
            }
            let expected = profile.dh_group().public_value_len();
            let actual = payloads.key_exchange.key_exchange_data.len();
            if actual != expected {
                return Err(Ikev2SaInitNegotiationError::InvalidKeyExchangeLength {
                    dh_group: selected_group,
                    expected,
                    actual,
                });
            }

            let transforms = proposal
                .transforms
                .iter()
                .enumerate()
                .filter(|(index, _)| selected_indices.contains(index))
                .map(|(_, transform)| transform_build_from_view(transform))
                .collect();
            return Ok(Ikev2SaInitNegotiation {
                profile,
                selected_proposal: Ikev2SaProposalBuild {
                    proposal_number: proposal.proposal_number,
                    protocol_id: PROTOCOL_ID_IKE,
                    spi: Vec::new(),
                    transforms,
                },
            });
        }
    }

    if let Some(preferred) = mismatched_preferred_group {
        return Err(Ikev2SaInitNegotiationError::KeyExchangeDhGroupMismatch {
            received: payloads.key_exchange.dh_group,
            preferred,
        });
    }
    Err(Ikev2SaInitNegotiationError::NoAcceptableProposal)
}

fn validate_proposals(
    proposals: &[Ikev2SaProposal<'_>],
) -> Result<(), Ikev2SaInitNegotiationError> {
    for (index, proposal) in proposals.iter().enumerate() {
        let expected = index + 1;
        if usize::from(proposal.proposal_number) != expected {
            return Err(Ikev2SaInitNegotiationError::InvalidProposalNumber {
                actual: proposal.proposal_number,
                expected,
            });
        }
        if proposal.protocol_id == PROTOCOL_ID_IKE
            && (proposal.spi_size != 0 || !proposal.spi.is_empty())
        {
            return Err(Ikev2SaInitNegotiationError::UnexpectedIkeProposalSpi {
                proposal_number: proposal.proposal_number,
                spi_len: proposal.spi.len(),
            });
        }
        let mut seen_transforms = HashSet::with_capacity(proposal.transforms.len());
        for transform in &proposal.transforms {
            let mut seen_attributes = HashSet::with_capacity(transform.attributes.len());
            for attribute in &transform.attributes {
                if !seen_attributes.insert(attribute.attribute_type) {
                    return Err(Ikev2SaInitNegotiationError::DuplicateTransformAttribute {
                        proposal_number: proposal.proposal_number,
                        transform_type: transform.transform_type,
                        attribute_type: attribute.attribute_type,
                    });
                }
            }
            let mut attributes = transform
                .attributes
                .iter()
                .map(|attribute| AttributeFingerprint {
                    attribute_type: attribute.attribute_type,
                    value: match attribute.value {
                        Ikev2TransformAttributeValue::Tv(value) => {
                            AttributeValueFingerprint::Tv(value)
                        }
                        Ikev2TransformAttributeValue::Tlv(bytes) => {
                            AttributeValueFingerprint::Tlv(bytes)
                        }
                    },
                })
                .collect::<Vec<_>>();
            attributes.sort_unstable_by_key(|attribute| attribute.attribute_type);
            let fingerprint = TransformFingerprint {
                transform_type: transform.transform_type,
                transform_id: transform.transform_id,
                attributes,
            };
            if !seen_transforms.insert(fingerprint) {
                return Err(Ikev2SaInitNegotiationError::DuplicateTransform {
                    proposal_number: proposal.proposal_number,
                    transform_type: transform.transform_type,
                    transform_id: transform.transform_id,
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct TransformFingerprint<'a> {
    transform_type: u8,
    transform_id: u16,
    attributes: Vec<AttributeFingerprint<'a>>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct AttributeFingerprint<'a> {
    attribute_type: u16,
    value: AttributeValueFingerprint<'a>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum AttributeValueFingerprint<'a> {
    Tv(u16),
    Tlv(&'a [u8]),
}

fn select_profile_transforms(
    profile: Ikev2SaInitCryptoProfile,
    proposal: &Ikev2SaProposal<'_>,
) -> Option<Vec<usize>> {
    if proposal.protocol_id != PROTOCOL_ID_IKE || proposal.spi_size != 0 || !proposal.spi.is_empty()
    {
        return None;
    }
    if proposal.transforms.iter().any(|transform| {
        !matches!(
            transform.transform_type,
            TRANSFORM_TYPE_ENCR | TRANSFORM_TYPE_PRF | TRANSFORM_TYPE_INTEG | TRANSFORM_TYPE_DH
        )
    }) {
        return None;
    }

    let encryption = find_transform(proposal, TRANSFORM_TYPE_ENCR, |transform| {
        transform.transform_id == profile.encryption().transform_id()
            && exact_encryption_key_length(transform, profile.encryption().key_bits())
    })?;
    let prf = find_transform(proposal, TRANSFORM_TYPE_PRF, |transform| {
        transform.transform_id == profile.prf().transform_id() && transform.attributes.is_empty()
    })?;
    let dh = find_transform(proposal, TRANSFORM_TYPE_DH, |transform| {
        transform.transform_id == profile.dh_group().transform_id()
            && transform.attributes.is_empty()
    })?;

    let mut selected = vec![encryption, prf, dh];
    match profile.integrity() {
        Some(integrity) => {
            selected.push(find_transform(
                proposal,
                TRANSFORM_TYPE_INTEG,
                |transform| {
                    transform.transform_id == integrity.transform_id()
                        && transform.attributes.is_empty()
                },
            )?);
        }
        None => {
            if proposal
                .transforms
                .iter()
                .any(|transform| transform.transform_type == TRANSFORM_TYPE_INTEG)
            {
                return None;
            }
        }
    }
    Some(selected)
}

fn find_transform<F>(
    proposal: &Ikev2SaProposal<'_>,
    transform_type: u8,
    matches: F,
) -> Option<usize>
where
    F: Fn(&Ikev2SaTransform<'_>) -> bool,
{
    proposal
        .transforms
        .iter()
        .enumerate()
        .find(|(_, transform)| transform.transform_type == transform_type && matches(transform))
        .map(|(index, _)| index)
}

fn exact_encryption_key_length(transform: &Ikev2SaTransform<'_>, key_bits: u16) -> bool {
    matches!(
        transform.attributes.as_slice(),
        [attribute]
            if attribute.attribute_type == TRANSFORM_ATTRIBUTE_KEY_LENGTH
                && attribute.value == Ikev2TransformAttributeValue::Tv(key_bits)
    )
}

fn transform_build_from_view(transform: &Ikev2SaTransform<'_>) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type: transform.transform_type,
        transform_id: transform.transform_id,
        attributes: transform
            .attributes
            .iter()
            .map(|attribute| Ikev2TransformAttributeBuild {
                attribute_type: attribute.attribute_type,
                value: match attribute.value {
                    Ikev2TransformAttributeValue::Tv(value) => {
                        Ikev2TransformAttributeBuildValue::Tv(value)
                    }
                    Ikev2TransformAttributeValue::Tlv(bytes) => {
                        Ikev2TransformAttributeBuildValue::Tlv(bytes.to_vec())
                    }
                },
            })
            .collect(),
    }
}
