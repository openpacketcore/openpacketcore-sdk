use std::collections::BTreeSet;

use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, UnknownIePolicy,
    ValidationLevel,
};

const CRITICALITY_REJECT: u8 = 0;
const CRITICALITY_IGNORE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IeRule {
    id: u16,
    criticality: u8,
    repeatable: bool,
}

impl IeRule {
    const fn singleton(id: u16, criticality: u8) -> Self {
        Self {
            id,
            criticality,
            repeatable: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IeProfile {
    rules: &'static [IeRule],
}

impl IeProfile {
    const fn new(rules: &'static [IeRule]) -> Self {
        Self { rules }
    }

    fn rule(self, id: u16) -> Option<IeRule> {
        self.rules.iter().copied().find(|rule| rule.id == id)
    }
}

/// Read the root `ProtocolIE-Container` count before `rasn` can allocate its
/// `SequenceOf`.
///
/// Every typed message in this crate has the same Release-18 ASN.1 root:
/// an extensible `SEQUENCE` whose first root component is
/// `ProtocolIE-Container`, constrained to `SIZE(0..maxProtocolIEs)` where
/// `maxProtocolIEs` is 65535. In aligned PER this is one extension bit padded
/// to an octet boundary followed by the fixed-width 16-bit element count.
pub(super) fn preflight_ie_count(
    value: &[u8],
    ctx: DecodeContext,
    structural_reason: &'static str,
) -> Result<usize, DecodeError> {
    const PREFIX_LEN: usize = 3;
    const MIN_IE_WIRE_LEN: usize = 4;

    if value.len() < PREFIX_LEN || value[0] & 0x7f != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: structural_reason,
            },
            0,
        ));
    }

    let count = usize::from(u16::from_be_bytes([value[1], value[2]]));
    if count > ctx.max_ies {
        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
    }

    // A protocol IE needs, at minimum, its two-octet constrained identifier,
    // one criticality octet, and one open-type length octet. Reject impossible
    // counts before the decoder can reserve a wire-controlled `Vec`.
    if count > value.len().saturating_sub(PREFIX_LEN) / MIN_IE_WIRE_LEN {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: structural_reason,
            },
            0,
        ));
    }

    Ok(count)
}

pub(super) fn apply_ie_policy<T, Id, Crit>(
    entries: &mut Vec<T>,
    declared_count: usize,
    profile: IeProfile,
    ctx: DecodeContext,
    id_of: Id,
    criticality_of: Crit,
) -> Result<(), DecodeError>
where
    Id: Fn(&T) -> u16,
    Crit: Fn(&T) -> u8,
{
    if entries.len() != declared_count {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "ngap protocol ie count mismatch",
            },
            0,
        ));
    }

    for entry in entries.iter() {
        let id = id_of(entry);
        let actual_criticality = criticality_of(entry);
        if let Some(rule) = profile.rule(id) {
            if actual_criticality != rule.criticality {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "ngap protocol ie criticality mismatch",
                    },
                    0,
                ));
            }
            continue;
        }

        let is_reject = actual_criticality == CRITICALITY_REJECT;
        let strict = matches!(
            ctx.validation_level,
            ValidationLevel::Strict | ValidationLevel::ProcedureAware
        );
        if is_reject && (strict || matches!(ctx.unknown_ie_policy, UnknownIePolicy::Reject)) {
            return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0));
        }
        if matches!(ctx.unknown_ie_policy, UnknownIePolicy::Reject) {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "unknown ngap protocol ie",
                },
                0,
            ));
        }
    }

    if matches!(ctx.unknown_ie_policy, UnknownIePolicy::Drop) {
        entries.retain(|entry| profile.rule(id_of(entry)).is_some());
    }

    let is_singleton = |entry: &T| {
        !profile
            .rule(id_of(entry))
            .is_some_and(|rule| rule.repeatable)
    };

    match ctx.duplicate_ie_policy {
        DuplicateIePolicy::Reject => {
            let mut seen = BTreeSet::new();
            for entry in entries.iter().filter(|entry| is_singleton(entry)) {
                if !seen.insert(id_of(entry)) {
                    return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, 0));
                }
            }
        }
        DuplicateIePolicy::First => {
            let mut seen = BTreeSet::new();
            entries.retain(|entry| !is_singleton(entry) || seen.insert(id_of(entry)));
        }
        DuplicateIePolicy::Last => {
            let mut seen = BTreeSet::new();
            entries.reverse();
            entries.retain(|entry| !is_singleton(entry) || seen.insert(id_of(entry)));
            entries.reverse();
        }
    }

    Ok(())
}

// The tables below are transcribed from the repository generator's pinned
// TS 38.413 Release-18 `NGAP-PDU-Contents.asn` object sets. Every top-level IE
// in the currently typed subset is singleton. List-valued IEs carry their
// standardized repetition inside the open-type value, not by repeating the
// top-level protocol-IE identifier.

pub(super) const PDU_SESSION_RESOURCE_SETUP_REQUEST: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_REJECT), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(83, CRITICALITY_IGNORE), // id-RANPagingPriority
    IeRule::singleton(38, CRITICALITY_REJECT), // id-NAS-PDU
    IeRule::singleton(74, CRITICALITY_REJECT), // id-PDUSessionResourceSetupListSUReq
    IeRule::singleton(110, CRITICALITY_IGNORE), // id-UEAggregateMaximumBitRate
    IeRule::singleton(335, CRITICALITY_IGNORE), // id-UESliceMaximumBitRateList
]);

pub(super) const PDU_SESSION_RESOURCE_SETUP_RESPONSE: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_IGNORE), // id-RAN-UE-NGAP-ID
    IeRule::singleton(75, CRITICALITY_IGNORE), // id-PDUSessionResourceSetupListSURes
    IeRule::singleton(58, CRITICALITY_IGNORE), // id-PDUSessionResourceFailedToSetupListSURes
    IeRule::singleton(19, CRITICALITY_IGNORE), // id-CriticalityDiagnostics
    IeRule::singleton(121, CRITICALITY_IGNORE), // id-UserLocationInformation
]);

pub(super) const PDU_SESSION_RESOURCE_RELEASE_COMMAND: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_REJECT), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(83, CRITICALITY_IGNORE), // id-RANPagingPriority
    IeRule::singleton(38, CRITICALITY_IGNORE), // id-NAS-PDU
    IeRule::singleton(79, CRITICALITY_REJECT), // id-PDUSessionResourceToReleaseListRelCmd
]);

pub(super) const PDU_SESSION_RESOURCE_RELEASE_RESPONSE: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_IGNORE), // id-RAN-UE-NGAP-ID
    IeRule::singleton(70, CRITICALITY_IGNORE), // id-PDUSessionResourceReleasedListRelRes
    IeRule::singleton(121, CRITICALITY_IGNORE), // id-UserLocationInformation
    IeRule::singleton(19, CRITICALITY_IGNORE), // id-CriticalityDiagnostics
]);

pub(super) const INITIAL_CONTEXT_SETUP_REQUEST: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_REJECT), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(48, CRITICALITY_REJECT), // id-OldAMF
    IeRule::singleton(110, CRITICALITY_REJECT), // id-UEAggregateMaximumBitRate
    IeRule::singleton(18, CRITICALITY_IGNORE), // id-CoreNetworkAssistanceInformationForInactive
    IeRule::singleton(28, CRITICALITY_REJECT), // id-GUAMI
    IeRule::singleton(71, CRITICALITY_REJECT), // id-PDUSessionResourceSetupListCxtReq
    IeRule::singleton(0, CRITICALITY_REJECT),  // id-AllowedNSSAI
    IeRule::singleton(119, CRITICALITY_REJECT), // id-UESecurityCapabilities
    IeRule::singleton(94, CRITICALITY_REJECT), // id-SecurityKey
    IeRule::singleton(108, CRITICALITY_IGNORE), // id-TraceActivation
    IeRule::singleton(36, CRITICALITY_IGNORE), // id-MobilityRestrictionList
    IeRule::singleton(117, CRITICALITY_IGNORE), // id-UERadioCapability
    IeRule::singleton(31, CRITICALITY_IGNORE), // id-IndexToRFSP
    IeRule::singleton(34, CRITICALITY_IGNORE), // id-MaskedIMEISV
    IeRule::singleton(38, CRITICALITY_IGNORE), // id-NAS-PDU
    IeRule::singleton(24, CRITICALITY_REJECT), // id-EmergencyFallbackIndicator
    IeRule::singleton(91, CRITICALITY_IGNORE), // id-RRCInactiveTransitionReportRequest
    IeRule::singleton(118, CRITICALITY_IGNORE), // id-UERadioCapabilityForPaging
    IeRule::singleton(146, CRITICALITY_IGNORE), // id-RedirectionVoiceFallback
    IeRule::singleton(33, CRITICALITY_IGNORE), // id-LocationReportingRequestType
    IeRule::singleton(165, CRITICALITY_IGNORE), // id-CNAssistedRANTuning
    IeRule::singleton(177, CRITICALITY_IGNORE), // id-SRVCCOperationPossible
    IeRule::singleton(199, CRITICALITY_IGNORE), // id-IAB-Authorized
    IeRule::singleton(205, CRITICALITY_IGNORE), // id-Enhanced-CoverageRestriction
    IeRule::singleton(206, CRITICALITY_IGNORE), // id-Extended-ConnectedTime
    IeRule::singleton(209, CRITICALITY_IGNORE), // id-UE-DifferentiationInfo
    IeRule::singleton(216, CRITICALITY_IGNORE), // id-NRV2XServicesAuthorized
    IeRule::singleton(215, CRITICALITY_IGNORE), // id-LTEV2XServicesAuthorized
    IeRule::singleton(218, CRITICALITY_IGNORE), // id-NRUESidelinkAggregateMaximumBitrate
    IeRule::singleton(217, CRITICALITY_IGNORE), // id-LTEUESidelinkAggregateMaximumBitrate
    IeRule::singleton(219, CRITICALITY_IGNORE), // id-PC5QoSParameters
    IeRule::singleton(222, CRITICALITY_IGNORE), // id-CEmodeBrestricted
    IeRule::singleton(234, CRITICALITY_IGNORE), // id-UE-UP-CIoT-Support
    IeRule::singleton(238, CRITICALITY_IGNORE), // id-RGLevelWirelineAccessCharacteristics
    IeRule::singleton(254, CRITICALITY_IGNORE), // id-ManagementBasedMDTPLMNList
    IeRule::singleton(264, CRITICALITY_REJECT), // id-UERadioCapabilityID
    IeRule::singleton(326, CRITICALITY_IGNORE), // id-TimeSyncAssistanceInfo
    IeRule::singleton(328, CRITICALITY_IGNORE), // id-QMCConfigInfo
    IeRule::singleton(334, CRITICALITY_IGNORE), // id-TargetNSSAIInformation
    IeRule::singleton(335, CRITICALITY_IGNORE), // id-UESliceMaximumBitRateList
    IeRule::singleton(345, CRITICALITY_IGNORE), // id-FiveG-ProSeAuthorized
    IeRule::singleton(346, CRITICALITY_IGNORE), // id-FiveG-ProSeUEPC5AggregateMaximumBitRate
    IeRule::singleton(347, CRITICALITY_IGNORE), // id-FiveG-ProSePC5QoSParameters
    IeRule::singleton(367, CRITICALITY_IGNORE), // id-NetworkControlledRepeaterAuthorized
    IeRule::singleton(373, CRITICALITY_IGNORE), // id-AerialUEsubscriptionInformation
    IeRule::singleton(374, CRITICALITY_IGNORE), // id-NR-A2X-ServicesAuthorized
    IeRule::singleton(375, CRITICALITY_IGNORE), // id-LTE-A2X-ServicesAuthorized
    IeRule::singleton(376, CRITICALITY_IGNORE), // id-NR-A2X-UE-PC5-AggregateMaximumBitRate
    IeRule::singleton(377, CRITICALITY_IGNORE), // id-LTE-A2X-UE-PC5-AggregateMaximumBitRate
    IeRule::singleton(378, CRITICALITY_IGNORE), // id-A2X-PC5-QoS-Parameters
    IeRule::singleton(400, CRITICALITY_IGNORE), // id-MobileIAB-Authorized
    IeRule::singleton(414, CRITICALITY_IGNORE), // id-Partially-Allowed-NSSAI
    IeRule::singleton(430, CRITICALITY_IGNORE), // id-SLPositioningRangingServiceInfo
    IeRule::singleton(443, CRITICALITY_IGNORE), // id-ExtendedOldAMF
    IeRule::singleton(450, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID2
]);

pub(super) const INITIAL_CONTEXT_SETUP_RESPONSE: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_IGNORE), // id-RAN-UE-NGAP-ID
    IeRule::singleton(72, CRITICALITY_IGNORE), // id-PDUSessionResourceSetupListCxtRes
    IeRule::singleton(55, CRITICALITY_IGNORE), // id-PDUSessionResourceFailedToSetupListCxtRes
    IeRule::singleton(19, CRITICALITY_IGNORE), // id-CriticalityDiagnostics
]);

pub(super) const INITIAL_CONTEXT_SETUP_FAILURE: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_IGNORE), // id-RAN-UE-NGAP-ID
    IeRule::singleton(132, CRITICALITY_IGNORE), // id-PDUSessionResourceFailedToSetupListCxtFail
    IeRule::singleton(15, CRITICALITY_IGNORE), // id-Cause
    IeRule::singleton(19, CRITICALITY_IGNORE), // id-CriticalityDiagnostics
]);

pub(super) const UE_CONTEXT_RELEASE_COMMAND: IeProfile = IeProfile::new(&[
    IeRule::singleton(114, CRITICALITY_REJECT), // id-UE-NGAP-IDs
    IeRule::singleton(15, CRITICALITY_IGNORE),  // id-Cause
]);

pub(super) const UE_CONTEXT_RELEASE_COMPLETE: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_IGNORE), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_IGNORE), // id-RAN-UE-NGAP-ID
    IeRule::singleton(121, CRITICALITY_IGNORE), // id-UserLocationInformation
    IeRule::singleton(32, CRITICALITY_IGNORE), // id-InfoOnRecommendedCellsAndRANNodesForPaging
    IeRule::singleton(60, CRITICALITY_REJECT), // id-PDUSessionResourceListCxtRelCpl
    IeRule::singleton(19, CRITICALITY_IGNORE), // id-CriticalityDiagnostics
    IeRule::singleton(207, CRITICALITY_IGNORE), // id-PagingAssisDataforCEcapabUE
]);

pub(super) const PAGING: IeProfile = IeProfile::new(&[
    IeRule::singleton(115, CRITICALITY_IGNORE), // id-UEPagingIdentity
    IeRule::singleton(50, CRITICALITY_IGNORE),  // id-PagingDRX
    IeRule::singleton(103, CRITICALITY_IGNORE), // id-TAIListForPaging
    IeRule::singleton(52, CRITICALITY_IGNORE),  // id-PagingPriority
    IeRule::singleton(118, CRITICALITY_IGNORE), // id-UERadioCapabilityForPaging
    IeRule::singleton(51, CRITICALITY_IGNORE),  // id-PagingOrigin
    IeRule::singleton(11, CRITICALITY_IGNORE),  // id-AssistanceDataForPaging
    IeRule::singleton(203, CRITICALITY_IGNORE), // id-NB-IoT-Paging-eDRXInfo
    IeRule::singleton(202, CRITICALITY_IGNORE), // id-NB-IoT-PagingDRX
    IeRule::singleton(205, CRITICALITY_IGNORE), // id-Enhanced-CoverageRestriction
    IeRule::singleton(208, CRITICALITY_IGNORE), // id-WUS-Assistance-Information
    IeRule::singleton(223, CRITICALITY_IGNORE), // id-EUTRA-PagingeDRXInformation
    IeRule::singleton(222, CRITICALITY_IGNORE), // id-CEmodeBrestricted
    IeRule::singleton(332, CRITICALITY_IGNORE), // id-NR-PagingeDRXInformation
    IeRule::singleton(342, CRITICALITY_IGNORE), // id-PagingCause
    IeRule::singleton(344, CRITICALITY_IGNORE), // id-PEIPSassistanceInformation
    IeRule::singleton(477, CRITICALITY_IGNORE), // id-LPWUSPSAssistanceInformation
    IeRule::singleton(495, CRITICALITY_IGNORE), // id-LPWUSDisableIndication
]);

pub(super) const INITIAL_UE_MESSAGE: IeProfile = IeProfile::new(&[
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(38, CRITICALITY_REJECT), // id-NAS-PDU
    IeRule::singleton(121, CRITICALITY_REJECT), // id-UserLocationInformation
    IeRule::singleton(90, CRITICALITY_IGNORE), // id-RRCEstablishmentCause
    IeRule::singleton(26, CRITICALITY_REJECT), // id-FiveG-S-TMSI
    IeRule::singleton(3, CRITICALITY_IGNORE),  // id-AMFSetID
    IeRule::singleton(112, CRITICALITY_IGNORE), // id-UEContextRequest
    IeRule::singleton(0, CRITICALITY_REJECT),  // id-AllowedNSSAI
    IeRule::singleton(171, CRITICALITY_IGNORE), // id-SourceToTarget-AMFInformationReroute
    IeRule::singleton(174, CRITICALITY_IGNORE), // id-SelectedPLMNIdentity
    IeRule::singleton(201, CRITICALITY_REJECT), // id-IABNodeIndication
    IeRule::singleton(224, CRITICALITY_REJECT), // id-CEmodeBSupport-Indicator
    IeRule::singleton(225, CRITICALITY_IGNORE), // id-LTEM-Indication
    IeRule::singleton(227, CRITICALITY_IGNORE), // id-EDT-Session
    IeRule::singleton(245, CRITICALITY_IGNORE), // id-AuthenticatedIndication
    IeRule::singleton(259, CRITICALITY_REJECT), // id-NPN-AccessInformation
    IeRule::singleton(333, CRITICALITY_IGNORE), // id-RedCapIndication
    IeRule::singleton(371, CRITICALITY_IGNORE), // id-SelectedNID
    IeRule::singleton(402, CRITICALITY_REJECT), // id-MobileIABNodeIndication
    IeRule::singleton(414, CRITICALITY_IGNORE), // id-Partially-Allowed-NSSAI
    IeRule::singleton(427, CRITICALITY_IGNORE), // id-ERedCapIndication
    IeRule::singleton(440, CRITICALITY_IGNORE), // id-AUN3DeviceAccessInfo
    IeRule::singleton(28, CRITICALITY_IGNORE), // id-GUAMI
    IeRule::singleton(176, CRITICALITY_IGNORE), // id-GUAMIType
    IeRule::singleton(454, CRITICALITY_IGNORE), // id-RequestedNSSAI
]);

pub(super) const DOWNLINK_NAS_TRANSPORT: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_REJECT), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(48, CRITICALITY_REJECT), // id-OldAMF
    IeRule::singleton(83, CRITICALITY_IGNORE), // id-RANPagingPriority
    IeRule::singleton(38, CRITICALITY_REJECT), // id-NAS-PDU
    IeRule::singleton(36, CRITICALITY_IGNORE), // id-MobilityRestrictionList
    IeRule::singleton(31, CRITICALITY_IGNORE), // id-IndexToRFSP
    IeRule::singleton(110, CRITICALITY_IGNORE), // id-UEAggregateMaximumBitRate
    IeRule::singleton(0, CRITICALITY_REJECT),  // id-AllowedNSSAI
    IeRule::singleton(177, CRITICALITY_IGNORE), // id-SRVCCOperationPossible
    IeRule::singleton(205, CRITICALITY_IGNORE), // id-Enhanced-CoverageRestriction
    IeRule::singleton(206, CRITICALITY_IGNORE), // id-Extended-ConnectedTime
    IeRule::singleton(209, CRITICALITY_IGNORE), // id-UE-DifferentiationInfo
    IeRule::singleton(222, CRITICALITY_IGNORE), // id-CEmodeBrestricted
    IeRule::singleton(117, CRITICALITY_IGNORE), // id-UERadioCapability
    IeRule::singleton(228, CRITICALITY_IGNORE), // id-UECapabilityInfoRequest
    IeRule::singleton(226, CRITICALITY_IGNORE), // id-EndIndication
    IeRule::singleton(264, CRITICALITY_REJECT), // id-UERadioCapabilityID
    IeRule::singleton(334, CRITICALITY_IGNORE), // id-TargetNSSAIInformation
    IeRule::singleton(34, CRITICALITY_IGNORE), // id-MaskedIMEISV
    IeRule::singleton(414, CRITICALITY_IGNORE), // id-Partially-Allowed-NSSAI
    IeRule::singleton(400, CRITICALITY_IGNORE), // id-MobileIAB-Authorized
    IeRule::singleton(443, CRITICALITY_IGNORE), // id-ExtendedOldAMF
]);

pub(super) const UPLINK_NAS_TRANSPORT: IeProfile = IeProfile::new(&[
    IeRule::singleton(10, CRITICALITY_REJECT), // id-AMF-UE-NGAP-ID
    IeRule::singleton(85, CRITICALITY_REJECT), // id-RAN-UE-NGAP-ID
    IeRule::singleton(38, CRITICALITY_REJECT), // id-NAS-PDU
    IeRule::singleton(121, CRITICALITY_IGNORE), // id-UserLocationInformation
    IeRule::singleton(239, CRITICALITY_REJECT), // id-W-AGFIdentityInformation
    IeRule::singleton(246, CRITICALITY_REJECT), // id-TNGFIdentityInformation
    IeRule::singleton(247, CRITICALITY_REJECT), // id-TWIFIdentityInformation
]);

pub(super) const NG_SETUP_REQUEST: IeProfile = IeProfile::new(&[
    IeRule::singleton(27, CRITICALITY_REJECT), // id-GlobalRANNodeID
    IeRule::singleton(82, CRITICALITY_IGNORE), // id-RANNodeName
    IeRule::singleton(102, CRITICALITY_REJECT), // id-SupportedTAList
    IeRule::singleton(21, CRITICALITY_IGNORE), // id-DefaultPagingDRX
    IeRule::singleton(147, CRITICALITY_IGNORE), // id-UERetentionInformation
    IeRule::singleton(204, CRITICALITY_IGNORE), // id-NB-IoT-DefaultPagingDRX
    IeRule::singleton(273, CRITICALITY_IGNORE), // id-Extended-RANNodeName
    IeRule::singleton(475, CRITICALITY_REJECT), // id-AIoT-Support
    IeRule::singleton(483, CRITICALITY_IGNORE), // id-AdditionalULI
]);

pub(super) const NG_SETUP_RESPONSE: IeProfile = IeProfile::new(&[
    IeRule::singleton(1, CRITICALITY_REJECT),   // id-AMFName
    IeRule::singleton(96, CRITICALITY_REJECT),  // id-ServedGUAMIList
    IeRule::singleton(86, CRITICALITY_IGNORE),  // id-RelativeAMFCapacity
    IeRule::singleton(80, CRITICALITY_REJECT),  // id-PLMNSupportList
    IeRule::singleton(19, CRITICALITY_IGNORE),  // id-CriticalityDiagnostics
    IeRule::singleton(147, CRITICALITY_IGNORE), // id-UERetentionInformation
    IeRule::singleton(200, CRITICALITY_IGNORE), // id-IAB-Supported
    IeRule::singleton(274, CRITICALITY_IGNORE), // id-Extended-AMFName
    IeRule::singleton(404, CRITICALITY_IGNORE), // id-MobileIAB-Supported
    IeRule::singleton(467, CRITICALITY_REJECT), // id-AIOTFIdentifier
    IeRule::singleton(476, CRITICALITY_REJECT), // id-AIOTFName
]);

pub(super) const NG_SETUP_FAILURE: IeProfile = IeProfile::new(&[
    IeRule::singleton(15, CRITICALITY_IGNORE),  // id-Cause
    IeRule::singleton(107, CRITICALITY_IGNORE), // id-TimeToWait
    IeRule::singleton(19, CRITICALITY_IGNORE),  // id-CriticalityDiagnostics
]);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestIe {
        id: u16,
        criticality: u8,
        marker: u8,
    }

    fn context(policy: DuplicateIePolicy) -> DecodeContext {
        DecodeContext {
            duplicate_ie_policy: policy,
            ..DecodeContext::default()
        }
    }

    #[test]
    fn repeatable_rule_survives_all_duplicate_policies() {
        const PROFILE: IeProfile = IeProfile::new(&[IeRule {
            id: 7,
            criticality: CRITICALITY_IGNORE,
            repeatable: true,
        }]);

        for policy in [
            DuplicateIePolicy::First,
            DuplicateIePolicy::Last,
            DuplicateIePolicy::Reject,
        ] {
            let mut entries = vec![
                TestIe {
                    id: 7,
                    criticality: CRITICALITY_IGNORE,
                    marker: 1,
                },
                TestIe {
                    id: 7,
                    criticality: CRITICALITY_IGNORE,
                    marker: 2,
                },
            ];
            apply_ie_policy(
                &mut entries,
                2,
                PROFILE,
                context(policy),
                |entry| entry.id,
                |entry| entry.criticality,
            )
            .unwrap();
            assert_eq!(
                entries.iter().map(|entry| entry.marker).collect::<Vec<_>>(),
                [1, 2]
            );
        }
    }

    #[test]
    fn every_production_profile_has_unique_singleton_ids() {
        let profiles = [
            PDU_SESSION_RESOURCE_SETUP_REQUEST,
            PDU_SESSION_RESOURCE_SETUP_RESPONSE,
            PDU_SESSION_RESOURCE_RELEASE_COMMAND,
            PDU_SESSION_RESOURCE_RELEASE_RESPONSE,
            INITIAL_CONTEXT_SETUP_REQUEST,
            INITIAL_CONTEXT_SETUP_RESPONSE,
            INITIAL_CONTEXT_SETUP_FAILURE,
            UE_CONTEXT_RELEASE_COMMAND,
            UE_CONTEXT_RELEASE_COMPLETE,
            PAGING,
            INITIAL_UE_MESSAGE,
            DOWNLINK_NAS_TRANSPORT,
            UPLINK_NAS_TRANSPORT,
            NG_SETUP_REQUEST,
            NG_SETUP_RESPONSE,
            NG_SETUP_FAILURE,
        ];

        for profile in profiles {
            assert!(!profile.rules.is_empty());
            let mut ids = BTreeSet::new();
            for rule in profile.rules {
                assert!(!rule.repeatable);
                assert!(ids.insert(rule.id), "duplicate profile IE id {}", rule.id);
            }
        }
    }
}
