//! Standard SBI service names (3GPP TS 29.510).
//!
//! These are the well-known `nfService` values used in NRF registrations.
//! Vendor-specific or release-specific service names can still be supplied as
//! raw strings.

/// AMF Communication service.
pub const NAMF_COMM: &str = "namf-comm";
/// AMF Event Exposure service.
pub const NAMF_EVTS: &str = "namf-evts";
/// AMF Mobile Terminated service.
pub const NAMF_MT: &str = "namf-mt";
/// AMF Location service.
pub const NAMF_LOC: &str = "namf-loc";

/// SMF PDU Session service.
pub const NSMF_PDUSESSION: &str = "nsmf-pdusession";
/// SMF Event Exposure service.
pub const NSMF_EVENTEXPOSURE: &str = "nsmf-eventexposure";

/// NRF NFManagement service.
pub const NNF_NFM: &str = "nnrf-nfm";
/// NRF NFDiscovery service.
pub const NNF_DISC: &str = "nnrf-disc";

/// AUSF Authentication service.
pub const NAUSF_AUTH: &str = "nausf-auth";

/// UDM Subscriber Data Management service.
pub const NUDM_SDM: &str = "nudm-sdm";
/// UDM UE Authentication service.
pub const NUDM_UEAU: &str = "nudm-ueau";

/// PCF Policy Authorization service.
pub const NPCF_POLICYAUTHORIZATION: &str = "npcf-policyauthorization";
/// PCF AMPolicyControl service.
pub const NPCF_AM_POLICY_CONTROL: &str = "npcf-am-policy-control";

/// NSSF NS Selection service.
pub const NSNSSF_NSSELECTION: &str = "nssf-nsselection";
