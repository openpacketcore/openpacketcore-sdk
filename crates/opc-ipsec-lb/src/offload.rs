//! NIC/DPU offload security posture guards.

use crate::error::IpsecLbError;

/// Key-custody posture for NIC/DPU offload deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NicOffloadSecurityPosture {
    /// No NIC/DPU offload is used.
    #[default]
    NotUsed,
    /// NIC/DPU offload is used only for steering, not inline IPsec crypto.
    SteeringOnly,
    /// Inline NIC/DPU IPsec crypto offload is used.
    InlineIpsecCrypto {
        /// The NIC/DPU key-custody boundary is documented in FIPS scope.
        fips_boundary_documented: bool,
        /// The NIC/DPU is documented in HSM/key-custody scope.
        hsm_scope_documented: bool,
    },
}

impl NicOffloadSecurityPosture {
    /// No NIC/DPU offload.
    #[must_use]
    pub const fn not_used() -> Self {
        Self::NotUsed
    }

    /// Steering-only NIC/DPU offload, with no IPsec key custody on the NIC.
    #[must_use]
    pub const fn steering_only() -> Self {
        Self::SteeringOnly
    }

    /// Inline IPsec crypto offload on the NIC/DPU.
    #[must_use]
    pub const fn inline_ipsec_crypto(
        fips_boundary_documented: bool,
        hsm_scope_documented: bool,
    ) -> Self {
        Self::InlineIpsecCrypto {
            fips_boundary_documented,
            hsm_scope_documented,
        }
    }

    /// Validate the offload posture before a NIC/DPU adapter is enabled.
    pub const fn validate(self) -> Result<(), IpsecLbError> {
        match self {
            Self::NotUsed | Self::SteeringOnly => Ok(()),
            Self::InlineIpsecCrypto {
                fips_boundary_documented: true,
                hsm_scope_documented: true,
            } => Ok(()),
            Self::InlineIpsecCrypto { .. } => Err(IpsecLbError::invalid_config(
                "nic_offload_security",
                "inline IPsec crypto offload requires documented FIPS and HSM/key-custody scope",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_only_offload_is_not_key_custody() {
        NicOffloadSecurityPosture::not_used().validate().unwrap();
        NicOffloadSecurityPosture::steering_only()
            .validate()
            .unwrap();
    }

    #[test]
    fn inline_crypto_requires_both_custody_documents() {
        assert!(matches!(
            NicOffloadSecurityPosture::inline_ipsec_crypto(false, true)
                .validate()
                .unwrap_err(),
            IpsecLbError::InvalidConfig { .. }
        ));
        assert!(matches!(
            NicOffloadSecurityPosture::inline_ipsec_crypto(true, false)
                .validate()
                .unwrap_err(),
            IpsecLbError::InvalidConfig { .. }
        ));
        NicOffloadSecurityPosture::inline_ipsec_crypto(true, true)
            .validate()
            .unwrap();
    }
}
