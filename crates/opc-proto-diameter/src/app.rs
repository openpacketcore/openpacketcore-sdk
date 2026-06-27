//! Initial 3GPP Diameter application dictionary skeletons.
//!
//! The `app-*` features record product-neutral application identifiers and
//! placeholder dictionary entries for later AVP/command additions. They do not
//! implement Gx/Rf/S6a/S6b/SWm/SWx business behavior, realm routing, or
//! charging policy.

use opc_protocol::SpecRef;

use crate::base;
use crate::dictionary::{ApplicationDefinition, Dictionary, DictionarySet};
use crate::{ApplicationId, VendorId};

/// 3GPP vendor identifier used in Diameter Vendor-Specific-Application-Id AVPs.
pub const VENDOR_ID_3GPP: VendorId = VendorId::new(10415);

#[cfg(feature = "app-gx")]
pub use gx::APPLICATION_ID as APPLICATION_ID_GX;
#[cfg(feature = "app-rf")]
pub use rf::APPLICATION_ID as APPLICATION_ID_RF_ACCOUNTING;
#[cfg(feature = "app-s6a")]
pub use s6a::APPLICATION_ID as APPLICATION_ID_S6A_S6D;
#[cfg(feature = "app-s6b")]
pub use s6b::APPLICATION_ID as APPLICATION_ID_S6B;
#[cfg(feature = "app-swm")]
pub use swm::APPLICATION_ID as APPLICATION_ID_SWM;
#[cfg(feature = "app-swx")]
pub use swx::APPLICATION_ID as APPLICATION_ID_SWX;

/// 3GPP Gx application dictionary skeleton.
#[cfg(feature = "app-gx")]
pub mod gx {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// 3GPP Gx application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_238);

    /// 3GPP Gx application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP Gx",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29212", "Gx Diameter application"),
    );
}

/// 3GPP Rf accounting application dictionary skeleton.
#[cfg(feature = "app-rf")]
pub mod rf {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// Diameter accounting application identifier used by 3GPP Rf accounting.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(3);

    /// 3GPP Rf application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP Rf accounting over Diameter accounting",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS32299", "Rf Diameter application"),
    );
}

/// 3GPP S6a/S6d application dictionary skeleton.
#[cfg(feature = "app-s6a")]
pub mod s6a {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// 3GPP S6a/S6d application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_251);

    /// 3GPP S6a/S6d application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP S6a/S6d",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29272", "S6a/S6d Diameter application"),
    );
}

/// 3GPP S6b application dictionary skeleton.
#[cfg(feature = "app-s6b")]
pub mod s6b {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// 3GPP S6b application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_272);

    /// 3GPP S6b application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP S6b",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29273", "S6b Diameter application"),
    );
}

/// 3GPP SWm application dictionary skeleton.
#[cfg(feature = "app-swm")]
pub mod swm {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// 3GPP SWm application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_264);

    /// 3GPP SWm application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP SWm",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29273", "SWm Diameter application"),
    );
}

/// 3GPP SWx application dictionary skeleton.
#[cfg(feature = "app-swx")]
pub mod swx {
    use super::{ApplicationDefinition, ApplicationId, SpecRef, VENDOR_ID_3GPP};

    /// 3GPP SWx application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_265);

    /// 3GPP SWx application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP SWx",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29273", "SWx Diameter application"),
    );
}

const APP_APPLICATIONS: &[ApplicationDefinition] = &[
    #[cfg(feature = "app-rf")]
    rf::APPLICATION,
    #[cfg(feature = "app-gx")]
    gx::APPLICATION,
    #[cfg(feature = "app-s6a")]
    s6a::APPLICATION,
    #[cfg(feature = "app-s6b")]
    s6b::APPLICATION,
    #[cfg(feature = "app-swm")]
    swm::APPLICATION,
    #[cfg(feature = "app-swx")]
    swx::APPLICATION,
];

const APP_COMMANDS: [crate::dictionary::CommandDefinition; 0] = [];
const APP_AVPS: [crate::dictionary::AvpDefinition; 0] = [];

/// Static initial 3GPP application dictionary scaffold.
pub static APP_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-app-scaffold",
    APP_APPLICATIONS,
    &APP_COMMANDS,
    &APP_AVPS,
);

static APP_DICTIONARY_REFS: [&Dictionary; 2] = [base::dictionary(), &APP_DICTIONARY];

/// Dictionary set layering RFC 6733 base metadata before 3GPP application metadata.
pub static APP_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&APP_DICTIONARY_REFS);

/// Return the static initial 3GPP application dictionary scaffold.
pub const fn dictionary() -> &'static Dictionary {
    &APP_DICTIONARY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "app-gx")]
    fn app_dictionary_contains_gx_application() {
        let gx = APP_DICTIONARIES.find_application(APPLICATION_ID_GX);
        assert!(matches!(gx, Some(definition) if definition.name() == "3GPP Gx"));
    }

    #[test]
    #[cfg(feature = "app-rf")]
    fn app_dictionary_contains_rf_application() {
        let rf = APP_DICTIONARIES.find_application(APPLICATION_ID_RF_ACCOUNTING);
        assert!(
            matches!(rf, Some(definition) if definition.name() == "3GPP Rf accounting over Diameter accounting")
        );
    }

    #[test]
    #[cfg(feature = "app-s6a")]
    fn app_dictionary_contains_s6a_application() {
        let s6a = APP_DICTIONARIES.find_application(APPLICATION_ID_S6A_S6D);
        assert!(matches!(s6a, Some(definition) if definition.name() == "3GPP S6a/S6d"));
    }

    #[test]
    #[cfg(feature = "app-s6b")]
    fn app_dictionary_contains_s6b_application() {
        let s6b = APP_DICTIONARIES.find_application(APPLICATION_ID_S6B);
        assert!(matches!(s6b, Some(definition) if definition.name() == "3GPP S6b"));
    }

    #[test]
    #[cfg(feature = "app-swm")]
    fn app_dictionary_contains_swm_application() {
        let swm = APP_DICTIONARIES.find_application(APPLICATION_ID_SWM);
        assert!(matches!(swm, Some(definition) if definition.name() == "3GPP SWm"));
    }

    #[test]
    #[cfg(feature = "app-swx")]
    fn app_dictionary_contains_swx_application() {
        let swx = APP_DICTIONARIES.find_application(APPLICATION_ID_SWX);
        assert!(matches!(swx, Some(definition) if definition.name() == "3GPP SWx"));
    }
}
