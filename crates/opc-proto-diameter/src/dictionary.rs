//! Diameter dictionary metadata primitives.
//!
//! The types in this module describe AVP, command, and application metadata in
//! a transport-neutral form. They intentionally do not embed realm routing,
//! peer topology, subscriber policy, or charging behavior.

use opc_protocol::SpecRef;

use crate::{ApplicationId, AvpCode, CommandCode, VendorId};

/// Dictionary key for an AVP code plus optional vendor identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvpKey {
    code: AvpCode,
    vendor_id: Option<VendorId>,
}

impl AvpKey {
    /// Create a vendor-neutral IETF AVP key.
    pub const fn ietf(code: AvpCode) -> Self {
        Self {
            code,
            vendor_id: None,
        }
    }

    /// Create a vendor-specific AVP key.
    pub const fn vendor(code: AvpCode, vendor_id: VendorId) -> Self {
        Self {
            code,
            vendor_id: Some(vendor_id),
        }
    }

    /// Return the AVP code.
    pub const fn code(self) -> AvpCode {
        self.code
    }

    /// Return the vendor identifier, if the AVP is vendor-specific.
    pub const fn vendor_id(self) -> Option<VendorId> {
        self.vendor_id
    }
}

/// Diameter AVP data type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvpDataType {
    /// RFC 6733 `OctetString`.
    OctetString,
    /// RFC 6733 `Integer32`.
    Integer32,
    /// RFC 6733 `Integer64`.
    Integer64,
    /// RFC 6733 `Unsigned32`.
    Unsigned32,
    /// RFC 6733 `Unsigned64`.
    Unsigned64,
    /// RFC 6733 `Float32`.
    Float32,
    /// RFC 6733 `Float64`.
    Float64,
    /// RFC 6733 `Grouped`.
    Grouped,
    /// RFC 6733 `Address`.
    Address,
    /// RFC 6733 `Time`.
    Time,
    /// RFC 6733 `UTF8String`.
    Utf8String,
    /// RFC 6733 `DiameterIdentity`.
    DiameterIdentity,
    /// RFC 6733 `DiameterURI`.
    DiameterUri,
    /// RFC 6733 `Enumerated`.
    Enumerated,
    /// RFC 6733 `IPFilterRule`.
    IpFilterRule,
    /// RFC 6733 `QoSFilterRule`.
    QosFilterRule,
}

/// Flag requirement for a dictionary-defined AVP bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagRequirement {
    /// The flag must be set by encoders and accepted decoders.
    MustBeSet,
    /// The flag must be unset by encoders and accepted decoders.
    MustBeUnset,
    /// The flag may be set or unset depending on the concrete AVP use.
    MayBeSet,
}

/// Dictionary constraints for AVP V, M, and P flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvpFlagRules {
    vendor: FlagRequirement,
    mandatory: FlagRequirement,
    protected: FlagRequirement,
}

impl AvpFlagRules {
    /// Create AVP flag constraints.
    pub const fn new(
        vendor: FlagRequirement,
        mandatory: FlagRequirement,
        protected: FlagRequirement,
    ) -> Self {
        Self {
            vendor,
            mandatory,
            protected,
        }
    }

    /// Flag constraints for common RFC 6733 base AVPs that require the M bit.
    pub const fn base_mandatory() -> Self {
        Self::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        )
    }

    /// Flag constraints for common RFC 6733 base AVPs where the M bit is optional.
    pub const fn base_optional() -> Self {
        Self::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        )
    }

    /// Flag constraints for RFC 6733 base AVPs whose M bit must not be set.
    pub const fn base_must_not_set_m() -> Self {
        Self::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
        )
    }

    /// Flag constraints for vendor-specific AVPs whose M bit may vary by application.
    pub const fn vendor_specific() -> Self {
        Self::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        )
    }

    /// Requirement for the AVP V bit.
    pub const fn vendor(self) -> FlagRequirement {
        self.vendor
    }

    /// Requirement for the AVP M bit.
    pub const fn mandatory(self) -> FlagRequirement {
        self.mandatory
    }

    /// Requirement for the AVP P bit.
    pub const fn protected(self) -> FlagRequirement {
        self.protected
    }
}

/// Metadata for a Diameter AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvpDefinition {
    key: AvpKey,
    name: &'static str,
    data_type: AvpDataType,
    flags: AvpFlagRules,
    spec_ref: SpecRef,
}

impl AvpDefinition {
    /// Create a dictionary AVP definition.
    pub const fn new(
        key: AvpKey,
        name: &'static str,
        data_type: AvpDataType,
        flags: AvpFlagRules,
        spec_ref: SpecRef,
    ) -> Self {
        Self {
            key,
            name,
            data_type,
            flags,
            spec_ref,
        }
    }

    /// Return the AVP lookup key.
    pub const fn key(&self) -> AvpKey {
        self.key
    }

    /// Return the AVP display name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Return the AVP data type classification.
    pub const fn data_type(&self) -> AvpDataType {
        self.data_type
    }

    /// Return the AVP flag constraints.
    pub const fn flags(&self) -> AvpFlagRules {
        self.flags
    }

    /// Return the specification reference for this AVP definition.
    pub const fn spec_ref(&self) -> &SpecRef {
        &self.spec_ref
    }
}

/// Request/answer role for a Diameter command definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandKind {
    /// Request command with the Diameter R bit set.
    Request,
    /// Answer command with the Diameter R bit unset.
    Answer,
}

/// Metadata for a Diameter command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDefinition {
    code: CommandCode,
    name: &'static str,
    kind: CommandKind,
    application_id: ApplicationId,
    proxiable: bool,
    spec_ref: SpecRef,
}

impl CommandDefinition {
    /// Create a command definition.
    pub const fn new(
        code: CommandCode,
        name: &'static str,
        kind: CommandKind,
        application_id: ApplicationId,
        proxiable: bool,
        spec_ref: SpecRef,
    ) -> Self {
        Self {
            code,
            name,
            kind,
            application_id,
            proxiable,
            spec_ref,
        }
    }

    /// Return the command code.
    pub const fn code(&self) -> CommandCode {
        self.code
    }

    /// Return the command display name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Return whether this definition is for the request or answer form.
    pub const fn kind(&self) -> CommandKind {
        self.kind
    }

    /// Return the Diameter application identifier for the command.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Return whether the command is proxiable.
    pub const fn proxiable(&self) -> bool {
        self.proxiable
    }

    /// Return the specification reference for this command definition.
    pub const fn spec_ref(&self) -> &SpecRef {
        &self.spec_ref
    }
}

/// Metadata for a Diameter application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationDefinition {
    id: ApplicationId,
    name: &'static str,
    vendor_id: Option<VendorId>,
    spec_ref: SpecRef,
}

impl ApplicationDefinition {
    /// Create an application definition.
    pub const fn new(
        id: ApplicationId,
        name: &'static str,
        vendor_id: Option<VendorId>,
        spec_ref: SpecRef,
    ) -> Self {
        Self {
            id,
            name,
            vendor_id,
            spec_ref,
        }
    }

    /// Return the application identifier.
    pub const fn id(&self) -> ApplicationId {
        self.id
    }

    /// Return the application display name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Return the vendor identifier associated with the application, if any.
    pub const fn vendor_id(&self) -> Option<VendorId> {
        self.vendor_id
    }

    /// Return the specification reference for this application definition.
    pub const fn spec_ref(&self) -> &SpecRef {
        &self.spec_ref
    }
}

/// Static Diameter dictionary made of applications, commands, and AVPs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dictionary {
    name: &'static str,
    applications: &'static [ApplicationDefinition],
    commands: &'static [CommandDefinition],
    avps: &'static [AvpDefinition],
}

impl Dictionary {
    /// Create a static dictionary.
    pub const fn new(
        name: &'static str,
        applications: &'static [ApplicationDefinition],
        commands: &'static [CommandDefinition],
        avps: &'static [AvpDefinition],
    ) -> Self {
        Self {
            name,
            applications,
            commands,
            avps,
        }
    }

    /// Return the dictionary name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Return all application definitions in this dictionary.
    pub const fn applications(&self) -> &'static [ApplicationDefinition] {
        self.applications
    }

    /// Return all command definitions in this dictionary.
    pub const fn commands(&self) -> &'static [CommandDefinition] {
        self.commands
    }

    /// Return all AVP definitions in this dictionary.
    pub const fn avps(&self) -> &'static [AvpDefinition] {
        self.avps
    }

    /// Find an application definition by application identifier.
    pub fn find_application(&self, id: ApplicationId) -> Option<&ApplicationDefinition> {
        self.applications
            .iter()
            .find(|definition| definition.id() == id)
    }

    /// Find a command definition by code and request/answer role.
    pub fn find_command(&self, code: CommandCode, kind: CommandKind) -> Option<&CommandDefinition> {
        self.commands
            .iter()
            .find(|definition| definition.code() == code && definition.kind() == kind)
    }

    /// Find an AVP definition by code plus optional vendor identifier.
    pub fn find_avp(&self, key: AvpKey) -> Option<&AvpDefinition> {
        self.avps.iter().find(|definition| definition.key() == key)
    }
}

/// Ordered set of dictionaries used for layered lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DictionarySet<'a> {
    dictionaries: &'a [&'a Dictionary],
}

impl<'a> DictionarySet<'a> {
    /// Create a dictionary set from an ordered slice.
    pub const fn new(dictionaries: &'a [&'a Dictionary]) -> Self {
        Self { dictionaries }
    }

    /// Return the dictionaries in lookup order.
    pub const fn dictionaries(self) -> &'a [&'a Dictionary] {
        self.dictionaries
    }

    /// Find an application definition in the set.
    pub fn find_application(self, id: ApplicationId) -> Option<&'a ApplicationDefinition> {
        self.dictionaries
            .iter()
            .find_map(|dictionary| dictionary.find_application(id))
    }

    /// Find a command definition in the set.
    pub fn find_command(
        self,
        code: CommandCode,
        kind: CommandKind,
    ) -> Option<&'a CommandDefinition> {
        self.dictionaries
            .iter()
            .find_map(|dictionary| dictionary.find_command(code, kind))
    }

    /// Find an AVP definition in the set.
    pub fn find_avp(self, key: AvpKey) -> Option<&'a AvpDefinition> {
        self.dictionaries
            .iter()
            .find_map(|dictionary| dictionary.find_avp(key))
    }
}
