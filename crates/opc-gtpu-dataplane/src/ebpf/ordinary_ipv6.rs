//! Inner-IPv6 PDP contexts on an ordinary (non-grouped) eBPF attachment.
//!
//! The frozen v5 maps key the ordinary path by a four-byte IPv4 UE address.
//! The tc programs already execute the family-tagged authority
//! (`GTPU_SESSIONS`, `GTPU_UL_INDEX`, `GTPU_DL_INDEX`) before that IPv4
//! fallback: uplink selects by the inner source `/64` plus the complete packet
//! mark, and downlink by `(outer family, inner family, local TEID)` with the
//! inner destination required to lie inside the `/64`.
//!
//! An ordinary inner-IPv6 context is stored there as one single-entry
//! authority record plus exactly its two selectors, all referencing a fresh
//! random record identity. The attachment's IPv4 S2b-U endpoint is published
//! once in `GTPU_CONFIG6`/`GTPU_SCHEMA6` so tc can prove endpoint ownership;
//! IPv4 contexts keep their byte-exact v5 graph. Only the ordinary per-device
//! writer gate authorizes these effects: the protected selector namespace,
//! transaction journal, and selector stamps are never used on an ordinary
//! attachment.
//!
//! Publication writes both selectors before the authority record, so tc drops
//! (rather than falls back) while a publication is incomplete. Removal deletes
//! the authority record first, which fences the context in tc before either
//! selector is removed. An interrupted publication or removal is completed by
//! the next ordinary install or family-scoped removal; readback reports it as
//! indeterminate.

use super::*;
use crate::GtpuSessionGroupId;
use opc_gtpu_ebpf_common::{GtpuSessionPaa, GTPU_SESSION_IPV6_SLOT};

const OPERATION: &str = "ebpf_ordinary_inner_ipv6";

/// Validated projection of one ordinary inner-IPv6 PDP context.
#[derive(Clone, Copy)]
pub(super) struct OrdinaryIpv6Plan {
    entry: EbpfSessionEntry,
    uplink_key: [u8; GTPU_SESSION_UPLINK_KEY_LEN],
    downlink_key: [u8; GTPU_SESSION_DOWNLINK_KEY_LEN],
}

/// Classified state of the two selectors named by one desired context.
enum OrdinaryIpv6Observation {
    /// Neither selector exists.
    Absent,
    /// Both selectors and the authority exactly carry the desired entry.
    Exact,
    /// Only this context's own interrupted publication or removal is
    /// retained: every present selector names one record whose complete
    /// selector inventory is a subset of the desired selectors, and whose
    /// authority is absent or exactly the desired entry.
    Resumable(GtpuSessionGroupRef),
    /// A valid different context owns at least one selector.
    Occupied,
}

fn indeterminate() -> GtpuError {
    GtpuError::StateIndeterminate {
        operation: OPERATION,
    }
}

fn ordinary_ipv6_paa(address: Ipv6Addr, field: &'static str) -> Result<GtpuSessionPaa, GtpuError> {
    if address.is_multicast() {
        return Err(GtpuError::invalid_config(
            field,
            "IPv6 PDN prefix must be unicast",
        ));
    }
    GtpuSessionPaa::new(GtpuEndpointAddress::Ipv6(address.octets())).ok_or_else(|| {
        GtpuError::invalid_config(
            field,
            "IPv6 PDN address must be its nonzero /64 prefix with a zero interface identifier",
        )
    })
}

fn ordinary_ipv6_downlink_key(local_teid: [u8; 4]) -> Option<[u8; GTPU_SESSION_DOWNLINK_KEY_LEN]> {
    GtpuSessionDownlinkKey::new(
        GtpuSessionIpFamily::Ipv4,
        GtpuSessionIpFamily::Ipv6,
        local_teid,
    )
    .map(GtpuSessionDownlinkKey::encode)
}

fn ordinary_ipv6_candidate() -> Option<GtpuSessionIndexCandidate> {
    GtpuSessionIndexCandidate::new(GtpuSessionGeneration::INITIAL, GTPU_SESSION_IPV6_SLOT)
}

/// Validate one ordinary inner-IPv6 context against the attachment's IPv4
/// S2b-U endpoint.
pub(super) fn ordinary_ipv6_plan(
    context: &GtpPdpContext,
    local_ip: Ipv4Addr,
) -> Result<OrdinaryIpv6Plan, GtpuError> {
    validate_gtp_version(context.gtp_version)?;
    let IpAddr::V6(ms_address) = context.ms_address else {
        return Err(GtpuError::invalid_config(
            "pdp.ms_address",
            "an ordinary inner-IPv6 context requires an IPv6 PDN prefix",
        ));
    };
    let paa = ordinary_ipv6_paa(ms_address, "pdp.ms_address")?;
    let peer_address = match context.peer_address {
        IpAddr::V4(address) if address.is_unspecified() => {
            return Err(GtpuError::invalid_config(
                "pdp.peer_address",
                "peer address must not be unspecified",
            ));
        }
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => {
            // The ordinary attachment owns exactly one IPv4 S2b-U endpoint.
            return Err(GtpuError::UnsupportedFeature {
                feature: "ebpf_ordinary_outer_ipv6",
            });
        }
    };
    GtpuDownlinkEndpoint::new(
        context.peer_address,
        IpAddr::V4(local_ip),
        context.link_ifindex,
        context.downlink_source_port_policy,
    )
    .ok_or_else(|| {
        GtpuError::invalid_config(
            "pdp.downlink_endpoint",
            "peer, local endpoint, and ingress attachment must form one canonical identity",
        )
    })?;
    let entry = EbpfSessionEntry::new(
        paa,
        GtpuEndpointAddress::Ipv4(peer_address.octets()),
        GtpuEndpointAddress::Ipv4(local_ip.octets()),
        context.local_teid.get().to_be_bytes(),
        context.peer_teid.get().to_be_bytes(),
        context
            .bearer_mark
            .map_or([0; 4], |mark| mark.get().to_be_bytes()),
        context.egress_dscp.map(crate::DscpCodepoint::get),
        context.downlink_source_port_policy,
        context.uplink_source_port_policy,
    )
    .ok_or_else(|| {
        GtpuError::invalid_config(
            "pdp.uplink_source_port_policy",
            "uplink source-port policy and PDP graph must be canonical",
        )
    })?;
    Ok(OrdinaryIpv6Plan {
        entry,
        uplink_key: GtpuSessionUplinkKey::from_entry(entry).encode(),
        downlink_key: GtpuSessionDownlinkKey::from_entry(entry).encode(),
    })
}

fn context_from_entry(entry: EbpfSessionEntry, ifindex: u32) -> Option<GtpPdpContext> {
    let mark = u32::from_be_bytes(entry.bearer_mark());
    Some(GtpPdpContext {
        local_teid: Teid::new(u32::from_be_bytes(entry.local_teid()))?,
        peer_teid: Teid::new(u32::from_be_bytes(entry.peer_teid()))?,
        ms_address: ip_address(entry.inner_paa().canonical_address()),
        peer_address: ip_address(entry.peer_outer_address()),
        link_ifindex: ifindex,
        downlink_source_port_policy: entry.downlink_source_port_policy(),
        gtp_version: GtpVersion::V1,
        bearer_mark: if mark == 0 {
            None
        } else {
            Some(GtpBearerMark::new(mark)?)
        },
        egress_dscp: entry
            .egress_dscp()
            .map(crate::DscpCodepoint::new)
            .transpose()
            .ok()?,
        uplink_source_port_policy: entry.uplink_source_port_policy(),
    })
}

impl EbpfGtpuDataplaneBackend {
    /// Return the validated family-tagged authority of an ordinary attachment.
    ///
    /// `None` means it was never initialized, so no inner-IPv6 context can be
    /// resident or forwarded by tc.
    fn ordinary_ipv6_authority_locked(
        &self,
        ifindex: u32,
        local_ip: Ipv4Addr,
    ) -> Result<Option<(GtpuSessionDeviceConfig, bool)>, GtpuError> {
        let (raw, complete) = match self.inner.runtime.ordinary_family_authority(ifindex)? {
            OrdinaryFamilyAuthority::Uninitialized => return Ok(None),
            OrdinaryFamilyAuthority::ConfigOnly(raw) => (raw, false),
            OrdinaryFamilyAuthority::Initialized(raw) => (raw, true),
        };
        let config = GtpuSessionDeviceConfig::decode(&raw)
            .filter(|config| config.encode() == raw)
            .ok_or_else(indeterminate)?;
        if config.ingress_ifindex() != ifindex
            || config.local_endpoint(GtpuSessionIpFamily::Ipv4)
                != Some(GtpuEndpointAddress::Ipv4(local_ip.octets()))
            || config.local_endpoint(GtpuSessionIpFamily::Ipv6).is_some()
        {
            return Err(indeterminate());
        }
        Ok(Some((config, complete)))
    }

    /// Return the complete ordinary authority, initializing it on first use.
    fn ensure_ordinary_ipv6_authority_locked(
        &self,
        ifindex: u32,
        local_ip: Ipv4Addr,
    ) -> Result<GtpuSessionDeviceConfig, GtpuError> {
        let config = match self.ordinary_ipv6_authority_locked(ifindex, local_ip)? {
            Some((config, true)) => return Ok(config),
            Some((config, false)) => config,
            None => {
                let device_id = ordinary_random_device_id().ok_or_else(|| {
                    GtpuError::io(
                        OPERATION,
                        io::Error::other("secure random device identity is unavailable"),
                    )
                })?;
                GtpuSessionDeviceConfig::new(device_id, ifindex, Some(local_ip.octets()), None)
                    .ok_or_else(indeterminate)?
            }
        };
        self.inner
            .runtime
            .initialize_ordinary_family_authority(ifindex, config.encode())?;
        match self.ordinary_ipv6_authority_locked(ifindex, local_ip)? {
            Some((observed, true)) if observed == config => Ok(config),
            _ => Err(indeterminate()),
        }
    }

    /// Read one record through an observed selector value and prove that the
    /// record's own selectors both name it.
    fn read_ordinary_ipv6_reference_locked(
        &self,
        ifindex: u32,
        config: GtpuSessionDeviceConfig,
        encoded_reference: [u8; GTPU_SESSION_GROUP_REF_LEN],
    ) -> Result<(GtpuSessionGroupRef, Option<EbpfSessionEntry>), GtpuError> {
        let reference = GtpuSessionGroupRef::decode(&encoded_reference)
            .filter(|reference| reference.encode() == encoded_reference)
            .filter(|reference| {
                reference.desired().is_none() && reference.base() == ordinary_ipv6_candidate()
            })
            .ok_or_else(indeterminate)?;
        let Some(encoded_record) = self
            .inner
            .runtime
            .session_group_get(ifindex, reference.group_id().to_bytes())?
        else {
            return Ok((reference, None));
        };
        let record = GtpuSessionGroupRecord::decode(&encoded_record)
            .filter(|record| record.encode() == encoded_record)
            .ok_or_else(indeterminate)?;
        let entry = record
            .entry(GtpuSessionIpFamily::Ipv6)
            .filter(|_| {
                record.group_id() == reference.group_id()
                    && record.device_id() == config.device_id()
                    && record.generation() == GtpuSessionGeneration::INITIAL
                    && record.phase() == GtpuSessionGroupPhase::Active
                    && record.entry(GtpuSessionIpFamily::Ipv4).is_none()
            })
            .filter(|entry| {
                entry.n3_qfi().is_none()
                    && entry.outer_family() == GtpuSessionIpFamily::Ipv4
                    && config.authorizes_local(entry.local_outer_address())
            })
            .ok_or_else(indeterminate)?;
        Ok((reference, Some(entry)))
    }

    /// Read the complete context named by one present selector value.
    fn read_ordinary_ipv6_context_locked(
        &self,
        ifindex: u32,
        config: GtpuSessionDeviceConfig,
        encoded_reference: [u8; GTPU_SESSION_GROUP_REF_LEN],
    ) -> Result<GtpPdpContext, GtpuError> {
        let (_, entry) =
            self.read_ordinary_ipv6_reference_locked(ifindex, config, encoded_reference)?;
        let entry = entry.ok_or_else(indeterminate)?;
        let uplink_key = GtpuSessionUplinkKey::from_entry(entry).encode();
        let downlink_key = GtpuSessionDownlinkKey::from_entry(entry).encode();
        if self.inner.runtime.session_uplink_get(ifindex, uplink_key)? != Some(encoded_reference)
            || self
                .inner
                .runtime
                .session_downlink_get(ifindex, downlink_key)?
                != Some(encoded_reference)
        {
            return Err(indeterminate());
        }
        context_from_entry(entry, ifindex).ok_or_else(indeterminate)
    }

    /// Inspect the inner-IPv6 local-TEID selector of an ordinary attachment.
    pub(super) fn inspect_ordinary_ipv6_local_locked(
        &self,
        ifindex: u32,
        local_teid: Teid,
    ) -> Result<PdpContextReadback, GtpuError> {
        let local_ip = self.managed_local_ip_locked(ifindex)?;
        let Some((config, _)) = self.ordinary_ipv6_authority_locked(ifindex, local_ip)? else {
            return Ok(PdpContextReadback::Absent);
        };
        let key =
            ordinary_ipv6_downlink_key(local_teid.get().to_be_bytes()).ok_or_else(indeterminate)?;
        match self.inner.runtime.session_downlink_get(ifindex, key)? {
            None => Ok(PdpContextReadback::Absent),
            Some(reference) => self
                .read_ordinary_ipv6_context_locked(ifindex, config, reference)
                .map(PdpContextReadback::Present),
        }
    }

    /// Inspect the inner-IPv6 `(/64, mark)` selector of an ordinary attachment.
    pub(super) fn inspect_ordinary_ipv6_uplink_locked(
        &self,
        ifindex: u32,
        ms_address: Ipv6Addr,
        bearer_mark: Option<GtpBearerMark>,
    ) -> Result<PdpContextReadback, GtpuError> {
        let paa = ordinary_ipv6_paa(ms_address, "pdp.selector.ms_address")?;
        let local_ip = self.managed_local_ip_locked(ifindex)?;
        let Some((config, _)) = self.ordinary_ipv6_authority_locked(ifindex, local_ip)? else {
            return Ok(PdpContextReadback::Absent);
        };
        let key = GtpuSessionUplinkKey::new(
            paa,
            bearer_mark.map_or([0; 4], |mark| mark.get().to_be_bytes()),
        )
        .encode();
        match self.inner.runtime.session_uplink_get(ifindex, key)? {
            None => Ok(PdpContextReadback::Absent),
            Some(reference) => self
                .read_ordinary_ipv6_context_locked(ifindex, config, reference)
                .map(PdpContextReadback::Present),
        }
    }

    /// Prove that every selector naming `reference` is one of `allowed`.
    fn ordinary_ipv6_reference_is_confined_locked(
        &self,
        ifindex: u32,
        reference: GtpuSessionGroupRef,
        uplink_key: [u8; GTPU_SESSION_UPLINK_KEY_LEN],
        downlink_key: [u8; GTPU_SESSION_DOWNLINK_KEY_LEN],
    ) -> Result<bool, GtpuError> {
        let encoded = reference.encode();
        let inventory = self
            .inner
            .runtime
            .session_index_inventory(ifindex, reference.group_id().to_bytes())?;
        Ok(inventory
            .uplink
            .iter()
            .all(|(key, value)| *key == uplink_key && *value == encoded)
            && inventory
                .downlink
                .iter()
                .all(|(key, value)| *key == downlink_key && *value == encoded))
    }

    fn observe_ordinary_ipv6_locked(
        &self,
        ifindex: u32,
        config: GtpuSessionDeviceConfig,
        plan: &OrdinaryIpv6Plan,
    ) -> Result<OrdinaryIpv6Observation, GtpuError> {
        let uplink = self
            .inner
            .runtime
            .session_uplink_get(ifindex, plan.uplink_key)?;
        let downlink = self
            .inner
            .runtime
            .session_downlink_get(ifindex, plan.downlink_key)?;
        let encoded_reference = match (uplink, downlink) {
            (None, None) => return Ok(OrdinaryIpv6Observation::Absent),
            (Some(uplink), Some(downlink)) if uplink != downlink => {
                // Two records occupy the selectors. Each must be valid.
                for encoded in [uplink, downlink] {
                    if self
                        .read_ordinary_ipv6_reference_locked(ifindex, config, encoded)?
                        .1
                        .is_none()
                    {
                        return Err(indeterminate());
                    }
                }
                return Ok(OrdinaryIpv6Observation::Occupied);
            }
            (Some(reference), _) | (None, Some(reference)) => reference,
        };
        let (reference, entry) =
            self.read_ordinary_ipv6_reference_locked(ifindex, config, encoded_reference)?;
        match entry {
            Some(entry) if entry != plan.entry => {
                let own_uplink = GtpuSessionUplinkKey::from_entry(entry).encode();
                let own_downlink = GtpuSessionDownlinkKey::from_entry(entry).encode();
                if self.inner.runtime.session_uplink_get(ifindex, own_uplink)?
                    == Some(encoded_reference)
                    && self
                        .inner
                        .runtime
                        .session_downlink_get(ifindex, own_downlink)?
                        == Some(encoded_reference)
                {
                    Ok(OrdinaryIpv6Observation::Occupied)
                } else {
                    Err(indeterminate())
                }
            }
            Some(_) if uplink.is_some() && downlink.is_some() => Ok(OrdinaryIpv6Observation::Exact),
            Some(_) | None => {
                if self.ordinary_ipv6_reference_is_confined_locked(
                    ifindex,
                    reference,
                    plan.uplink_key,
                    plan.downlink_key,
                )? {
                    Ok(OrdinaryIpv6Observation::Resumable(reference))
                } else {
                    Err(indeterminate())
                }
            }
        }
    }

    fn put_ordinary_ipv6_selector_locked(
        &self,
        ifindex: u32,
        key: GroupedIndexKey,
        reference: [u8; GTPU_SESSION_GROUP_REF_LEN],
    ) -> Result<(), GtpuError> {
        if self.grouped_index_get(ifindex, key)? == Some(reference) {
            return Ok(());
        }
        let _ = self.grouped_index_put(
            ifindex,
            GroupedIndexElement {
                key,
                value: reference,
            },
            EbpfMapUpdateMode::NoExist,
        );
        if self.grouped_index_get(ifindex, key)? == Some(reference) {
            Ok(())
        } else {
            Err(indeterminate())
        }
    }

    /// Install one ordinary inner-IPv6 context under the device writer gate.
    pub(super) fn install_ordinary_ipv6_locked(
        &self,
        request: &GtpPdpContext,
        local_ip: Ipv4Addr,
    ) -> Result<(), GtpuError> {
        let ifindex = request.link_ifindex;
        let plan = ordinary_ipv6_plan(request, local_ip)?;
        if !self.inner.runtime.pdp_readback_datapath_usable(ifindex) {
            return Err(GtpuError::io(
                "ebpf_ordinary_inner_ipv6_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live family-tagged datapath identity is unavailable",
                ),
            ));
        }
        let config = self.ensure_ordinary_ipv6_authority_locked(ifindex, local_ip)?;
        if !self
            .inner
            .runtime
            .grouped_datapath_usable(ifindex, config.encode())
        {
            return Err(GtpuError::io(
                "ebpf_ordinary_inner_ipv6_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live family-tagged datapath identity is unavailable",
                ),
            ));
        }
        let reference = match self.observe_ordinary_ipv6_locked(ifindex, config, &plan)? {
            OrdinaryIpv6Observation::Exact => return Ok(()),
            OrdinaryIpv6Observation::Occupied => return Err(GtpuError::AlreadyExists),
            OrdinaryIpv6Observation::Resumable(reference) => reference,
            OrdinaryIpv6Observation::Absent => {
                let group_id = ordinary_random_group_id().ok_or_else(|| {
                    GtpuError::io(
                        OPERATION,
                        io::Error::other("secure random record identity is unavailable"),
                    )
                })?;
                GtpuSessionGroupRef::single(
                    group_id,
                    ordinary_ipv6_candidate().ok_or_else(indeterminate)?,
                )
            }
        };
        let encoded_reference = reference.encode();
        let record = GtpuSessionGroupRecord::active(
            reference.group_id(),
            config.device_id(),
            GtpuSessionGeneration::INITIAL,
            None,
            Some(plan.entry),
        )
        .ok_or_else(indeterminate)?;
        self.put_ordinary_ipv6_selector_locked(
            ifindex,
            GroupedIndexKey::Uplink(plan.uplink_key),
            encoded_reference,
        )?;
        self.put_ordinary_ipv6_selector_locked(
            ifindex,
            GroupedIndexKey::Downlink(plan.downlink_key),
            encoded_reference,
        )?;
        let key = reference.group_id().to_bytes();
        let encoded_record = record.encode();
        if self.inner.runtime.session_group_get(ifindex, key)? != Some(encoded_record) {
            let _ = self.inner.runtime.session_group_put(
                ifindex,
                key,
                encoded_record,
                EbpfMapUpdateMode::NoExist,
            );
        }
        match self.observe_ordinary_ipv6_locked(ifindex, config, &plan)? {
            OrdinaryIpv6Observation::Exact => Ok(()),
            _ => Err(indeterminate()),
        }
    }

    /// Remove the ordinary inner-IPv6 context named by one local TEID.
    ///
    /// The authority record is deleted first so tc fences the context before
    /// either selector is removed. A retained selector whose record is absent
    /// is an interrupted publication or removal; its exact selector inventory
    /// is removed.
    pub(super) fn remove_ordinary_ipv6_locked(
        &self,
        ifindex: u32,
        local_teid: Teid,
    ) -> Result<(), GtpuError> {
        let local_ip = self.managed_local_ip_locked(ifindex)?;
        let Some((config, _)) = self.ordinary_ipv6_authority_locked(ifindex, local_ip)? else {
            return Ok(());
        };
        let downlink_key =
            ordinary_ipv6_downlink_key(local_teid.get().to_be_bytes()).ok_or_else(indeterminate)?;
        let Some(encoded_reference) = self
            .inner
            .runtime
            .session_downlink_get(ifindex, downlink_key)?
        else {
            return Ok(());
        };
        let (reference, entry) =
            self.read_ordinary_ipv6_reference_locked(ifindex, config, encoded_reference)?;
        let (uplink_keys, downlink_keys) = match entry {
            Some(entry) => {
                if GtpuSessionDownlinkKey::from_entry(entry).encode() != downlink_key {
                    return Err(indeterminate());
                }
                let uplink_key = GtpuSessionUplinkKey::from_entry(entry).encode();
                if !self.ordinary_ipv6_reference_is_confined_locked(
                    ifindex,
                    reference,
                    uplink_key,
                    downlink_key,
                )? {
                    return Err(indeterminate());
                }
                let key = reference.group_id().to_bytes();
                let _ = self.inner.runtime.session_group_remove(ifindex, key);
                if self
                    .inner
                    .runtime
                    .session_group_get(ifindex, key)?
                    .is_some()
                {
                    return Err(indeterminate());
                }
                (vec![uplink_key], vec![downlink_key])
            }
            None => {
                let inventory = self
                    .inner
                    .runtime
                    .session_index_inventory(ifindex, reference.group_id().to_bytes())?;
                if inventory
                    .uplink
                    .iter()
                    .any(|(_, value)| *value != encoded_reference)
                    || inventory
                        .downlink
                        .iter()
                        .any(|(_, value)| *value != encoded_reference)
                {
                    return Err(indeterminate());
                }
                (
                    inventory.uplink.iter().map(|(key, _)| *key).collect(),
                    inventory.downlink.iter().map(|(key, _)| *key).collect(),
                )
            }
        };
        for key in uplink_keys {
            let _ = self.inner.runtime.session_uplink_remove(ifindex, key);
            if self
                .inner
                .runtime
                .session_uplink_get(ifindex, key)?
                .is_some()
            {
                return Err(indeterminate());
            }
        }
        for key in downlink_keys {
            let _ = self.inner.runtime.session_downlink_remove(ifindex, key);
            if self
                .inner
                .runtime
                .session_downlink_get(ifindex, key)?
                .is_some()
            {
                return Err(indeterminate());
            }
        }
        Ok(())
    }
}

fn ordinary_random_bytes() -> Option<[u8; GTPU_SESSION_GROUP_ID_LEN]> {
    let mut rng = SysRng;
    for _ in 0..4 {
        let mut value = [0_u8; GTPU_SESSION_GROUP_ID_LEN];
        if rng.try_fill_bytes(&mut value).is_err() {
            return None;
        }
        if value.iter().any(|byte| *byte != 0) {
            return Some(value);
        }
    }
    None
}

fn ordinary_random_device_id() -> Option<GtpuSessionDeviceId> {
    ordinary_random_bytes().and_then(GtpuSessionDeviceId::new)
}

fn ordinary_random_group_id() -> Option<GtpuSessionGroupId> {
    ordinary_random_bytes().and_then(GtpuSessionGroupId::new)
}
