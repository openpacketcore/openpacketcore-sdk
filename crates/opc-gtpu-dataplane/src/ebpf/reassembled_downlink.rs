//! Backend-authoritative consumer for G-PDUs delivered to the shared UDP/2152
//! queue (kernel outer-fragment reassembly and unknown-TEID handoff).
//!
//! The tc downlink program hands outer IPv4 fragments to the kernel unchanged
//! (`GtpuDownlinkFragmentContract::KernelReassemblyHandoff`). The kernel
//! reassembles them and delivers one complete UDP payload to the backend-owned
//! socket. This module authorizes that payload with the *same* decisions as
//! the tc fast path, reading the backend's own maps through the runtime:
//!
//! 1. the grouped downlink index first; a present index never falls back to
//!    the v5 TEID maps, and its Active generation, device, slot, local
//!    endpoint, peer, source-port policy and inner destination must all match;
//! 2. on a true index miss, the v5 legacy/marked PDR, endpoint binding, owner
//!    journal, FAR and DSCP, with the Active `PdpContextCommit` read **last**
//!    as the publication fence.
//!
//! The shared wire validators in `opc-gtpu-ebpf-common` are the same code the
//! tc object runs. Any read failure is `StateUnavailable`, never a fallback.

use bytes::Bytes;
use opc_gtpu_ebpf_common::{
    gtpu_endpoint_requires_extension_control, marked_owner_wire_authorizes_downlink,
    n3_downlink_psc_matches, parse_gtpu_tpdu, pdp_commit_wire_authorized_source_port,
    pdp_commit_wire_authorizes_downlink, select_gtpu_session_entry_wire,
    validate_ipv4_downlink_binding_wire, DownlinkBindingMismatch, DownlinkPdr,
    GtpuSessionDeviceConfig, GtpuSessionIpFamily, MarkedDownlinkPdr, UplinkFar, UplinkFarKey,
    GTPU_SESSION_DOWNLINK_KEY_LEN, GTPU_SESSION_GROUP_ID_LEN,
};

use super::EbpfGtpuRuntime;
use crate::control_port::{GtpuControlDatagram, GtpuControlDatagramKind};
use crate::model::{GtpAddressFamily, GtpBearerMark};
use crate::reassembly::{
    GtpuDecapsulatedDownlink, GtpuDownlinkCounters, GtpuDownlinkDrop, GtpuDownlinkEvent,
};

const GTPU_MANDATORY_HEADER_LEN: usize = 8;
const GTPU_OPTIONAL_BLOCK_LEN: usize = 4;
const GTPU_FLAG_EXTENSION: u8 = 0x04;
const GTPU_MAX_EXTENSION_HEADERS: usize = 4;
const PDU_SESSION_CONTAINER: u8 = 0x85;

/// Exact attachment scope for one processing call, captured under the
/// backend's attachment serialization boundary.
#[derive(Clone, Copy)]
pub(super) struct DownlinkAuthorityScope {
    pub(super) ifindex: u32,
    /// Canonical grouped device configuration; `None` for an ordinary
    /// attachment, whose grouped index must stay empty.
    pub(super) grouped_config: Option<GtpuSessionDeviceConfig>,
}

enum Verdict {
    Decapsulate {
        payload_offset: usize,
        bearer_mark: [u8; 4],
        family: GtpAddressFamily,
    },
    Control,
    UnknownTunnel,
    Drop(GtpuDownlinkDrop),
}

/// Authorize and decapsulate one received datagram, recording exactly one
/// counter.
pub(super) fn process_downlink_datagram(
    runtime: &dyn EbpfGtpuRuntime,
    scope: DownlinkAuthorityScope,
    datagram: GtpuControlDatagram,
    counters: &mut GtpuDownlinkCounters,
) -> GtpuDownlinkEvent {
    let verdict = authorize(runtime, scope, &datagram);
    match verdict {
        Verdict::Decapsulate {
            payload_offset,
            bearer_mark,
            family,
        } => {
            counters.decapsulated = counters.decapsulated.saturating_add(1);
            let inner: Bytes = datagram.bytes_handle().slice(payload_offset..);
            GtpuDownlinkEvent::Decapsulated(GtpuDecapsulatedDownlink::new(
                inner,
                GtpBearerMark::new(u32::from_be_bytes(bearer_mark)),
                family,
            ))
        }
        Verdict::Control => {
            counters.control_plane = counters.control_plane.saturating_add(1);
            GtpuDownlinkEvent::Control(datagram)
        }
        Verdict::UnknownTunnel => {
            counters.unknown_tunnel = counters.unknown_tunnel.saturating_add(1);
            GtpuDownlinkEvent::UnknownTunnel(datagram)
        }
        Verdict::Drop(reason) => {
            counters.record_drop(reason);
            GtpuDownlinkEvent::Dropped(reason)
        }
    }
}

fn authorize(
    runtime: &dyn EbpfGtpuRuntime,
    scope: DownlinkAuthorityScope,
    datagram: &GtpuControlDatagram,
) -> Verdict {
    match datagram.kind() {
        GtpuControlDatagramKind::Gpdu => {}
        GtpuControlDatagramKind::Malformed => {
            return Verdict::Drop(GtpuDownlinkDrop::Malformed);
        }
        GtpuControlDatagramKind::Control
        | GtpuControlDatagramKind::Unmodelled
        | GtpuControlDatagramKind::UnsupportedRequiredExtension => return Verdict::Control,
    }
    let message = datagram.bytes();
    // The fast path's own bounded parser decides the T-PDU offset; the typed
    // codec classification above is necessary but not sufficient.
    let tpdu = match parse_gtpu_tpdu(message) {
        Ok(Some(tpdu)) => tpdu,
        Ok(None) => return Verdict::Control,
        Err(_) => return Verdict::Drop(GtpuDownlinkDrop::Malformed),
    };
    let payload_offset = message.len() - tpdu.payload.len();
    let payload = tpdu.payload;
    let teid = tpdu.teid;
    let provenance = datagram.provenance();
    // A positive packet-info ifindex was already matched to the sealed socket;
    // it must also be this exact attachment.
    if provenance.ingress_ifindex() != scope.ifindex {
        return Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(
            DownlinkBindingMismatch::IngressAttachment,
        ));
    }
    match runtime.traffic_gate_allows_packet_effects(scope.ifindex) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Verdict::Drop(GtpuDownlinkDrop::StateUnavailable),
    }

    // tc: `grouped_downlink_authority`. An unknown inner version or zero TEID
    // is a grouped lookup error, never a v5 fallback.
    let inner_family = match payload[0] >> 4 {
        4 => GtpuSessionIpFamily::Ipv4,
        6 => GtpuSessionIpFamily::Ipv6,
        _ => {
            return Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid,
            ))
        }
    };
    if teid == [0; 4] {
        return Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(
            DownlinkBindingMismatch::Invalid,
        ));
    }
    let mut index_key = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
    index_key[0] = GtpuSessionIpFamily::Ipv4 as u8;
    index_key[1] = inner_family as u8;
    index_key[4..8].copy_from_slice(&teid);
    let reference = match runtime.session_downlink_get(scope.ifindex, index_key) {
        Ok(reference) => reference,
        Err(_) => return Verdict::Drop(GtpuDownlinkDrop::StateUnavailable),
    };
    if let Some(reference) = reference {
        return authorize_grouped(
            runtime,
            scope,
            datagram,
            &index_key,
            &reference,
            inner_family,
            payload_offset,
        );
    }
    authorize_legacy(runtime, scope, datagram, teid, payload_offset)
}

#[allow(clippy::too_many_arguments)]
fn authorize_grouped(
    runtime: &dyn EbpfGtpuRuntime,
    scope: DownlinkAuthorityScope,
    datagram: &GtpuControlDatagram,
    index_key: &[u8; GTPU_SESSION_DOWNLINK_KEY_LEN],
    reference: &[u8; opc_gtpu_ebpf_common::GTPU_SESSION_GROUP_REF_LEN],
    inner_family: GtpuSessionIpFamily,
    payload_offset: usize,
) -> Verdict {
    let invalid = Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(
        DownlinkBindingMismatch::Invalid,
    ));
    // An ordinary attachment has no canonical grouped configuration, so tc
    // cannot select any retained grouped entry for it.
    let Some(config) = scope.grouped_config else {
        return invalid;
    };
    let config_wire = config.encode();
    // Proves the live pinned configuration, schema marker, and exact hooks.
    if !runtime.grouped_datapath_usable(scope.ifindex, config_wire) {
        return Verdict::Drop(GtpuDownlinkDrop::StateUnavailable);
    }
    let message = datagram.bytes();
    let payload = &message[payload_offset..];
    let mut inner_destination = [0_u8; 16];
    match inner_family {
        GtpuSessionIpFamily::Ipv4 => inner_destination[..4].copy_from_slice(&payload[16..20]),
        GtpuSessionIpFamily::Ipv6 => {
            let Some(destination) = payload.get(24..40) else {
                return invalid;
            };
            inner_destination.copy_from_slice(destination);
        }
    }
    let mut group_key = [0_u8; GTPU_SESSION_GROUP_ID_LEN];
    group_key.copy_from_slice(&reference[..GTPU_SESSION_GROUP_ID_LEN]);
    let authority = match runtime.session_group_get(scope.ifindex, group_key) {
        Ok(Some(authority)) => authority,
        Ok(None) => return invalid,
        Err(_) => return Verdict::Drop(GtpuDownlinkDrop::StateUnavailable),
    };
    let Some(entry) = select_gtpu_session_entry_wire(
        &authority,
        reference,
        &config_wire,
        scope.ifindex,
        inner_family.slot(),
    ) else {
        return invalid;
    };
    if !entry.authorizes_downlink_key(index_key) {
        return invalid;
    }
    let provenance = datagram.provenance();
    let mut outer_peer = [0_u8; 16];
    let mut outer_local = [0_u8; 16];
    outer_peer[..4].copy_from_slice(&provenance.peer_address().octets());
    outer_local[..4].copy_from_slice(&provenance.local_address().octets());
    if !entry.authorizes_downlink_packet(
        &outer_peer,
        &outer_local,
        provenance.source_port(),
        &inner_destination,
    ) {
        return invalid;
    }
    if let Some(qfi) = entry.n3_qfi() {
        if !n3_downlink_psc_matches_message(message, payload_offset, qfi) {
            return invalid;
        }
    }
    if !inner_payload_is_exact(payload, inner_family) {
        return Verdict::Drop(GtpuDownlinkDrop::Malformed);
    }
    Verdict::Decapsulate {
        payload_offset,
        bearer_mark: entry.bearer_mark(),
        family: match inner_family {
            GtpuSessionIpFamily::Ipv4 => GtpAddressFamily::Ipv4,
            GtpuSessionIpFamily::Ipv6 => GtpAddressFamily::Ipv6,
        },
    }
}

/// tc: `authorize_and_decap_legacy_downlink`, with the commit read last.
fn authorize_legacy(
    runtime: &dyn EbpfGtpuRuntime,
    scope: DownlinkAuthorityScope,
    datagram: &GtpuControlDatagram,
    teid: [u8; 4],
    payload_offset: usize,
) -> Verdict {
    let unavailable = Verdict::Drop(GtpuDownlinkDrop::StateUnavailable);
    let invalid = Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(
        DownlinkBindingMismatch::Invalid,
    ));
    let ifindex = scope.ifindex;
    let Ok(legacy_pdr) = runtime.pdr_get(ifindex, teid) else {
        return unavailable;
    };
    let Ok(marked_pdr) = runtime.marked_pdr_get(ifindex, teid) else {
        return unavailable;
    };
    let (pdr, owner_selector) = match (legacy_pdr, marked_pdr) {
        (None, None) => {
            return match runtime.downlink_binding_get(ifindex, teid) {
                // A partially removed graph is not an unowned tunnel.
                Ok(Some(_)) => invalid,
                Ok(None) => Verdict::UnknownTunnel,
                Err(_) => unavailable,
            };
        }
        (Some(_), Some(_)) => return Verdict::Drop(GtpuDownlinkDrop::Malformed),
        (Some(value), None) => (
            MarkedDownlinkPdr {
                ue_ip: DownlinkPdr::decode(&value).ue_ip,
                bearer_mark: [0; 4],
            },
            None,
        ),
        (None, Some(value)) => {
            let pdr = MarkedDownlinkPdr::decode(&value);
            if pdr.bearer_mark == [0; 4] {
                return Verdict::Drop(GtpuDownlinkDrop::Malformed);
            }
            let selector = UplinkFarKey {
                ue_ip: pdr.ue_ip,
                bearer_mark: pdr.bearer_mark,
            }
            .encode();
            (pdr, Some(selector))
        }
    };
    let binding = match runtime.downlink_binding_get(ifindex, teid) {
        Ok(Some(binding)) => binding,
        Ok(None) => return invalid,
        Err(_) => return unavailable,
    };
    let provenance = datagram.provenance();
    if let Err(reason) = validate_ipv4_downlink_binding_wire(
        &binding,
        provenance.peer_address().octets(),
        provenance.local_address().octets(),
        provenance.ingress_ifindex(),
        provenance.source_port(),
    ) {
        return Verdict::Drop(GtpuDownlinkDrop::BindingMismatch(reason));
    }
    if let Some(selector) = owner_selector {
        let owner = match runtime.marked_owner_get(ifindex, selector) {
            Ok(Some(owner)) => owner,
            Ok(None) => return invalid,
            Err(_) => return unavailable,
        };
        if !marked_owner_wire_authorizes_downlink(&owner, teid, &binding) {
            return invalid;
        }
    }
    let far = match owner_selector {
        Some(selector) => runtime.marked_far_get(ifindex, selector),
        None => runtime.far_get(ifindex, pdr.ue_ip),
    };
    let far = match far {
        Ok(Some(far)) => UplinkFar::decode(&far),
        Ok(None) => return invalid,
        Err(_) => return unavailable,
    };
    let dscp = match owner_selector {
        Some(selector) => runtime.marked_dscp_get(ifindex, selector),
        None => runtime.dscp_get(ifindex, pdr.ue_ip),
    };
    let dscp_wire = match dscp {
        Ok(Some(value)) if value[0] > 63 => return invalid,
        Ok(Some(value)) => value[0],
        Ok(None) => 0xff,
        Err(_) => return unavailable,
    };
    // Publication fence: the one Active commit record is read last.
    let commit = match owner_selector {
        Some(selector) => runtime.marked_sport_get(ifindex, selector),
        None => runtime.sport_get(ifindex, pdr.ue_ip),
    };
    let commit = match commit {
        Ok(Some(commit)) => commit,
        Ok(None) => return invalid,
        Err(_) => return unavailable,
    };
    if pdp_commit_wire_authorized_source_port(&commit, &far, dscp_wire).is_none()
        || !pdp_commit_wire_authorizes_downlink(&commit, teid, &binding)
    {
        return invalid;
    }
    let payload = &datagram.bytes()[payload_offset..];
    if payload[0] >> 4 != 4 {
        return Verdict::Drop(GtpuDownlinkDrop::Malformed);
    }
    if payload[16..20] != pdr.ue_ip {
        return Verdict::Drop(GtpuDownlinkDrop::DestinationMismatch);
    }
    Verdict::Decapsulate {
        payload_offset,
        bearer_mark: pdr.bearer_mark,
        family: GtpAddressFamily::Ipv4,
    }
}

/// tc: `grouped_inner_payload_is_exact`.
fn inner_payload_is_exact(payload: &[u8], family: GtpuSessionIpFamily) -> bool {
    match family {
        GtpuSessionIpFamily::Ipv4 => {
            let header_len = usize::from(payload[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            payload[0] >> 4 == 4
                && header_len >= 20
                && total_len >= header_len
                && total_len == payload.len()
        }
        GtpuSessionIpFamily::Ipv6 => {
            if payload.len() < 40 || payload[0] >> 4 != 6 {
                return false;
            }
            let payload_len = u16::from_be_bytes([payload[4], payload[5]]);
            // IPv6 "No Next Header" is the only zero-length payload.
            if payload_len == 0 && payload[6] != 59 {
                return false;
            }
            40 + usize::from(payload_len) == payload.len()
        }
    }
}

/// tc: `grouped_n3_downlink_matches`, over the complete GTP-U message.
fn n3_downlink_psc_matches_message(message: &[u8], payload_offset: usize, qfi: u8) -> bool {
    if message[0] & GTPU_FLAG_EXTENSION == 0 {
        return false;
    }
    let mut cursor = GTPU_MANDATORY_HEADER_LEN + GTPU_OPTIONAL_BLOCK_LEN;
    if cursor > payload_offset {
        return false;
    }
    let mut next = message[cursor - 1];
    let mut found = false;
    let mut walked = 0;
    while next != 0 {
        if walked == GTPU_MAX_EXTENSION_HEADERS || cursor >= payload_offset {
            return false;
        }
        let units = message[cursor];
        let end = cursor + usize::from(units) * 4;
        if units == 0 || end > payload_offset {
            return false;
        }
        if next == PDU_SESSION_CONTAINER {
            let prefix = [message[cursor], message[cursor + 1], message[cursor + 2]];
            if found || !n3_downlink_psc_matches(prefix, qfi) {
                return false;
            }
            found = true;
        } else if gtpu_endpoint_requires_extension_control(next) {
            return false;
        }
        next = message[end - 1];
        cursor = end;
        walked += 1;
    }
    found && cursor == payload_offset
}
