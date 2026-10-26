//! End Marker emission uses the existing namespace effect and control queue.

use super::*;
use crate::GtpuN3EndMarkerRequest;

impl EbpfGtpuDataplaneBackend {
    pub(super) fn submit_n3_end_markers_sync(
        &self,
        request: GtpuN3EndMarkerRequest,
    ) -> Result<GtpuN3EndMarkerRequest, GtpuError> {
        // Reject the entire profile before any send, including a mixed graph.
        // No separate socket or source-port substitution can satisfy the old
        // tunnel's tuple contract.
        let targets = end_marker_targets(request.retired_group())?;
        let _operation = self.operation_guard()?;
        let context = self
            .grouped_attachment_context(request.binding().stable_device())
            .map_err(|_| state_indeterminate("ebpf_n3_end_marker_attachment"))?;
        self.validate_grouped_model_attachment(request.retired_group(), &context)
            .map_err(|_| state_indeterminate("ebpf_n3_end_marker_attachment"))?;
        let effect = self
            .inner
            .runtime
            .acquire_selector_namespace_effect(context.device.ifindex, request.binding())?;
        let validate = || self.validate_end_marker_retirement(&context, &request);
        validate()?;
        // GLOBAL is the same qualified real RCU grace used for selector reuse;
        // private/expedited memory-ordering IPIs are not substitutes. This waits
        // for prior non-sleepable classifier executions, not qdisc/NIC drain.
        self.inner.runtime.synchronize_grouped_readers()?;
        validate()?;
        for (local, peer, teid) in targets {
            validate()?;
            self.send_retired_n3_end_marker_under_guard(
                &context.device,
                local,
                peer,
                teid,
                || request.is_current(),
            )?;
        }
        validate()?;
        effect.finish()?;
        if !request.is_current() {
            return Err(state_indeterminate("ebpf_n3_end_marker_window"));
        }
        Ok(request)
    }

    fn validate_end_marker_retirement(
        &self,
        context: &GroupedAttachmentContext,
        request: &GtpuN3EndMarkerRequest,
    ) -> Result<(), GtpuError> {
        if !request.is_current() {
            return Err(state_indeterminate("ebpf_n3_end_marker_window"));
        }
        let observed = self
            .stable_grouped_observation(context, request.retired_group().id())
            .map_err(|_| state_indeterminate("ebpf_n3_end_marker_readback"))?
            .ok_or_else(|| state_indeterminate("ebpf_n3_end_marker_readback"))?;
        if observed.authority.is_some()
            || observed.transaction.is_some()
            || !observed.indexes.is_empty()
            || !observed
                .selector_stamp
                .is_some_and(|stamp| request.verifies_exact_terminal_retired_stamp(&stamp))
        {
            return Err(state_indeterminate("ebpf_n3_end_marker_retirement"));
        }
        let record =
            grouped_record_from_model(request.retired_group(), GtpuSessionGeneration::INITIAL)
                .ok_or_else(|| state_indeterminate("ebpf_n3_end_marker_graph"))?;
        let indexes = grouped_record_candidates(record)
            .ok_or_else(|| state_indeterminate("ebpf_n3_end_marker_graph"))?;
        for key in indexes.keys() {
            if self
                .grouped_index_get(context.device.ifindex, *key)?
                .is_some()
            {
                return Err(state_indeterminate("ebpf_n3_end_marker_selector_conflict"));
            }
        }
        self.ensure_grouped_attachment(context)
            .map_err(|_| state_indeterminate("ebpf_n3_end_marker_attachment"))?;
        request
            .is_current()
            .then_some(())
            .ok_or_else(|| state_indeterminate("ebpf_n3_end_marker_window"))
    }
}

fn end_marker_targets(
    group: &GtpuSessionGroup,
) -> Result<std::collections::BTreeSet<(Ipv4Addr, Ipv4Addr, crate::PeerTeid)>, GtpuError> {
    group
        .entries()
        .iter()
        .map(|entry| {
            let context = entry.context();
            let (IpAddr::V4(local), IpAddr::V4(peer)) =
                (entry.local_outer_address(), context.peer_address)
            else {
                return Err(GtpuError::UnsupportedFeature {
                    feature: "n3_end_marker_outer_ipv6",
                });
            };
            if entry.n3_qfi().is_none() {
                return Err(GtpuError::UnsupportedFeature {
                    feature: "n3_end_marker_role",
                });
            }
            if context.uplink_source_port_policy
                != crate::GtpuUplinkSourcePortPolicy::LegacyServicePort
            {
                return Err(GtpuError::UnsupportedFeature {
                    feature: "n3_end_marker_selected_source_port",
                });
            }
            Ok((local, peer, context.peer_teid))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_teid_zero_is_retained_in_n3_end_marker_targets() {
        let local = Ipv4Addr::new(192, 0, 2, 1);
        let peer = Ipv4Addr::new(192, 0, 2, 10);
        let context = crate::GtpPdpContext {
            local_teid: crate::Teid::new(7).unwrap(),
            peer_teid: crate::PeerTeid::ZERO,
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(peer),
            link_ifindex: 7,
            downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
            gtp_version: crate::GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
            downlink_inner_mtu: None,
        };
        let entry = crate::GtpuSessionEntry::new(context, IpAddr::V4(local))
            .unwrap()
            .restore_n3_qfi(0)
            .unwrap();
        let group = GtpuSessionGroup::new(
            crate::GtpuSessionGroupId::new([0x41; 16]).unwrap(),
            crate::GtpuSessionDeviceId::new([0x42; 16]).unwrap(),
            vec![entry],
        )
        .unwrap();
        let targets = end_marker_targets(&group).unwrap();
        assert_eq!(targets.len(), 1);
        let (actual_local, actual_peer, teid) = targets.into_iter().next().unwrap();
        assert_eq!((actual_local, actual_peer, teid.get()), (local, peer, 0));
    }
}
