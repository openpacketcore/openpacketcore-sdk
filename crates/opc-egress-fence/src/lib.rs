//! Lease-bound kernel egress fencing for datagram sockets.
//!
//! A Linux root-cgroup eBPF gate authorizes datagrams only while the exact
//! socket cookie is bound to a live durable store lease. The userspace lifecycle
//! captures suspend-aware time before each lease operation, derives a
//! conservative kernel deadline from that start, and terminal-closes on every
//! failure or cancellation path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod guardian;
#[cfg(target_os = "linux")]
mod install_manifest;
mod lifecycle;
#[cfg(target_os = "linux")]
mod root_cgroup;
#[cfg(target_os = "linux")]
mod root_inventory;
mod socket;

pub use guardian::{
    fenced_udp_channels, run_fenced_udp_guardian, FencedUdpChannels, FencedUdpGuardianError,
    FencedUdpGuardianPorts, FencedUdpInboundDatagram, FencedUdpSender, GuardianOperationalError,
};
pub use lifecycle::{
    DurablePriorFenceState, EgressFenceLeaseAuthority, FenceAttachmentIdentity, FenceError,
    FenceLeaseGrant, LeaseFenceError, LeaseFenceTiming, TerminalClosureEvidence,
};
#[cfg(target_os = "linux")]
pub use root_cgroup::HostCgroupV2Root;
pub use socket::{FencedUdpSocket, RetireFenceError};

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod model;

#[cfg(test)]
mod tests {
    use super::model::{
        DatapathPacket, EgressFenceModel, FenceMark, FenceVerdict, ProtectedEndpoint,
    };

    const COOKIE: u64 = 0x0102_0304_0506_0708;
    const TOKEN: u64 = 7;
    const DEADLINE_NS: u64 = 9_000_000_000;
    const MARK_BIT: u32 = 1 << 17;

    fn endpoint() -> ProtectedEndpoint {
        ProtectedEndpoint::ipv4([192, 0, 2, 10], 2123)
            .expect("documentation endpoint is a usable fixture")
    }

    fn model() -> EgressFenceModel {
        EgressFenceModel::new(
            endpoint(),
            FenceMark::new(MARK_BIT).expect("single-bit fixture"),
            4,
        )
    }

    #[test]
    fn marked_missing_cookie_drops_instead_of_bypassing_the_fence() {
        let model = model();
        let packet = DatapathPacket::marked_udp(MARK_BIT, COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(model.verdict(&packet, 1), FenceVerdict::DropMissing);
    }

    #[test]
    fn protected_endpoint_without_mark_drops() {
        let model = model();
        let packet = DatapathPacket::unmarked_udp(COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(model.verdict(&packet, 1), FenceVerdict::DropUnmarked);
    }

    #[test]
    fn delayed_stale_activation_cannot_reopen_after_its_operation_deadline() {
        let mut model = model();
        model
            .register_closed(COOKIE)
            .expect("fixture registration is within capacity");
        model
            .publish_token(TOKEN)
            .expect("fixture token publication");
        model
            .activate(
                COOKIE,
                TOKEN,
                DEADLINE_NS,
                opc_egress_fence_common::EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
                DEADLINE_NS + 1,
            )
            .expect_err("post-deadline activation must fail closed");
        let packet = DatapathPacket::marked_udp(MARK_BIT, COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(
            model.verdict(&packet, DEADLINE_NS + 1),
            FenceVerdict::DropClosed
        );
    }
}
