//! Lease-bound kernel egress fencing for datagram sockets.
//!
//! The deterministic contract tests are written before the implementation so
//! the SDK gap has an executable RED detector.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
mod model;

#[cfg(test)]
mod tests {
    use super::model::{
        DatapathPacket, EgressFenceModel, FenceVerdict, ProtectedEndpoint, EGRESS_FENCE_MARK_VALUE,
    };

    const COOKIE: u64 = 0x0102_0304_0506_0708;
    const TOKEN: u64 = 7;
    const DEADLINE_NS: u64 = 9_000_000_000;

    fn endpoint() -> ProtectedEndpoint {
        ProtectedEndpoint::ipv4([192, 0, 2, 10], 2123)
            .expect("documentation endpoint is a usable fixture")
    }

    #[test]
    fn marked_missing_cookie_drops_instead_of_bypassing_the_fence() {
        let model = EgressFenceModel::new(endpoint(), 4);
        let packet =
            DatapathPacket::marked_udp(EGRESS_FENCE_MARK_VALUE, COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(model.verdict(&packet, 1), FenceVerdict::DropMissing);
    }

    #[test]
    fn protected_endpoint_without_mark_drops() {
        let model = EgressFenceModel::new(endpoint(), 4);
        let packet = DatapathPacket::unmarked_udp(COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(model.verdict(&packet, 1), FenceVerdict::DropUnmarked);
    }

    #[test]
    fn delayed_stale_activation_cannot_reopen_after_its_operation_deadline() {
        let mut model = EgressFenceModel::new(endpoint(), 4);
        model
            .register_closed(COOKIE)
            .expect("fixture registration is within capacity");
        model
            .activate(
                COOKIE,
                TOKEN,
                DEADLINE_NS,
                opc_egress_fence_common::EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
                DEADLINE_NS + 1,
            )
            .expect_err("post-deadline activation must fail closed");
        let packet =
            DatapathPacket::marked_udp(EGRESS_FENCE_MARK_VALUE, COOKIE, [192, 0, 2, 10], 2123);

        assert_eq!(
            model.verdict(&packet, DEADLINE_NS + 1),
            FenceVerdict::DropClosed
        );
    }
}
