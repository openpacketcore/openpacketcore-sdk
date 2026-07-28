use std::collections::BTreeMap;

use opc_egress_fence_common::{
    decide_egress, FenceAuthoritySnapshot, FenceEntryState, PacketEndpointDisposition,
    PacketFenceContext, EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
};
pub(crate) use opc_egress_fence_common::{FenceEntry, FenceMark, FenceVerdict, ProtectedEndpoint};

#[derive(Clone, Copy)]
pub(crate) struct DatapathPacket {
    mark: u32,
    socket_cookie: u64,
    source: PacketSource,
}

#[derive(Clone, Copy)]
enum PacketSource {
    Ipv4 { address: [u8; 4], port: u16 },
}

impl DatapathPacket {
    pub(crate) const fn marked_udp(
        mark: u32,
        socket_cookie: u64,
        address: [u8; 4],
        port: u16,
    ) -> Self {
        Self {
            mark,
            socket_cookie,
            source: PacketSource::Ipv4 { address, port },
        }
    }

    pub(crate) const fn unmarked_udp(socket_cookie: u64, address: [u8; 4], port: u16) -> Self {
        Self::marked_udp(0, socket_cookie, address, port)
    }

    const fn disposition(self, endpoint: ProtectedEndpoint) -> PacketEndpointDisposition {
        match self.source {
            PacketSource::Ipv4 { address, port } if endpoint.matches_ipv4(address, port) => {
                PacketEndpointDisposition::Protected
            }
            PacketSource::Ipv4 { .. } => PacketEndpointDisposition::Unrelated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModelError {
    Capacity,
    DeadlineElapsed,
    ClosedActivation,
    TerminalActivation,
    EpochMismatch,
    EpochExhausted,
    StaleDurableFence,
    ZeroDurableFence,
    UnknownCookie,
}

pub(crate) struct EgressFenceModel {
    endpoint: ProtectedEndpoint,
    mark: FenceMark,
    capacity: usize,
    current_durable_fence_token: u64,
    entries: BTreeMap<u64, FenceEntry>,
    attachment_identity_valid: bool,
}

impl EgressFenceModel {
    pub(crate) fn new(endpoint: ProtectedEndpoint, mark: FenceMark, capacity: usize) -> Self {
        Self {
            endpoint,
            mark,
            capacity,
            current_durable_fence_token: 0,
            entries: BTreeMap::new(),
            attachment_identity_valid: true,
        }
    }

    pub(crate) fn register_closed(&mut self, cookie: u64) -> Result<(), ModelError> {
        if !self.entries.contains_key(&cookie) && self.entries.len() >= self.capacity {
            return Err(ModelError::Capacity);
        }
        self.entries.insert(cookie, FenceEntry::initial_closed());
        Ok(())
    }

    pub(crate) fn publish_token(&mut self, durable_fence_token: u64) -> Result<(), ModelError> {
        if durable_fence_token == 0 {
            return Err(ModelError::ZeroDurableFence);
        }
        if durable_fence_token < self.current_durable_fence_token {
            return Err(ModelError::StaleDurableFence);
        }
        self.current_durable_fence_token = durable_fence_token;
        Ok(())
    }

    pub(crate) fn activate(
        &mut self,
        cookie: u64,
        durable_fence_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
        now_boot_ns: u64,
    ) -> Result<(), ModelError> {
        let current_entry = self
            .entries
            .get(&cookie)
            .copied()
            .ok_or(ModelError::UnknownCookie)?;
        if current_entry.control_epoch() != expected_epoch {
            return Err(ModelError::EpochMismatch);
        }
        match current_entry.state() {
            FenceEntryState::InitialClosed | FenceEntryState::Active => {}
            FenceEntryState::TerminalClosed => return Err(ModelError::TerminalActivation),
        }
        if durable_fence_token == 0 || deadline_boot_ns == 0 {
            return Err(ModelError::ClosedActivation);
        }
        if now_boot_ns >= deadline_boot_ns {
            return Err(ModelError::DeadlineElapsed);
        }
        if durable_fence_token != self.current_durable_fence_token {
            return Err(ModelError::StaleDurableFence);
        }
        let next_epoch = expected_epoch
            .checked_add(1)
            .ok_or(ModelError::EpochExhausted)?;
        let next_entry = FenceEntry::active(durable_fence_token, deadline_boot_ns, next_epoch)
            .ok_or(ModelError::ClosedActivation)?;
        self.entries.insert(cookie, next_entry);
        Ok(())
    }

    pub(crate) fn close(&mut self, cookie: u64) -> Result<(), ModelError> {
        let current = self
            .entries
            .get(&cookie)
            .copied()
            .ok_or(ModelError::UnknownCookie)?;
        let next_epoch = current
            .control_epoch()
            .checked_add(1)
            .ok_or(ModelError::EpochExhausted)?;
        let terminal = FenceEntry::terminal_closed(current.durable_fence_token(), next_epoch)
            .ok_or(ModelError::EpochExhausted)?;
        self.entries.insert(cookie, terminal);
        Ok(())
    }

    pub(crate) fn cleanup_reclaimable(&mut self, now_boot_ns: u64) -> usize {
        let current = self.current_durable_fence_token;
        let before = self.entries.len();
        self.entries.retain(|_, entry| match entry.state() {
            FenceEntryState::Active => {
                entry.durable_fence_token() == current && now_boot_ns < entry.deadline_boot_ns()
            }
            FenceEntryState::TerminalClosed => entry.durable_fence_token() == current,
            FenceEntryState::InitialClosed => false,
        });
        before.saturating_sub(self.entries.len())
    }

    pub(crate) fn set_attachment_identity_valid(&mut self, valid: bool) {
        self.attachment_identity_valid = valid;
    }

    pub(crate) fn verdict(&self, packet: &DatapathPacket, now_boot_ns: u64) -> FenceVerdict {
        decide_egress(
            PacketFenceContext::new(
                self.attachment_identity_valid,
                packet.disposition(self.endpoint),
                self.mark,
                packet.mark,
                packet.socket_cookie,
            ),
            FenceAuthoritySnapshot::new(
                self.entries.get(&packet.socket_cookie).copied(),
                self.current_durable_fence_token,
                now_boot_ns,
            ),
        )
    }

    #[cfg(test)]
    pub(crate) fn current_durable_fence_token(&self) -> u64 {
        self.current_durable_fence_token
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn entry(&self, cookie: u64) -> Option<FenceEntry> {
        self.entries.get(&cookie).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_COOKIE: u64 = 11;
    const NEW_COOKIE: u64 = 12;
    const MARK_BIT: u32 = 1 << 17;

    fn endpoint() -> ProtectedEndpoint {
        ProtectedEndpoint::ipv4([192, 0, 2, 20], 2123)
            .expect("documentation endpoint is a usable fixture")
    }

    fn packet(cookie: u64) -> DatapathPacket {
        DatapathPacket::marked_udp(MARK_BIT | 7, cookie, [192, 0, 2, 20], 2123)
    }

    fn model() -> EgressFenceModel {
        EgressFenceModel::new(
            endpoint(),
            FenceMark::new(MARK_BIT).expect("single-bit fixture"),
            4,
        )
    }

    #[test]
    fn higher_successor_token_immediately_stales_old_cookie() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.publish_token(8).expect("old publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("old activation");
        model.register_closed(NEW_COOKIE).expect("new registration");
        model.publish_token(9).expect("successor publication");
        model
            .activate(NEW_COOKIE, 9, 200, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 2)
            .expect("new activation");

        assert_eq!(
            model.verdict(&packet(OLD_COOKIE), 3),
            FenceVerdict::DropStaleToken
        );
        assert_eq!(model.verdict(&packet(NEW_COOKIE), 3), FenceVerdict::Allow);
    }

    #[test]
    fn delayed_old_token_cannot_regress_monotonic_current_fence() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.register_closed(NEW_COOKIE).expect("new registration");
        model.publish_token(9).expect("successor publication");
        model
            .activate(NEW_COOKIE, 9, 200, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 2)
            .expect("new activation");

        assert_eq!(
            model.activate(OLD_COOKIE, 8, 300, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 3),
            Err(ModelError::StaleDurableFence)
        );
        assert_eq!(model.current_durable_fence_token(), 9);
        assert_eq!(model.verdict(&packet(NEW_COOKIE), 4), FenceVerdict::Allow);
    }

    #[test]
    fn cleanup_removes_only_superseded_tokens_and_never_active_current() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.publish_token(8).expect("old publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("old activation");
        model.register_closed(NEW_COOKIE).expect("new registration");
        model.publish_token(9).expect("successor publication");
        model
            .activate(NEW_COOKIE, 9, 200, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 2)
            .expect("new activation");

        assert_eq!(model.cleanup_reclaimable(3), 1);
        assert_eq!(model.entry_count(), 1);
        assert_eq!(model.verdict(&packet(NEW_COOKIE), 3), FenceVerdict::Allow);
    }

    #[test]
    fn cleanup_reclaims_closed_and_expired_current_without_evicting_live_current() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.register_closed(NEW_COOKIE).expect("new registration");
        model.publish_token(8).expect("publication");
        model
            .activate(OLD_COOKIE, 8, 10, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("old activation");
        model
            .activate(NEW_COOKIE, 8, 20, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("new activation");

        assert_eq!(model.cleanup_reclaimable(10), 1);
        assert_eq!(model.entry_count(), 1);
        assert_eq!(model.verdict(&packet(NEW_COOKIE), 11), FenceVerdict::Allow);
    }

    #[test]
    fn explicit_close_immediately_blocks_a_live_cookie() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("registration");
        model.publish_token(8).expect("publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("activation");
        model.close(OLD_COOKIE).expect("close");

        assert_eq!(
            model.verdict(&packet(OLD_COOKIE), 2),
            FenceVerdict::DropClosed
        );
    }

    #[test]
    fn invalid_attachment_identity_drops_even_unrelated_unmarked_packet() {
        let mut model = model();
        model.set_attachment_identity_valid(false);
        let unrelated = DatapathPacket::unmarked_udp(99, [198, 51, 100, 40], 9999);

        assert_eq!(model.verdict(&unrelated, 1), FenceVerdict::DropMalformed);
    }

    #[test]
    fn mark_mask_preserves_unowned_routing_bits() {
        let marked = MARK_BIT | !MARK_BIT;
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("registration");
        model.publish_token(8).expect("publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("activation");
        let packet = DatapathPacket::marked_udp(marked, OLD_COOKIE, [192, 0, 2, 20], 2123);

        assert_eq!(model.verdict(&packet, 2), FenceVerdict::Allow);
    }

    #[test]
    fn delayed_same_token_refresh_cannot_reopen_after_terminal_close() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("registration");
        model.publish_token(8).expect("publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("activation");
        let active_epoch = model
            .entry(OLD_COOKIE)
            .expect("active entry")
            .control_epoch();
        model.close(OLD_COOKIE).expect("terminal close");

        assert_eq!(
            model.activate(OLD_COOKIE, 8, 200, active_epoch, 2),
            Err(ModelError::EpochMismatch)
        );
        assert!(model.entry(OLD_COOKIE).expect("tombstone").is_terminal());
        assert_eq!(
            model.verdict(&packet(OLD_COOKIE), 3),
            FenceVerdict::DropClosed
        );
    }

    #[test]
    fn cleanup_retains_current_terminal_tombstone_until_token_advances() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.publish_token(8).expect("old publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("old activation");
        model.close(OLD_COOKIE).expect("terminal close");

        assert_eq!(model.cleanup_reclaimable(2), 0);
        assert!(model.entry(OLD_COOKIE).expect("retained").is_terminal());

        model.register_closed(NEW_COOKIE).expect("new registration");
        model.publish_token(9).expect("successor publication");
        model
            .activate(NEW_COOKIE, 9, 200, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 3)
            .expect("successor activation");
        assert_eq!(model.cleanup_reclaimable(4), 1);
        assert!(model.entry(OLD_COOKIE).is_none());
    }

    #[test]
    fn publication_is_separate_monotonic_and_crash_before_activation_is_closed() {
        let mut model = model();
        model.register_closed(OLD_COOKIE).expect("old registration");
        model.publish_token(8).expect("old publication");
        model
            .activate(OLD_COOKIE, 8, 100, EGRESS_FENCE_INITIAL_COOKIE_EPOCH, 1)
            .expect("old activation");
        model.register_closed(NEW_COOKIE).expect("new registration");

        model.publish_token(9).expect("successor publication");

        assert_eq!(
            model.verdict(&packet(OLD_COOKIE), 2),
            FenceVerdict::DropStaleToken
        );
        assert_eq!(
            model.verdict(&packet(NEW_COOKIE), 2),
            FenceVerdict::DropClosed
        );
        assert_eq!(model.publish_token(8), Err(ModelError::StaleDurableFence));
        assert_eq!(model.current_durable_fence_token(), 9);
    }
}
