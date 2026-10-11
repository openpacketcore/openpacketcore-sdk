//! Reservations outlive observers; only verified retirement releases a key.

use super::ScopedXfrmRequest;
use crate::XfrmError;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Reservation {
    pub(super) request: Arc<ScopedXfrmRequest>,
    identity: Arc<()>,
}
#[derive(Default)]
pub(super) struct Registry {
    entries: Vec<Reservation>,
}
impl Registry {
    pub(super) fn reserve(
        &mut self,
        request: Arc<ScopedXfrmRequest>,
    ) -> Result<Reservation, XfrmError> {
        if self
            .entries
            .iter()
            .any(|entry| conflicts(&entry.request, &request))
        {
            return Err(XfrmError::AlreadyExists);
        }
        let receipt = Reservation {
            request,
            identity: Arc::new(()),
        };
        self.entries.push(receipt.clone());
        Ok(receipt)
    }
    pub(super) fn contains(&self, receipt: &Reservation) -> bool {
        self.entries
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.identity, &receipt.identity))
    }
    pub(super) fn retired(&mut self, receipt: &Reservation) -> Result<(), XfrmError> {
        let index = self
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.identity, &receipt.identity))
            .ok_or(XfrmError::StateMismatch {
                operation: "local_scope_receipt",
            })?;
        self.entries.remove(index);
        Ok(())
    }
}
fn conflicts(first: &ScopedXfrmRequest, second: &ScopedXfrmRequest) -> bool {
    // Both requests have full, nonzero marks. Interface and child identifiers
    // cannot separate an SA lookup; expiration cannot release this reservation.
    (first.sa.id == second.sa.id && first.sa.mark == second.sa.mark)
        || (first.policy.selector == second.policy.selector
            && first.policy.direction == second.policy.direction
            && first.policy.mark == second.policy.mark
            && first.policy.if_id == second.policy.if_id)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_scope::request::fixture;
    fn request(if_id: u32) -> Arc<ScopedXfrmRequest> {
        let (mut sa, mut policy) = fixture();
        sa.if_id = Some(if_id);
        policy.if_id = Some(if_id);
        Arc::new(ScopedXfrmRequest::new(sa, policy).unwrap())
    }
    #[test]
    fn unresolved_kernel_key_excludes_different_interface_and_dropped_observer() {
        let mut registry = Registry::default();
        let owned = registry.reserve(request(1)).unwrap();
        let observer = owned.clone();
        drop(observer);
        assert!(
            registry.reserve(request(2)).is_err(),
            "if_id and child identity are absent from Linux SA deletion lookup"
        );
        assert!(registry.contains(&owned));
        registry.retired(&owned).unwrap();
        registry.reserve(request(2)).unwrap();
    }
    #[test]
    fn policy_deletion_key_also_excludes_a_different_spi() {
        let mut registry = Registry::default();
        registry.reserve(request(1)).unwrap();
        let (mut sa, mut policy) = fixture();
        sa.id.spi += 1;
        sa.if_id = Some(1);
        policy.if_id = Some(1);
        let candidate = Arc::new(ScopedXfrmRequest::new(sa, policy).unwrap());
        assert!(
            registry.reserve(candidate).is_err(),
            "a different SA does not own its predecessor policy selector"
        );
    }
    #[test]
    fn transplanted_or_retired_receipt_never_releases_another_registry_entry() {
        let mut first = Registry::default();
        let mut second = Registry::default();
        let own = first.reserve(request(1)).unwrap();
        let foreign = second.reserve(request(1)).unwrap();
        assert!(first.retired(&foreign).is_err());
        assert!(first.contains(&own));
        first.retired(&own).unwrap();
        let next = first.reserve(request(1)).unwrap();
        assert!(first.retired(&own).is_err());
        assert!(first.contains(&next));
    }
}
