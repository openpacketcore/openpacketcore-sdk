//! Reservations outlive observers; only verified retirement releases a key.

use super::ScopedXfrmRequest;
use crate::XfrmError;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationRole {
    /// A request that owns its complete flow identity.
    Primary,
    /// A rekey successor that shares one live primary's policy identity.
    Successor,
}

#[derive(Clone)]
pub(crate) struct Reservation {
    pub(super) request: Arc<ScopedXfrmRequest>,
    identity: Arc<()>,
    role: ReservationRole,
    predecessor: Option<Arc<()>>,
}
impl Reservation {
    #[cfg(test)]
    pub(super) const fn is_successor(&self) -> bool {
        matches!(self.role, ReservationRole::Successor)
    }
}
#[derive(Default)]
pub(crate) struct Registry {
    entries: Vec<Reservation>,
}
impl Registry {
    pub(crate) fn reserve(
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
            role: ReservationRole::Primary,
            predecessor: None,
        };
        self.entries.push(receipt.clone());
        Ok(receipt)
    }

    /// Admit one rekey successor beside a live primary reservation.
    ///
    /// The successor keeps the predecessor's policy lookup identity; only its
    /// SA SPI and request ID differ. Exactly one successor may exist for a
    /// primary, and the successor's SA deletion key must still be unused. An
    /// unrelated request on the live policy key remains refused by
    /// [`Self::reserve`].
    /// # Errors
    /// `local_scope_successor_flow`/`local_scope_successor_identity` for an
    /// invalid successor; [`XfrmError::AlreadyExists`] for a second successor
    /// or an SA deletion-key collision; `local_scope_successor_chain` when the
    /// supplied predecessor is itself a successor.
    pub(crate) fn reserve_successor(
        &mut self,
        predecessor: &Reservation,
        request: Arc<ScopedXfrmRequest>,
    ) -> Result<Reservation, XfrmError> {
        let Some(primary) = self
            .entries
            .iter()
            .find(|entry| Arc::ptr_eq(&entry.identity, &predecessor.identity))
        else {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor",
            });
        };
        if primary.role != ReservationRole::Primary {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_chain",
            });
        }
        request.validate_successor_of(&primary.request)?;
        if self.successor_of(predecessor).is_some() {
            return Err(XfrmError::AlreadyExists);
        }
        // The successor's SA deletion key is distinct from every live SA key,
        // but still checked so a caller cannot alias an unrelated receipt.
        if self.entries.iter().any(|entry| {
            entry.request.sa.id == request.sa.id && entry.request.sa.mark == request.sa.mark
        }) {
            return Err(XfrmError::AlreadyExists);
        }
        let receipt = Reservation {
            request,
            identity: Arc::new(()),
            role: ReservationRole::Successor,
            predecessor: Some(Arc::clone(&primary.identity)),
        };
        self.entries.push(receipt.clone());
        Ok(receipt)
    }

    /// The live successor admitted for `predecessor`, when one exists.
    pub(crate) fn successor_of(&self, predecessor: &Reservation) -> Option<&Reservation> {
        self.entries.iter().find(|entry| {
            entry.role == ReservationRole::Successor
                && entry
                    .predecessor
                    .as_ref()
                    .is_some_and(|identity| Arc::ptr_eq(identity, &predecessor.identity))
        })
    }

    /// Retire a primary whose policy identity a published successor now owns.
    ///
    /// Refuses while no successor exists: dropping the primary first would
    /// release the only reservation for a still-installed protective policy.
    pub(crate) fn retire_predecessor(
        &mut self,
        predecessor: &Reservation,
    ) -> Result<(), XfrmError> {
        if self.successor_of(predecessor).is_none() {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_not_live",
            });
        }
        self.retired(predecessor)
    }

    /// Refuse releasing a successor while its predecessor is still reserved.
    pub(crate) fn check_successor_release(&self, successor: &Reservation) -> Result<(), XfrmError> {
        let Some(predecessor) = successor.predecessor.as_ref() else {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor",
            });
        };
        if self
            .entries
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.identity, predecessor))
        {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor_live",
            });
        }
        Ok(())
    }

    pub(crate) fn contains(&self, receipt: &Reservation) -> bool {
        self.entries
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.identity, &receipt.identity))
    }
    pub(crate) fn retired(&mut self, receipt: &Reservation) -> Result<(), XfrmError> {
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

    fn successor_request_for(predecessor: &ScopedXfrmRequest) -> Arc<ScopedXfrmRequest> {
        let mut sa = predecessor.sa.clone();
        sa.id.spi = sa.id.spi.checked_add(1).unwrap();
        sa.request_id = Some(crate::XfrmRequestId::new(100).unwrap());
        let mut policy = predecessor.policy.clone();
        policy.templates[0].request_id = sa.request_id;
        Arc::new(ScopedXfrmRequest::new(sa, policy).unwrap())
    }

    #[test]
    fn successor_reservation_shares_the_flow_but_keeps_unrelated_requests_refused() {
        let predecessor_request = request(1);
        let mut registry = Registry::default();
        let predecessor = registry.reserve(predecessor_request.clone()).unwrap();
        let successor = registry
            .reserve_successor(&predecessor, successor_request_for(&predecessor_request))
            .unwrap();
        assert!(successor.is_successor());
        assert!(registry.successor_of(&predecessor).is_some());

        // Exactly one successor: a second one is refused.
        assert!(registry
            .reserve_successor(&predecessor, successor_request_for(&predecessor_request))
            .is_err());
        // The existing refusal of an unrelated request on the live policy key stays.
        assert!(registry.reserve(predecessor_request.clone()).is_err());
        // A successor cannot itself be succeeded while its predecessor is live.
        assert!(matches!(
            registry.reserve_successor(&successor, successor_request_for(&predecessor_request)),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_chain"
            })
        ));
        // A successor SA deletion key cannot alias another live SA.
        let mut alias = (*successor_request_for(&predecessor_request)).clone();
        alias.sa.id.spi = predecessor_request.sa.id.spi.checked_add(2).unwrap();
        alias.sa.request_id = Some(crate::XfrmRequestId::new(101).unwrap());
        alias.policy.templates[0].request_id = alias.sa.request_id;
        assert!(registry
            .reserve_successor(&predecessor, Arc::new(alias))
            .is_err());
    }

    #[test]
    fn retirement_order_is_exact_and_never_releases_the_only_policy_reservation() {
        let predecessor_request = request(1);
        let mut registry = Registry::default();
        let predecessor = registry.reserve(predecessor_request.clone()).unwrap();
        // A predecessor cannot be retired into a policy identity with no owner.
        assert!(matches!(
            registry.retire_predecessor(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_not_live"
            })
        ));
        let successor = registry
            .reserve_successor(&predecessor, successor_request_for(&predecessor_request))
            .unwrap();
        // The successor cannot be released while the predecessor is live.
        assert!(matches!(
            registry.check_successor_release(&successor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor_live"
            })
        ));
        registry.retire_predecessor(&predecessor).unwrap();
        assert!(!registry.contains(&predecessor));
        assert!(registry.contains(&successor));
        registry.check_successor_release(&successor).unwrap();
        registry.retired(&successor).unwrap();
        assert!(!registry.contains(&successor));
    }
    #[test]
    fn successor_reservations_support_repeated_generations_before_and_after_retirement() {
        for retire_first in [false, true] {
            let mut registry = Registry::default();
            let first = registry.reserve(request(1)).unwrap();
            let second = registry
                .reserve_successor(&first, successor_request_for(&first.request))
                .unwrap();
            if retire_first {
                registry.retire_predecessor(&first).unwrap();
            }
            let mut third = (*successor_request_for(&second.request)).clone();
            third.sa.request_id = crate::XfrmRequestId::new(101);
            third.policy.templates[0].request_id = third.sa.request_id;
            let third = registry
                .reserve_successor(&second, Arc::new(third))
                .unwrap();
            assert!(registry.contains(&second));
            assert!(registry.contains(&third));
            assert!(registry.reserve(third.request.clone()).is_err());
        }
    }

    #[test]
    fn successor_reservation_excludes_other_flows_that_select_the_same_reqid() {
        for successor_first in [false, true] {
            let mut registry = Registry::default();
            let first = registry.reserve(request(1)).unwrap();
            let next = successor_request_for(&first.request);
            let mut foreign = (*next).clone();
            foreign.sa.id.spi += 1;
            foreign.sa.selector.protocol = 17;
            foreign.policy.selector = foreign.sa.selector.clone();
            let foreign = Arc::new(ScopedXfrmRequest::new(foreign.sa, foreign.policy).unwrap());
            if successor_first {
                let next = registry.reserve_successor(&first, next).unwrap();
                assert!(matches!(
                    registry.reserve(foreign),
                    Err(XfrmError::AlreadyExists)
                ));
                assert!(registry.contains(&next));
            } else {
                let foreign = registry.reserve(foreign).unwrap();
                assert!(matches!(
                    registry.reserve_successor(&first, next),
                    Err(XfrmError::AlreadyExists)
                ));
                assert!(registry.contains(&foreign));
            }
            assert!(registry.contains(&first));
        }
    }
}
