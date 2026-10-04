//! Safe XFRM backend trait.

use async_trait::async_trait;

use crate::model::{
    validate_exact_remove_policy_request, validate_exact_remove_sa_request, AllocateSpiRequest,
    ExactRemovePolicyRequest, ExactRemoveSaRequest, InstallPolicyRequest, InstallSaRequest,
    PolicyParameters, QueryPolicyRequest, QuerySaRequest, RekeyPolicyRequest, RekeySaRequest,
    RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest, SaKeySnapshot, SaLookupKey,
    SaRelocationIdentity, SaState, SpiAllocation, XfrmCapability, XfrmProbe,
};
use crate::XfrmError;

/// Backend that can mutate Linux XFRM IPsec state.
///
/// Implementations are async because real adapters may perform blocking netlink
/// I/O or privilege checks, and the SDK's callers are async. The mock and
/// unsupported adapters keep operations cheap and deterministic.
#[async_trait]
pub trait XfrmBackend: Send + Sync + std::fmt::Debug {
    /// Report support for the optional authenticated complete-roster profile.
    /// Raw, mock and custom adapters default to Missing. Available still
    /// requires a valid bounded intent and a bound durable namespace actor.
    #[cfg(all(unix, feature = "ikev2"))]
    async fn child_sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        Ok(XfrmCapability::Missing)
    }

    /// Acquire an affine ticket for installed Child-SA roster publication.
    ///
    /// Only a namespace-bound actor with whole-roster readback and writer
    /// fencing implements this optional profile. Raw Linux, mock and custom
    /// backends fail closed by default. Install/adopt resources before this call.
    async fn begin_child_sa_roster_update(&self) -> Result<crate::ChildSaRosterUpdate, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Consume a current ticket, read back every declared SA/policy and publish
    /// one key-free generation. A failed readback retires the predecessor.
    ///
    /// The actor continues an admitted call after caller cancellation. Lost
    /// replies require a fresh ticket and full readback; they do not authorize
    /// use of an older generation. This call makes no kernel mutations and
    /// grants no packet-provenance or endpoint-migration authority.
    async fn publish_child_sa_roster(
        &self,
        _update: crate::ChildSaRosterUpdate,
        _request: crate::ChildSaInstalledRosterRequest,
    ) -> Result<crate::InstalledChildSaRoster, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Select an exact outbound pair after fresh whole-roster readback.
    ///
    /// Caller classification chooses a class or the explicit default. This is
    /// a point-in-time observation under namespace writer exclusion, not a
    /// lock across later packet sends. Any admitted actor mutation invalidates
    /// the publication, even if that mutation later fails or is indeterminate.
    async fn select_installed_child_sa(
        &self,
        _roster: &crate::InstalledChildSaRoster,
        _selection: crate::child_sa::ChildSaOutboundSelection,
    ) -> Result<crate::InstalledChildSaSelection, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Allocate an SPI for an inbound SA.
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError>;

    /// Install a new Security Association.
    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError>;

    /// Query an existing Security Association.
    async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError>;

    /// Query one exactly identified Security Policy.
    ///
    /// This is the policy counterpart of [`Self::query_sa`]: an observation
    /// authority that reports the current kernel parameters of the exact
    /// selector/direction/mark/interface identity, or [`XfrmError::NotFound`]
    /// when no such policy exists. It never authorizes a mutation. Backends
    /// without an exact single-policy readback fail closed with
    /// [`XfrmError::UnsupportedFeature`].
    async fn query_policy(
        &self,
        _request: QueryPolicyRequest,
    ) -> Result<PolicyParameters, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "exact_policy_query",
        })
    }

    /// Query the exact current-state snapshot needed to authorize one SA
    /// relocation.
    ///
    /// This is separate from [`Self::query_sa`] so the established public
    /// `SaState` shape remains source compatible. Backends that cannot prove
    /// the complete raw selector, lookup mark, zero-original-address NAT-T
    /// template, and interface identifier fail closed.
    async fn query_sa_relocation_identity(
        &self,
        _request: QuerySaRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_relocation",
        })
    }

    /// Read every SA state at one lookup key, whatever its lookup mark.
    ///
    /// Linux GETSA, DELSA, UPDSA, and MIGRATE_STATE all select their state
    /// with `__xfrm_state_lookup`: the first state in an SPI hash chain whose
    /// stored mark satisfies `(lookup & mask) == value`. An unmarked state
    /// satisfies every lookup, new states go to the chain head, and a hash
    /// resize can reverse the chain. When two states at one key match a
    /// lookup, no point query can prove which one the next lookup selects.
    /// This read does not depend on chain order. Apply the predicate with
    /// [`SaKeySnapshot::lookup_candidates`].
    ///
    /// # Completeness contract
    ///
    /// - The caller excludes every other userspace SA writer in the network
    ///   namespace, at any key, for the duration of the read.
    /// - Kernel ACQUIRE activity is detected and makes the read
    ///   indeterminate.
    ///
    /// Under this contract, a returned snapshot holds exactly the states that
    /// were at the key when the read began. Any of them may have expired
    /// since.
    ///
    /// A finished Linux dump is not proof of a complete one: Linux ends a
    /// state dump with a successful `NLMSG_DONE` after silently dropping a
    /// state too large for a dump batch, together with every older state. The
    /// Linux backend therefore dumps every state in the namespace and accepts
    /// the dump only when it returned as many states as the kernel's SAD count
    /// read just before and just after it. A state that the dump returned but
    /// that was inserted after the first count could stand in for a dropped
    /// one. Another userspace writer could insert one, which the first clause
    /// excludes. Linux itself inserts one kind of state: the larval state of
    /// an ACQUIRE, when outbound traffic matches a policy template that no SA
    /// satisfies while a key manager listens. The backend classifies every
    /// dumped state, and a larval state, or one it cannot classify, makes the
    /// read indeterminate. A larval state that Linux inserts after the dump
    /// starts is never returned, so it cannot stand in. SPI allocation also
    /// leaves a larval state until its SA is installed or the allocation
    /// expires, so a pending allocation anywhere in the namespace makes the
    /// read indeterminate too.
    ///
    /// This is a read and changes no kernel state. Through the namespace
    /// actor a lost reply is `Unavailable`, as for other reads. Backends
    /// without a complete key read fail closed with
    /// [`XfrmError::UnsupportedFeature`].
    ///
    /// # Errors
    ///
    /// [`XfrmError::InvalidConfig`] for a zero SPI or a protocol other than
    /// AH, ESP, or IPComp. A Linux read whose dump the kernel flags as
    /// interrupted, whose state count disagrees with the SAD count, or whose
    /// dump holds a larval or unclassifiable state is repeated a bounded
    /// number of times, then reported as [`XfrmError::StateIndeterminate`]. A
    /// state at the key that the SDK cannot represent, such as one with an
    /// unaddressable lookup mark, fails the read instead of being left out.
    async fn query_sa_key_snapshot(&self, _key: SaLookupKey) -> Result<SaKeySnapshot, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_key_snapshot",
        })
    }

    /// Rekey (update) an existing Security Association.
    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError>;

    /// Relocate one exactly identified SA's outer endpoints and optionally
    /// preserve, set, or remove its NAT-T encapsulation.
    ///
    /// Outgoing callers must install the upstream-required block policy before
    /// selecting `OutboundBlockPolicyInstalled` and retain it until the
    /// replacement allow policy is active. Incoming relocation does not need
    /// that block. See [`crate::SaRelocationDirection`].
    ///
    /// Backends without an exact single-SA primitive fail closed. The default
    /// keeps third-party adapters source-compatible while making lack of this
    /// optional capability explicit.
    ///
    /// # Cancel safety
    ///
    /// This operation is not cancellation-safe once polled. A backend may
    /// continue its kernel mutation and readback after the returned future is
    /// dropped. Callers must supervise and poll the future to completion rather
    /// than wrap it in an aborting timeout. Cancellation, disconnection, or
    /// process loss is operationally [`XfrmError::StateIndeterminate`]: retain
    /// the outbound block policy and namespace-wide writer exclusion until the
    /// worker completes and exact old/new tuple readback reconciles the state.
    /// After process loss, reconcile before retrying; relocation is not blindly
    /// idempotent.
    async fn relocate_sa(&self, _request: RelocateSaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_relocation",
        })
    }

    /// Report exact single-SA relocation support without changing the
    /// source-compatible [`XfrmProbe`] structure.
    ///
    /// Linux uses the upstream non-mutating missing-SA probe. `ESRCH` proves
    /// support, while `EINVAL` identifies a kernel predating the message and
    /// `ENOPROTOOPT` identifies a kernel built without migration support.
    async fn sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        Ok(XfrmCapability::Missing)
    }

    /// Remove a Security Association.
    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError>;

    /// Remove one SA only when the backend can exclude every competing state
    /// change throughout its observation and deletion.
    ///
    /// [`Self::remove_sa`] deletes whatever state the kernel lookup selects
    /// first, which need not be the caller's state when another state at the
    /// key also matches the lookup mark (for example an unmarked state, which
    /// matches every mark). A snapshot showing one matching candidate does
    /// not exclude a later insertion or replacement before that lookup.
    ///
    /// The default, Linux and namespace-bound Linux implementations validate
    /// the request, then return [`XfrmError::UnsupportedFeature`] with feature
    /// `exact_sa_removal` before any snapshot, deletion or actor admission.
    /// Linux has no conditional SA deletion, and these implementations cannot
    /// exclude kernel ACQUIRE insertion throughout a read-and-delete sequence.
    /// A nonzero SPI and userspace writer serialization do not close that gap.
    ///
    /// [`crate::MockXfrmBackend`] implements the operation under one state
    /// lock: it removes a sole lookup candidate only when every
    /// [`SaRelocationIdentity`] field matches. That identity omits algorithm,
    /// key, lifetime and replay fingerprints; matching it does not establish
    /// installation ownership or authorize cleanup of kernel state.
    ///
    /// # Errors
    ///
    /// The default and Linux implementations return [`XfrmError::InvalidConfig`]
    /// for an invalid key or zero interface identifier before reporting the
    /// unsupported capability. The locked mock also returns
    /// [`XfrmError::StateIndeterminate`] for several candidates,
    /// [`XfrmError::StateMismatch`] for one different candidate, and
    /// [`XfrmError::NotFound`] when no candidate exists, without deleting any
    /// state in those cases.
    async fn remove_sa_exact(&self, request: ExactRemoveSaRequest) -> Result<(), XfrmError> {
        validate_exact_remove_sa_request(&request)?;
        Err(XfrmError::UnsupportedFeature {
            feature: "exact_sa_removal",
        })
    }

    /// Install a new Security Policy.
    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError>;

    /// Rekey (update) an existing Security Policy.
    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError>;

    /// Remove a Security Policy.
    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError>;

    /// Remove one exactly interface-scoped Security Policy.
    ///
    /// The default keeps existing backend implementations source-compatible.
    /// It delegates an unscoped request to [`Self::remove_policy`] and fails
    /// closed for a scoped request because the established method cannot carry
    /// `XFRMA_IF_ID`. Backends must override this method to advertise and
    /// implement scoped deletion. A scoped implementation must prove through
    /// exact policy readback that the platform recognized the requested
    /// interface ID before issuing an unconditional delete; older Linux
    /// kernels silently ignore unknown netlink attributes.
    ///
    /// Linux has no owner- or generation-conditional policy deletion. Callers
    /// must therefore hold namespace-wide XFRM writer exclusion across the
    /// complete readback-and-delete future. The namespace actor serializes SDK
    /// operations on that actor, but it cannot exclude unrelated writers.
    async fn remove_policy_exact(
        &self,
        request: ExactRemovePolicyRequest,
    ) -> Result<(), XfrmError> {
        validate_exact_remove_policy_request(&request)?;
        if request.if_id().is_some() {
            return Err(XfrmError::UnsupportedFeature {
                feature: "exact_scoped_policy_removal",
            });
        }
        self.remove_policy(request.into_request()).await
    }

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<XfrmProbe, XfrmError>;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::{IpAddress, SaRelocationSelector, XfrmId, XfrmLookupMark, XfrmMode};

    fn expected_sa() -> SaRelocationIdentity {
        let source = IpAddress::Ipv4([192, 0, 2, 10]);
        let destination = IpAddress::Ipv4([192, 0, 2, 20]);
        SaRelocationIdentity {
            selector: SaRelocationSelector {
                source,
                destination,
                source_port: 0,
                source_port_mask: 0,
                destination_port: 0,
                destination_port_mask: 0,
                protocol: 0,
                source_prefix_len: 32,
                destination_prefix_len: 32,
                ifindex: 0,
                user_id: 0,
            },
            id: XfrmId {
                destination,
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: source,
            request_id: None,
            mode: XfrmMode::Tunnel,
            encap: None,
            mark: Some(XfrmLookupMark::full(0x42)),
            if_id: None,
            output_mark: None,
        }
    }

    /// Supports snapshots and unconditional removal, but deliberately uses
    /// the trait's default exact-removal implementation.
    #[derive(Debug)]
    struct UnfencedBackend {
        target: Mutex<Option<SaRelocationIdentity>>,
        snapshot_error: Option<XfrmError>,
        snapshot_calls: AtomicUsize,
        removal_calls: AtomicUsize,
    }

    impl UnfencedBackend {
        fn new(snapshot_error: Option<XfrmError>) -> Self {
            Self {
                target: Mutex::new(Some(expected_sa())),
                snapshot_error,
                snapshot_calls: AtomicUsize::new(0),
                removal_calls: AtomicUsize::new(0),
            }
        }

        fn assert_untouched(&self) {
            assert_eq!(
                (
                    self.snapshot_calls.load(Ordering::SeqCst),
                    self.removal_calls.load(Ordering::SeqCst),
                    self.target.lock().unwrap().clone(),
                ),
                (0, 0, Some(expected_sa())),
                "refusal must precede both backend calls and retain the target",
            );
        }
    }

    #[async_trait]
    impl XfrmBackend for UnfencedBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn query_sa_key_snapshot(
            &self,
            key: SaLookupKey,
        ) -> Result<SaKeySnapshot, XfrmError> {
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = &self.snapshot_error {
                return Err(error.clone());
            }
            SaKeySnapshot::new(
                key,
                self.target.lock().unwrap().clone().into_iter().collect(),
            )
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn remove_sa(&self, _request: RemoveSaRequest) -> Result<(), XfrmError> {
            self.removal_calls.fetch_add(1, Ordering::SeqCst);
            self.target
                .lock()
                .unwrap()
                .take()
                .map(|_| ())
                .ok_or(XfrmError::NotFound)
        }

        async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::Unavailable)
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::unsupported())
        }
    }

    #[tokio::test]
    async fn unfenced_exact_removal_default_refuses_even_with_a_matching_snapshot() {
        let backend = UnfencedBackend::new(None);
        let result = backend
            .remove_sa_exact(ExactRemoveSaRequest::new(expected_sa()))
            .await;
        backend.assert_untouched();
        assert!(matches!(
            result,
            Err(XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            })
        ));
    }

    #[tokio::test]
    async fn unfenced_exact_removal_default_never_calls_an_unavailable_snapshot() {
        let backend = UnfencedBackend::new(Some(XfrmError::Unavailable));
        let result = backend
            .remove_sa_exact(ExactRemoveSaRequest::new(expected_sa()))
            .await;
        backend.assert_untouched();
        assert!(matches!(
            result,
            Err(XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            })
        ));
    }

    #[tokio::test]
    async fn unfenced_exact_removal_default_validates_before_refusing() {
        let backend = UnfencedBackend::new(Some(XfrmError::Unavailable));
        let mut zero_spi = expected_sa();
        zero_spi.id.spi = 0;
        let mut wrong_protocol = expected_sa();
        wrong_protocol.id.protocol = 17;
        let mut zero_if_id = expected_sa();
        zero_if_id.if_id = Some(0);
        for (expected, field) in [
            (zero_spi, "sa_key.spi"),
            (wrong_protocol, "sa_key.protocol"),
            (zero_if_id, "sa.if_id"),
        ] {
            let result = backend
                .remove_sa_exact(ExactRemoveSaRequest::new(expected))
                .await;
            assert!(
                matches!(result, Err(XfrmError::InvalidConfig { field: actual, .. }) if actual == field),
                "{result:?}"
            );
            backend.assert_untouched();
        }
    }
}
