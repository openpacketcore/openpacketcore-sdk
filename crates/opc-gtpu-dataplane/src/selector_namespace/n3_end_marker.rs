//! Ordered, retirement-bound N3 End Marker submission.

use super::*;
use std::net::IpAddr;

/// Bounded, redacted result of retirement-bound End Marker submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GtpuN3EndMarkerError {
    /// The protected namespace could not establish or finish a safe operation.
    /// A final lease-release failure can occur after local submission.
    #[error("N3 End Marker namespace operation was not confirmed")]
    Namespace,
    /// The backend or whole tunnel profile is unsupported. No End Marker was
    /// submitted by this attempt; the retired claim remains recoverable.
    #[error("N3 End Marker submission profile is unsupported")]
    Unsupported,
    /// The backend did not confirm all local submissions. Some datagrams may
    /// have been submitted; an explicit retry can therefore duplicate them.
    #[error("N3 End Marker backend operation was not confirmed")]
    Backend,
}

/// One SDK-issued request to submit End Markers after exact N3 retirement.
///
/// The protected namespace has checked the current terminal coordinate, no
/// successor, and no other admitted group sharing an outgoing tunnel. The
/// backend must still verify complete dataplane absence and the terminal stamp,
/// complete its classifier grace period, and send on each original tunnel tuple
/// under the same exclusive effect lease. This is not caller-supplied drain
/// evidence or permission to end another tunnel.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::GtpuN3EndMarkerRequest;
/// fn cannot_replay(request: GtpuN3EndMarkerRequest) { let _ = request.clone(); }
/// ```
pub struct GtpuN3EndMarkerRequest {
    retired: GtpuSessionSelectorRetiredClaim,
    window: SelectorBackendMutationWindow,
}

impl GtpuN3EndMarkerRequest {
    /// Exact retired graph; distinct inner families may share one outer tunnel.
    #[must_use]
    pub const fn retired_group(&self) -> &GtpuSessionGroup {
        &self.retired.group
    }

    /// Opaque binding to the one protected namespace and managed attachment.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.retired.admission.binding()
    }

    /// Verify the entire terminal-retired stamp, including its protected
    /// dataplane generation. Partial or caller-reconstructed stamps do not pass.
    #[must_use]
    pub fn verifies_exact_terminal_retired_stamp(
        &self,
        stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
    ) -> bool {
        verifies_terminal_retired_stamp(&self.retired.admission, stamp)
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    /// Complete only after every distinct outgoing tunnel's End Marker was
    /// accepted by the local UDP stack after the qualified classifier grace.
    /// This receipt asserts neither NIC drain nor remote delivery/order. An
    /// error after any send must not be converted into this receipt.
    pub fn confirm_submitted(self) -> GtpuN3EndMarkerReceipt {
        GtpuN3EndMarkerReceipt {
            retired: self.retired,
            window: self.window.into_receipt(),
        }
    }
}

/// Affine backend receipt; only an SDK-issued request can construct it.
pub struct GtpuN3EndMarkerReceipt {
    retired: GtpuSessionSelectorRetiredClaim,
    window: SelectorBackendMutationWindowReceipt,
}

/// Completed local submission with the original retired claim preserved.
///
/// A lost acknowledgement is indeterminate: recovery may repeat an End Marker.
/// This object grants no selector reuse or peer-restart authority.
#[must_use = "retain the retired claim for subsequent explicit lifecycle operations"]
pub struct GtpuN3EndMarkerCompletion {
    retired: GtpuSessionSelectorRetiredClaim,
}

impl GtpuN3EndMarkerCompletion {
    /// Number of distinct outgoing tunnel datagrams submitted (one or two).
    #[must_use]
    pub fn datagram_count(&self) -> usize {
        outgoing_tunnels(&self.retired.group).len()
    }

    /// Recover the same retired capability. Reuse still requires the separate
    /// backend-authorized selector protocol and caller-owned peer coordination.
    pub fn into_retired_claim(self) -> GtpuSessionSelectorRetiredClaim {
        self.retired
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(
    GtpuN3EndMarkerRequest,
    GtpuN3EndMarkerReceipt,
    GtpuN3EndMarkerCompletion
);

// Retain each original outgoing UDP tuple for submission. Neither the QFI nor
// the inner address family creates another tunnel at the peer.
fn outgoing_tunnels(group: &GtpuSessionGroup) -> BTreeSet<(IpAddr, IpAddr, u16, u32)> {
    group
        .entries()
        .iter()
        .map(|entry| {
            let context = entry.context();
            let port = context.uplink_source_port_policy.effective_source_port();
            (
                entry.local_outer_address(),
                context.peer_address,
                port,
                context.peer_teid.get(),
            )
        })
        .collect()
}

fn peer_tunnels(group: &GtpuSessionGroup) -> BTreeSet<(IpAddr, u32)> {
    // A different local address or UDP source port does not make a shared peer
    // TEID safe to end. Compare the receiving endpoint, regardless of QFI.
    group
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.context().peer_address,
                entry.context().peer_teid.get(),
            )
        })
        .collect()
}

impl<B> GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    /// Submit N3 End Markers after exact retirement and a backend classifier
    /// grace period. The owned worker holds the durable namespace lease through
    /// completion even if the caller drops the future.
    ///
    /// A stale/foreign claim, a successor, or any other historical admitted group
    /// sharing the peer address and TEID is refused before issuing the request.
    /// The eBPF profile supports IPv4 outer tunnels using UDP source port 2152;
    /// other profiles/backends return [`GtpuN3EndMarkerError::Unsupported`]
    /// before any submission.
    /// There is no retransmission timer, remote acknowledgement, automatic
    /// removal on received controls, or peer-delivery guarantee. Except for
    /// `Unsupported`, errors can be indeterminate; recover the retired claim
    /// before an explicit retry, which may submit duplicate End Markers.
    pub fn send_n3_end_markers<D>(
        &self,
        backend: Arc<D>,
        retired: GtpuSessionSelectorRetiredClaim,
    ) -> GtpuSessionSelectorOperation<GtpuN3EndMarkerCompletion, GtpuN3EndMarkerError>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        spawn_selector_operation(
            self.storage_scope_commitment,
            GtpuN3EndMarkerError::Backend,
            async move {
                authority
                    .send_n3_end_markers_owned(backend.as_ref(), retired)
                    .await
            },
        )
    }

    async fn send_n3_end_markers_owned<D: GtpuDataplaneBackend + ?Sized>(
        &self,
        backend: &D,
        retired: GtpuSessionSelectorRetiredClaim,
    ) -> Result<GtpuN3EndMarkerCompletion, GtpuN3EndMarkerError> {
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuN3EndMarkerError::Namespace)?;
        let result = async {
            self.ensure_backend_namespace(backend, &mut lease)
                .await
                .map_err(|_| GtpuN3EndMarkerError::Namespace)?;
            let (_, state) = self
                .read_state()
                .await
                .map_err(|_| GtpuN3EndMarkerError::Namespace)?;
            if !end_marker_source_is_current(&state, self.storage_scope_commitment, &retired) {
                return Err(GtpuN3EndMarkerError::Namespace);
            }
            let window = self
                .mint_backend_mutation_window(&mut lease)
                .await
                .map_err(|_| GtpuN3EndMarkerError::Namespace)?;
            let receipt = settle_selector_backend_step(
                backend.submit_n3_end_markers(GtpuN3EndMarkerRequest { retired, window }),
            )
            .await
            .ok_or(GtpuN3EndMarkerError::Backend)?
            .map_err(|error| match error {
                crate::GtpuError::UnsupportedFeature { .. } => GtpuN3EndMarkerError::Unsupported,
                _ => GtpuN3EndMarkerError::Backend,
            })?;
            if !receipt.window.is_current() {
                return Err(GtpuN3EndMarkerError::Backend);
            }
            Ok(GtpuN3EndMarkerCompletion {
                retired: receipt.retired,
            })
        }
        .await;
        // Preserve the primary result if durable lease release also fails.
        // A failed release after submission cannot report a clean handoff.
        let release = self.release_worker_lease(lease).await;
        match result {
            Err(error) => Err(error),
            Ok(completion) if release.is_ok() => Ok(completion),
            Ok(_) => Err(GtpuN3EndMarkerError::Namespace),
        }
    }
}

pub(super) fn end_marker_source_is_current(
    state: &NamespaceState,
    scope: [u8; 32],
    retired: &GtpuSessionSelectorRetiredClaim,
) -> bool {
    let admission = &retired.admission;
    if state.lifecycle != NamespaceLifecycle::Bound
        || state.decommission_fence.is_some()
        || admission.phase != SelectorAdmissionPhase::Retired
        || !admission.validates(&retired.group)
        || state
            .canonical_group_for(admission.group_fingerprint)
            .as_ref()
            != Some(&retired.group)
        || retired
            .group
            .entries()
            .iter()
            .any(|entry| entry.n3_qfi().is_none())
        || state.binding_with_scope(scope).ok() != Some(admission.binding())
    {
        return false;
    }
    let Some(GroupState::Retired {
        device,
        selectors,
        desired,
        generation,
        operation_nonce,
        retired_dataplane_generation,
        successor: None,
        ..
    }) = state.groups.get(&admission.group_fingerprint)
    else {
        return false;
    };
    if *device != admission.device_fingerprint
        || *selectors != admission.selector_set_fingerprint
        || *desired != admission.desired_fingerprint
        || *generation != admission.terminal_generation
        || *operation_nonce != admission.terminal_operation_nonce
        || Some(*retired_dataplane_generation) != admission.retired_dataplane_generation
    {
        return false;
    }
    let source = peer_tunnels(&retired.group);
    state.groups.keys().all(|id| {
        *id == admission.group_fingerprint
            || state
                .canonical_group_for(*id)
                .is_some_and(|other| source.is_disjoint(&peer_tunnels(&other)))
    })
}
