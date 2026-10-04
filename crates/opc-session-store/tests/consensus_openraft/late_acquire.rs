use super::*;
use opc_session_store::{
    SessionConsensusIdentity, SessionConsensusRequestId, SessionMutationIntent,
};

// Read-only mirror of the mutation envelope. Only the typed acquire intent is
// inspected; original request bytes remain confined to this synthetic fixture.
#[derive(Deserialize)]
enum ForwardObservation {
    Mutation(MutationObservation),
}

#[derive(Deserialize)]
struct MutationObservation {
    #[serde(rename = "request_id")]
    _request_id: SessionConsensusRequestId,
    intent: SessionMutationIntent,
    #[serde(rename = "required_consumer_scope")]
    _required_consumer_scope: ForwardScopeObservation,
}

// Postcard is not self-describing, so IgnoredAny cannot skip these fields.
#[derive(Deserialize)]
enum ForwardScopeObservation {
    Internal,
    Consumer(#[allow(dead_code)] Box<SessionConsensusIdentity>),
}

struct AcquireArrivalCapture {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    key: SessionKey,
    hold_before_handling: AtomicBool,
    captured: StdMutex<Option<(SessionConsensusNodeId, SessionConsensusWireRequest)>>,
    captures: AtomicUsize,
}

impl fmt::Debug for AcquireArrivalCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcquireArrivalCapture(<redacted>)")
    }
}

impl AcquireArrivalCapture {
    fn new(
        inner: Arc<dyn SessionConsensusRpcHandler>,
        key: SessionKey,
        hold_before_handling: bool,
    ) -> Self {
        Self {
            inner,
            key,
            hold_before_handling: AtomicBool::new(hold_before_handling),
            captured: StdMutex::new(None),
            captures: AtomicUsize::new(0),
        }
    }

    fn captured_request(&self) -> (SessionConsensusNodeId, SessionConsensusWireRequest) {
        self.captured
            .lock()
            .expect("capture mutex")
            .as_ref()
            .cloned()
            .expect("one actual forwarded acquire was captured")
    }

    async fn deliver_original(&self) -> SessionConsensusWireResponse {
        let (sender, request) = self.captured_request();
        self.inner.handle(sender, request).await
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for AcquireArrivalCapture {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        let exact_acquire = request.family == SessionConsensusRpcFamily::ForwardMutation
            && matches!(
                decode_bounded::<ForwardObservation>(&request.payload),
                Ok(ForwardObservation::Mutation(MutationObservation {
                    intent: SessionMutationIntent::AcquireLease { ref key, .. },
                    ..
                })) if key == &self.key
            );
        if exact_acquire {
            {
                let mut captured = self.captured.lock().expect("capture mutex");
                if captured.is_none() {
                    *captured = Some((authenticated_sender, request.clone()));
                }
            }
            self.captures.fetch_add(1, Ordering::SeqCst);
            if self.hold_before_handling.load(Ordering::SeqCst) {
                // Capture actual arrival before invoking the receiver. The
                // sender's timeout drops this pending future; delivery below
                // is explicit and starts no detached test task.
                return std::future::pending().await;
            }
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

fn capture_follower_acquire(
    cluster: &TestCluster,
    key: SessionKey,
    hold: bool,
) -> (usize, usize, Arc<AcquireArrivalCapture>) {
    let (leader, _, _) = cluster.observed_leader();
    let follower = (leader + 1) % MEMBER_COUNT;
    let capture = Arc::new(AcquireArrivalCapture::new(
        cluster.stores[leader].rpc_handler(),
        key,
        hold,
    ));
    cluster.paths[&(follower, leader)].install(capture.clone());
    (leader, follower, capture)
}

#[tokio::test]
async fn delayed_distinct_acquire_can_supersede_acknowledged_same_owner_replacement() {
    let cluster = TestCluster::start().await;
    let key = session_key(b"delayed-distinct-acquire-diagnostic");
    let owner = owner("delayed-distinct-acquire-owner");
    let ttl = Duration::from_secs(3600);
    let (leader, follower, capture) = capture_follower_acquire(&cluster, key.clone(), true);

    let first = tokio::time::timeout(
        RECOVERY_TIMEOUT,
        cluster.stores[follower].acquire(&key, owner.clone(), ttl),
    )
    .await
    .expect("original caller reaches its own bounded outcome");
    assert!(
        matches!(first, Err(LeaseError::OperationOutcomeUnavailable)),
        "held real acquire must have a typed indeterminate result"
    );
    assert!(capture.captures.load(Ordering::SeqCst) > 0);
    assert_eq!(cluster.observed_leader().0, leader);

    let replacement = cluster.stores[leader]
        .acquire(&key, owner, ttl)
        .await
        .expect("distinct same-owner replacement is acknowledged");
    let before = cluster.stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("read fence before old arrival");
    assert_eq!(before.current_fence(), replacement.fence());

    let response = capture.deliver_original().await;
    assert!(
        response.result.is_ok(),
        "real receiver accepts held envelope"
    );
    let after = cluster.stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("read fence after old arrival");
    assert!(after.current_fence().get() > replacement.fence().get());
    assert!(
        matches!(
            cluster.stores[leader].renew(&replacement, ttl).await,
            Err(LeaseError::StaleFence)
        ),
        "late distinct acquire invalidates B; this is a cause witness, not a repair"
    );
}

#[tokio::test]
async fn replay_of_already_committed_acquire_does_not_supersede_later_replacement() {
    let cluster = TestCluster::start().await;
    let key = session_key(b"committed-acquire-replay-control");
    let owner = owner("committed-acquire-replay-owner");
    let ttl = Duration::from_secs(3600);
    let (leader, follower, capture) = capture_follower_acquire(&cluster, key.clone(), false);
    let first = cluster.stores[follower]
        .acquire(&key, owner.clone(), ttl)
        .await
        .expect("original acquire commits before replacement");
    assert!(capture.captures.load(Ordering::SeqCst) > 0);
    let replacement = cluster.stores[leader]
        .acquire(&key, owner, ttl)
        .await
        .expect("later replacement commits");
    assert!(replacement.fence().get() > first.fence().get());
    let response = capture.deliver_original().await;
    assert!(
        response.result.is_ok(),
        "same-ID replay reaches real receiver"
    );
    let after = cluster.stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("read durable fence after replay");
    assert_eq!(after.current_fence(), replacement.fence());
    let renewed = cluster.stores[leader]
        .renew(&replacement, ttl)
        .await
        .expect("same-ID replay leaves replacement current");
    assert_eq!(renewed.fence(), replacement.fence());
}

#[tokio::test]
async fn explicit_consumer_retry_keeps_unknown_acquire_identity_across_late_delivery() {
    use opc_session_store::{
        SessionConsumerAuthorizationGrant, SessionConsumerIdentity,
        SessionConsumerLeaseMutationOperation, SessionConsumerLeaseMutationRequest,
        SessionConsumerLeaseMutationResult, SessionConsumerLeaseMutationStatus,
        SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
        SessionConsumerResponse, SessionConsumerTenantNfScope, SessionQuorumConsumer,
    };
    let cluster = TestCluster::start().await;
    let key = session_key(b"explicit-acquire-retry-control");
    let owner = owner("explicit-acquire-retry-owner");
    let ttl = Duration::from_secs(3600);
    let (leader, follower, capture) = capture_follower_acquire(&cluster, key.clone(), true);
    let identity =
        "spiffe://test.example/tenant/lease-recovery/ns/test/sa/consumer/nf/smf/instance/one";
    let grant = SessionConsumerAuthorizationGrant::try_new(
        opc_types::SpiffeId::new(identity).expect("synthetic consumer identity"),
        [SessionConsumerTenantNfScope::new(
            key.tenant.clone(),
            key.nf_kind.clone(),
        )],
    )
    .expect("exact synthetic grant");
    let manifest = cluster.stores[follower]
        .consumer_authorization_manifest([grant])
        .await
        .expect("store-issued fixture authority");
    let authorization = manifest
        .authorize(&SessionConsumerIdentity::new(identity).expect("identity"))
        .expect("trusted fixture caller authorization");
    let scope = manifest.scope();
    let first_id = SessionConsumerRequestId::new();
    let first = SessionConsumerRequest::new(
        scope,
        first_id,
        SessionConsumerOperation::AcquireLease {
            key: key.clone(),
            owner: owner.clone(),
            ttl,
        },
    );
    assert!(matches!(
        cluster.stores[follower]
            .consumer_service()
            .execute(&authorization, first.clone())
            .await,
        SessionConsumerResponse::OutcomeUnknown(_)
    ));
    assert!(capture.captures.load(Ordering::SeqCst) > 0);
    let retained = SessionConsumerLeaseMutationRequest::new(
        first_id,
        SessionConsumerLeaseMutationOperation::Acquire {
            key: key.clone(),
            owner: owner.clone(),
            ttl,
        },
    );
    let status = SessionConsumerRequest::new(
        scope,
        first_id,
        SessionConsumerOperation::LeaseMutationStatus {
            request: Box::new(retained),
        },
    );
    assert!(matches!(
        cluster.stores[leader]
            .consumer_service()
            .execute(&authorization, status.clone())
            .await,
        SessionConsumerResponse::LeaseMutationStatus(Ok(
            SessionConsumerLeaseMutationStatus::NotFound
        ))
    ));
    // NotFound did not retire A. Explicitly retry that exact A at the live
    // leader, with its original complete public identity/body/scope binding.
    let first_lease = match cluster.stores[leader]
        .consumer_service()
        .execute(&authorization, first)
        .await
    {
        SessionConsumerResponse::AcquireLease(Ok(lease)) => lease,
        _ => panic!("exact A must resolve before a successor can be admitted"),
    };
    match cluster.stores[leader]
        .consumer_service()
        .execute(&authorization, status)
        .await
    {
        SessionConsumerResponse::LeaseMutationStatus(Ok(
            SessionConsumerLeaseMutationStatus::Recorded(result),
        )) => {
            assert!(matches!(*result,
                Ok(SessionConsumerLeaseMutationResult::Acquire(ref lease))
                    if lease == &first_lease));
        }
        _ => panic!("A must have an authoritative exact receipt"),
    }
    let second = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::new(),
        SessionConsumerOperation::AcquireLease {
            key: key.clone(),
            owner,
            ttl,
        },
    );
    let second_lease = match cluster.stores[leader]
        .consumer_service()
        .execute(&authorization, second)
        .await
    {
        SessionConsumerResponse::AcquireLease(Ok(lease)) => lease,
        _ => panic!("B succeeds only after A is known"),
    };
    assert!(second_lease.fence().get() > first_lease.fence().get());
    assert!(capture.deliver_original().await.result.is_ok());
    let observed = cluster.stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("fence readback");
    assert_eq!(observed.current_fence(), second_lease.fence());
    cluster.stores[leader]
        .renew(&second_lease, ttl)
        .await
        .expect("late A cannot fence B");
}
