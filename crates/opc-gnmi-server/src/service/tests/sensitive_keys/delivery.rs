use super::*;

fn key_stream_list() -> gnmi::SubscriptionList {
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        crate::get::yang_path_to_proto(&user_role_yang_path("permitted-key-marker")).unwrap(),
        gnmi::SubscriptionMode::OnChange,
    );
    list.subscription[0].sample_interval = 0;
    list
}

fn controlled_events(
    capacity: usize,
) -> (
    opc_mgmt_opstate::OperationalEventSender,
    Arc<ControlledEvents>,
) {
    let (sender, receiver) = operational_event_channel(capacity);
    (
        sender,
        Arc::new(ControlledEvents {
            receiver: Mutex::new(Some(receiver)),
            requests: Default::default(),
        }),
    )
}

async fn assert_terminal<S>(stream: &mut S)
where
    S: tonic::codegen::tokio_stream::Stream<Item = Result<gnmi::SubscribeResponse, Status>> + Unpin,
{
    let terminal =
        std::future::poll_fn(|cx| std::task::Poll::Ready(Pin::new(&mut *stream).poll_next(cx)))
            .await;
    let std::task::Poll::Ready(Some(Err(error))) = terminal else {
        panic!("termination ready at change acknowledgement")
    };
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "gNMI service unavailable");
    assert!(!format!("{error:?}").contains("key-marker"));
    assert!(stream.next().await.is_none());
}

async fn complete_change(pending: opc_mgmt_authz::PendingAuthorizationChange) -> u64 {
    tokio::time::timeout(Duration::from_secs(5), pending.complete())
        .await
        .expect("control must not wait for data work")
        .unwrap()
}

#[tokio::test]
async fn idle_on_change_revocation_with_continuously_queued_hidden_events() {
    for context_change in [false, true] {
        let policy = Arc::new(ChangingContext::new());
        let (sender, events) = controlled_events(8);
        let service = state_key_service(
            policy.clone(),
            Arc::new(KeyOperational::default()),
            events,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let mut stream = service
            .subscribe(open_subscribe_request(key_stream_list()))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            stream.next().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        assert_eq!(
            stream.next().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
        let pending = policy
            .hub
            .prepare_change(|| {
                if context_change {
                    policy.resolved_group.store(false, Ordering::SeqCst);
                } else {
                    *policy.policy.lock().unwrap() =
                        selected_policy(&["/sys:system/sys:user/sys:role"], NacmAction::Subscribe);
                }
            })
            .await
            .unwrap();
        let producer = tokio::spawn(async move {
            loop {
                if sender
                    .send(OperationalEvent::Delete {
                        path: user_role_yang_path("hidden-other-key-marker"),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        policy.wait_calls(2).await;
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                stream.as_mut().poll_next(cx).is_pending()
            ))
            .await
        );
        assert_eq!(complete_change(pending).await, 1);
        assert_terminal(&mut stream).await;
        producer.await.unwrap();
    }
}

#[tokio::test]
async fn authorization_change_delivery_invalidation_refresh_and_lost_source() {
    for fault in ["principal", "refresh", "delivery"] {
        let policy = Arc::new(ChangingContext::new());
        let (_sender, events) = controlled_events(1);
        let service = state_key_service(
            policy.clone(),
            Arc::new(KeyOperational::default()),
            events,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let mut stream = service
            .subscribe(open_subscribe_request(key_stream_list()))
            .await
            .unwrap()
            .into_inner();
        stream.next().await.unwrap().unwrap();
        stream.next().await.unwrap().unwrap();
        match fault {
            "principal" => {
                let pending = policy
                    .hub
                    .prepare_change(|| policy.invalid.store(true, Ordering::SeqCst))
                    .await
                    .unwrap();
                assert_eq!(complete_change(pending).await, 1);
                assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
            }
            "refresh" => policy.hub.fail(),
            "delivery" => drop(policy.hub.prepare_change(|| {}).await.unwrap()),
            _ => unreachable!(),
        }
        assert_terminal(&mut stream).await;
    }
}

#[tokio::test]
async fn authorization_change_delivery_revoke_restore_closes_every_old_stream() {
    let policy = Arc::new(ChangingContext::new());
    let mut streams = Vec::new();
    let mut senders = Vec::new();
    for _ in 0..2 {
        let (sender, events) = controlled_events(1);
        senders.push(sender);
        let service = state_key_service(
            policy.clone(),
            Arc::new(KeyOperational::default()),
            events,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let mut stream = service
            .subscribe(open_subscribe_request(key_stream_list()))
            .await
            .unwrap()
            .into_inner();
        stream.next().await.unwrap().unwrap();
        stream.next().await.unwrap().unwrap();
        streams.push(stream);
    }
    let revoke = policy
        .hub
        .prepare_change(|| policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    let restore = policy
        .hub
        .prepare_change(|| policy.resolved_group.store(true, Ordering::SeqCst));
    tokio::pin!(restore);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(restore.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert!(!policy.resolved_group.load(Ordering::SeqCst));
    assert_eq!(complete_change(revoke).await, 1);
    assert_eq!(
        policy.calls.load(Ordering::SeqCst),
        4,
        "each complete batch uses one context"
    );
    let restore = restore.await.unwrap();
    assert_eq!(complete_change(restore).await, 2);
    for stream in &mut streams {
        assert_terminal(stream).await;
    }
}

struct BlockedProvider {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    block_subscription: bool,
    receiver: Mutex<Option<OperationalEventReceiver>>,
}
impl BlockedProvider {
    fn wait(&self) {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        self.release.lock().unwrap().recv().unwrap();
    }
}
impl OperationalStateProvider for BlockedProvider {
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        if !self.block_subscription {
            self.wait();
        }
        Ok(OperationalResponse::new(request.paths().iter().map(
            |path| OperationalValue::new(path.clone(), "\"visible-role-marker\"").unwrap(),
        )))
    }
}
impl OperationalEventSource for BlockedProvider {
    fn subscribe(
        &self,
        _: &OperationalSubscriptionRequest,
    ) -> Result<OperationalEventReceiver, OperationalError> {
        if self.block_subscription {
            self.wait();
        }
        Ok(self.receiver.lock().unwrap().take().unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_change_delivery_does_not_wait_for_blocked_provider() {
    for subscription in [false, true] {
        let policy = Arc::new(ChangingContext::new());
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (_sender, receiver) = operational_event_channel(1);
        let provider = Arc::new(BlockedProvider {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(release_rx),
            block_subscription: subscription,
            receiver: Mutex::new(Some(receiver)),
        });
        let service = state_key_service(
            policy.clone(),
            provider.clone(),
            provider,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let mut stream = service
            .subscribe(open_subscribe_request(key_stream_list()))
            .await
            .unwrap()
            .into_inner();
        entered_rx.await.unwrap();
        let pending = policy
            .hub
            .prepare_change(|| policy.resolved_group.store(false, Ordering::SeqCst))
            .await
            .unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(2), pending.complete()).await;
        // Always release the test provider before asserting, including when a
        // missing isolation guard would otherwise strand a runtime worker.
        release.send(()).unwrap();
        assert_eq!(
            completed
                .expect("provider work must not gate control acknowledgement")
                .unwrap(),
            1
        );
        assert_terminal(&mut stream).await;
    }
}

struct PendingAudit(tokio::sync::Notify);
impl AuditSink for PendingAudit {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        panic!("async audit path")
    }
    fn record_async<'a>(
        &'a self,
        _: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.notify_one();
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn authorization_change_delivery_does_not_wait_for_audit() {
    let policy = Arc::new(ChangingContext::new());
    let audit = Arc::new(PendingAudit(Default::default()));
    let (_sender, events) = controlled_events(1);
    let service = state_key_service(
        policy.clone(),
        Arc::new(KeyOperational::default()),
        events,
        audit.clone(),
    )
    .await;
    let mut stream = service
        .subscribe(open_subscribe_request(key_stream_list()))
        .await
        .unwrap()
        .into_inner();
    audit.0.notified().await;
    let pending = policy
        .hub
        .prepare_change(|| policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(complete_change(pending).await, 1);
    assert_terminal(&mut stream).await;
}

#[tokio::test]
async fn authorization_change_delivery_discards_buffered_output_on_revocation() {
    let policy = Arc::new(ChangingContext::new());
    let (sender, events) = controlled_events(1);
    let service = state_key_service(
        policy.clone(),
        Arc::new(KeyOperational::default()),
        events,
        Arc::new(CapturingAudit::default()),
    )
    .await;
    let mut stream = service
        .subscribe(open_subscribe_request(key_stream_list()))
        .await
        .unwrap()
        .into_inner();
    stream.next().await.unwrap().unwrap();
    stream.next().await.unwrap().unwrap();
    let capacity = subscribe_response_queue_capacity(service.server().limits());
    // Fill every data output slot and leave the writer blocked on one more.
    for _ in 0..=capacity {
        sender
            .send(OperationalEvent::Update(
                OperationalValue::new(
                    user_role_yang_path("permitted-key-marker"),
                    "\"visible-role-marker\"",
                )
                .unwrap(),
            ))
            .await
            .unwrap();
    }
    policy.wait_calls(capacity + 2).await;
    let pending = policy
        .hub
        .prepare_change(|| policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(complete_change(pending).await, 1);
    assert_terminal(&mut stream).await;
}

#[tokio::test]
async fn hidden_event_during_pending_principal_invalidation_does_not_trigger_termination() {
    let policy = Arc::new(ChangingContext::new());
    let (sender, events) = controlled_events(1);
    let service = state_key_service(
        policy.clone(),
        Arc::new(KeyOperational::default()),
        events,
        Arc::new(CapturingAudit::default()),
    )
    .await;
    let mut stream = service
        .subscribe(open_subscribe_request(key_stream_list()))
        .await
        .unwrap()
        .into_inner();
    stream.next().await.unwrap().unwrap();
    stream.next().await.unwrap().unwrap();
    let pending = policy
        .hub
        .prepare_change(|| policy.invalid.store(true, Ordering::SeqCst))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Delete {
            path: user_role_yang_path("hidden-invalid-principal-marker"),
        })
        .await
        .unwrap();
    policy.wait_calls(2).await;
    sender
        .send(OperationalEvent::Delete {
            path: user_role_yang_path("second-hidden-invalid-principal-marker"),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), policy.wait_calls(3))
        .await
        .expect("first hidden event must finish without closing the stream");
    // A held change owns the termination boundary, even when refreshing this
    // principal now fails. Hidden traffic cannot turn that into an early close.
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            stream.as_mut().poll_next(cx).is_pending()
        ))
        .await
    );
    assert_eq!(complete_change(pending).await, 1);
    assert_terminal(&mut stream).await;
}
