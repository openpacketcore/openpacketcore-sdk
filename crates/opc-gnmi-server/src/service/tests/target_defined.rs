use super::*;
use http_body_util::BodyExt;
use std::time::Duration;

type SubscriptionStream = <GnmiService<DemoConfig, TestBinding> as GNmi>::SubscribeStream;

fn open_request(list: gnmi::SubscriptionList) -> Request<tonic::Streaming<gnmi::SubscribeRequest>> {
    let payload = subscribe_request(list).encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let body =
        http_body_util::Full::new(bytes::Bytes::from(frame)).with_trailers(std::future::pending::<
            Option<Result<tonic::codegen::http::HeaderMap, std::convert::Infallible>>,
        >());
    let mut codec =
        tonic_prost::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
    let mut request = Request::new(tonic::Streaming::new_request(
        codec.decoder(),
        tonic::body::Body::new(body),
        None,
        None,
    ));
    request.extensions_mut().insert(authenticated_principal());
    request
}

async fn next(stream: &mut SubscriptionStream) -> gnmi::SubscribeResponse {
    tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("subscription deadline")
        .expect("open subscription")
        .expect("update")
}

fn updates(response: gnmi::SubscribeResponse) -> Vec<gnmi::Update> {
    let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response else {
        panic!("expected data notification")
    };
    notification.update
}

fn ends_at(update: &gnmi::Update, leaf: &str) -> bool {
    update
        .path
        .as_ref()
        .and_then(|path| path.elem.last())
        .is_some_and(|elem| elem.name == leaf || elem.name == format!("sys:{leaf}"))
}

fn notification(response: gnmi::SubscribeResponse) -> gnmi::Notification {
    match response.response {
        Some(gnmi::subscribe_response::Response::Update(notification)) => notification,
        _ => panic!("expected data notification"),
    }
}

fn is_user(path: &gnmi::Path, user: &str) -> bool {
    path.elem
        .iter()
        .any(|element| element.key.values().any(|value| value == user))
}

async fn writable_subscribe_service() -> GnmiService<DemoConfig, TestBinding> {
    authenticated_service_with_policy(allow_policy_for_actions(&[
        NacmAction::Read,
        NacmAction::Subscribe,
        NacmAction::Create,
        NacmAction::Update,
        NacmAction::Replace,
        NacmAction::Delete,
    ]))
    .await
}

async fn user_stream(
    service: &GnmiService<DemoConfig, TestBinding>,
    mode: gnmi::SubscriptionMode,
) -> SubscriptionStream {
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        gnmi_path(vec![path_elem("user")]),
        mode,
    );
    list.prefix = Some(gnmi_path(vec![path_elem("system")]));
    list.subscription[0].suppress_redundant = true;
    if mode == gnmi::SubscriptionMode::TargetDefined {
        list.subscription[0].sample_interval = 0;
    }
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    let initial = updates(next(&mut stream).await);
    for user in ["admin", "guest"] {
        assert!(initial
            .iter()
            .any(|update| is_user(update.path.as_ref().unwrap(), user)));
    }
    assert_eq!(
        next(&mut stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    stream
}

#[tokio::test]
async fn review_config_stream_reports_removed_keyed_nodes_including_the_last_node() {
    for mode in [
        gnmi::SubscriptionMode::OnChange,
        gnmi::SubscriptionMode::TargetDefined,
    ] {
        let service = writable_subscribe_service().await;
        let mut stream = user_stream(&service, mode).await;
        for user in ["guest", "admin"] {
            service
                .set(authenticated_set_request(gnmi::SetRequest {
                    delete: vec![user_path(user)],
                    ..Default::default()
                }))
                .await
                .unwrap();
            let change = notification(next(&mut stream).await);
            assert!(
                !change.delete.is_empty(),
                "removed nodes require explicit delete paths"
            );
            assert!(change.delete.iter().all(|path| is_user(path, user)));
            assert!(
                change.update.is_empty(),
                "unchanged users must not be resent"
            );
            assert!(
                !change.atomic,
                "a delta must not replace the entire subscription subtree"
            );
        }
    }
}

async fn only_changed_user_is_reported(mode: gnmi::SubscriptionMode) {
    let service = writable_subscribe_service().await;
    let mut stream = user_stream(&service, mode).await;
    service
        .set(authenticated_set_request(gnmi::SetRequest {
            update: vec![json_update(
                user_role_path("admin"),
                br#""operator""#.to_vec(),
            )],
            ..Default::default()
        }))
        .await
        .unwrap();
    let change = notification(next(&mut stream).await);
    assert_eq!(change.update.len(), 1, "only the changed leaf may be sent");
    assert!(is_user(change.update[0].path.as_ref().unwrap(), "admin"));
    assert!(ends_at(&change.update[0], "role"));
    assert!(change.delete.is_empty());
    assert!(
        !change.atomic,
        "partial notifications cannot assert complete subtree coverage"
    );
}

#[tokio::test]
async fn review_on_change_reports_only_changed_leaves() {
    only_changed_user_is_reported(gnmi::SubscriptionMode::OnChange).await;
}

#[tokio::test]
async fn review_target_defined_reports_only_changed_leaves() {
    only_changed_user_is_reported(gnmi::SubscriptionMode::TargetDefined).await;
}

#[tokio::test]
async fn review_sample_suppression_reports_only_changed_leaves() {
    only_changed_user_is_reported(gnmi::SubscriptionMode::Sample).await;
}

#[tokio::test]
async fn target_defined_separates_config_events_from_state_samples() {
    let service = authenticated_service_with_policy(allow_policy_for_actions(&[
        NacmAction::Read,
        NacmAction::Subscribe,
        NacmAction::Update,
        NacmAction::Create,
        NacmAction::Replace,
        NacmAction::Delete,
    ]))
    .await;
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        gnmi_path(vec![path_elem("system")]),
        gnmi::SubscriptionMode::TargetDefined,
    );
    list.subscription[0].sample_interval = 0;
    SubscribePlan::from_subscription_list(service.server(), list.clone())
        .expect("target-defined plan");
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    let mut initial = Vec::new();
    loop {
        let response = next(&mut stream).await;
        if response.response == Some(gnmi::subscribe_response::Response::SyncResponse(true)) {
            break;
        }
        initial.extend(updates(response));
    }
    assert!(initial.iter().any(|update| ends_at(update, "hostname")));
    assert!(initial.iter().any(|update| ends_at(update, "uptime")));
    for _ in 0..2 {
        let sample = updates(next(&mut stream).await);
        assert_eq!(sample.len(), 1);
        assert!(ends_at(&sample[0], "uptime"), "config must not be sampled");
    }
    service
        .set(authenticated_set_request(hostname_set(
            "changed-host",
            Vec::new(),
        )))
        .await
        .expect("configuration change");
    loop {
        let change = updates(next(&mut stream).await);
        if let Some(hostname) = change.iter().find(|update| ends_at(update, "hostname")) {
            assert!(
                !change.iter().any(|update| ends_at(update, "uptime")),
                "config event must not resample state"
            );
            assert_eq!(
                hostname.val.as_ref().unwrap().value,
                Some(gnmi::typed_value::Value::JsonIetfVal(
                    br#""changed-host""#.to_vec()
                ))
            );
            break;
        }
    }
}

#[tokio::test]
async fn zero_sample_interval_uses_the_target_minimum() {
    let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        uptime_path(),
        gnmi::SubscriptionMode::Sample,
    );
    list.subscription[0].sample_interval = 0;
    list.updates_only = true;
    SubscribePlan::from_subscription_list(service.server(), list.clone())
        .expect("zero interval is target-selected");
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next(&mut stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    let sample = updates(next(&mut stream).await);
    assert_eq!(sample.len(), 1);
    assert!(ends_at(&sample[0], "uptime"));
}

#[tokio::test]
async fn target_defined_preserves_keyed_prefix_and_subscribe_authorization() {
    for allowed in [true, false] {
        let policy = if allowed {
            allow_all_subscribe_policy()
        } else {
            allow_all_read_policy()
        };
        let service = authenticated_service_with_policy(policy).await;
        let mut prefix = user_role_path("admin");
        let role = prefix.elem.pop().unwrap();
        let mut list = subscribe_list(
            gnmi::subscription_list::Mode::Stream,
            gnmi_path(vec![role]),
            gnmi::SubscriptionMode::TargetDefined,
        );
        list.prefix = Some(prefix);
        list.subscription[0].sample_interval = 0;
        let mut stream = service
            .subscribe(open_request(list))
            .await
            .unwrap()
            .into_inner();
        let response = next(&mut stream).await;
        if allowed {
            let data = updates(response);
            assert_eq!(data.len(), 1);
            assert_eq!(
                data[0].path.as_ref().unwrap().elem[1]
                    .key
                    .get("name")
                    .or_else(|| data[0].path.as_ref().unwrap().elem[1].key.get("sys:name"))
                    .map(String::as_str),
                Some("admin")
            );
            assert_eq!(
                next(&mut stream).await.response,
                Some(gnmi::subscribe_response::Response::SyncResponse(true))
            );
        } else {
            assert_eq!(
                response.response,
                Some(gnmi::subscribe_response::Response::SyncResponse(true))
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(220), stream.next())
                .await
                .is_err(),
            "config-only target-defined subscription must await a change"
        );
    }
}

#[tokio::test]
async fn mixed_sample_intervals_do_not_resample_slower_paths() {
    let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        uptime_path(),
        gnmi::SubscriptionMode::Sample,
    );
    list.updates_only = true;
    list.subscription.push(gnmi::Subscription {
        path: Some(hostname_path()),
        mode: gnmi::SubscriptionMode::Sample as i32,
        sample_interval: 600_000_000,
        ..Default::default()
    });
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next(&mut stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    let started = tokio::time::Instant::now();
    let mut fast_samples = 0;
    loop {
        let data = updates(next(&mut stream).await);
        assert_eq!(
            data.len(),
            1,
            "independent schedules must not publish one another's paths"
        );
        if ends_at(&data[0], "hostname") {
            assert!(
                started.elapsed() >= Duration::from_millis(500),
                "slower path fired at the fast interval"
            );
            break;
        }
        assert!(ends_at(&data[0], "uptime"));
        fast_samples += 1;
        assert!(fast_samples < 20, "slow schedule must not starve");
    }
    assert!(fast_samples >= 2);
}

#[tokio::test]
async fn redundant_suppression_is_scoped_to_its_subscription() {
    let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        uptime_path(),
        gnmi::SubscriptionMode::Sample,
    );
    list.updates_only = true;
    list.subscription[0].suppress_redundant = true;
    list.subscription.push(gnmi::Subscription {
        path: Some(hostname_path()),
        mode: gnmi::SubscriptionMode::Sample as i32,
        sample_interval: 300_000_000,
        ..Default::default()
    });
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next(&mut stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    for _ in 0..2 {
        let data = updates(next(&mut stream).await);
        assert_eq!(data.len(), 1);
        assert!(ends_at(&data[0], "hostname"));
    }
}

#[tokio::test]
async fn on_change_heartbeat_does_not_require_redundant_suppression() {
    let service = authenticated_service_with_policy(allow_all_subscribe_policy()).await;
    let mut list = subscribe_list(
        gnmi::subscription_list::Mode::Stream,
        hostname_path(),
        gnmi::SubscriptionMode::OnChange,
    );
    list.updates_only = true;
    list.subscription[0].heartbeat_interval = 100_000_000;
    let mut stream = service
        .subscribe(open_request(list))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next(&mut stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    for _ in 0..2 {
        let data = updates(next(&mut stream).await);
        assert_eq!(data.len(), 1);
        assert!(ends_at(&data[0], "hostname"));
    }
}
