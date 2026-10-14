//! gNMI Subscribe handling.

#![allow(deprecated)]

use std::future;
use std::sync::Arc;
use std::time::Duration;

use crate::subscription_auth::{authorization_failure, StreamAuthorization};
use opc_config_bus::{ConfigEvent, SubscriberLagPolicy};
use opc_config_model::{OpcConfig, RequestId, TrustedPrincipal, YangPath};
use opc_mgmt_audit::{AuditOperation, AuditOutcome, SchemaNodePath};
use opc_mgmt_authz::{AuthorizationGate, ReadAction, ReadAuthorizer};
use opc_mgmt_opstate::{
    OperationalEvent, OperationalEventReceiver, OperationalSubscriptionRequest,
};
use prost::Message;
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

use crate::audit::{outcome_for_error, record_audit, schema_paths_for_schema};
use crate::get::{
    encoding_from_proto, handle_read_request, handle_subscribed_read, now_nanos, operational_error,
    project_operational_value, read_node, select_paths, select_read_request, update_to_proto,
    validate_operational_identity, yang_path_to_proto, GetDataType, ModelFilter,
};
use crate::metrics::{
    active_stream, record_rpc_error, GnmiNacmAction, GnmiOperation, SubscribeModeMetric,
};
use crate::proto::gnmi;
use crate::proto_adapter::path_from_proto;
use crate::service::{status_from_error, validate_extensions_for_operation, ExtensionOperation};
use crate::{GnmiConfigBinding, GnmiError, GnmiJsonUpdate, GnmiServer, ResolvedGnmiPath};

const RESPONSE_QUEUE_BYTES_ESTIMATE: usize = 4096;
const MAX_SUBSCRIBE_QUEUE_MESSAGES: usize = 1024;

/// Serves one authenticated gNMI Subscribe request stream.
#[cfg(test)]
pub(crate) async fn serve_subscribe_stream<C, B>(
    server: Arc<GnmiServer<C, B>>,
    principal: TrustedPrincipal,
    inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    serve_subscribe_stream_with_gate(
        server,
        principal,
        inbound,
        outbound,
        AuthorizationGate::default(),
    )
    .await
}

pub(crate) async fn serve_subscribe_stream_with_gate<C, B>(
    server: Arc<GnmiServer<C, B>>,
    principal: TrustedPrincipal,
    mut inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    gate: AuthorizationGate,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let request_id = RequestId::new();
    let first = match inbound.message().await {
        Ok(Some(first)) => first,
        Ok(None) => {
            let err = GnmiError::invalid("gNMI Subscribe stream ended before subscription");
            audit_subscribe_result(
                server.as_ref(),
                request_id,
                &principal,
                outcome_for_error(&err),
                Vec::new(),
            )
            .await?;
            return Err(err);
        }
        Err(_) => {
            let err = GnmiError::unavailable("gNMI Subscribe request stream failed");
            audit_subscribe_result(
                server.as_ref(),
                request_id,
                &principal,
                outcome_for_error(&err),
                Vec::new(),
            )
            .await?;
            return Err(err);
        }
    };
    if let Err(err) = validate_extensions_for_operation(
        server.extensions(),
        &first.extension,
        ExtensionOperation::Subscribe,
    ) {
        audit_subscribe_result(
            server.as_ref(),
            request_id,
            &principal,
            outcome_for_error(&err),
            Vec::new(),
        )
        .await?;
        return Err(err);
    }
    let mut plan = match SubscribePlan::from_first_request(server.as_ref(), first) {
        Ok(plan) => plan,
        Err(err) => {
            audit_subscribe_result(
                server.as_ref(),
                request_id,
                &principal,
                outcome_for_error(&err),
                Vec::new(),
            )
            .await?;
            return Err(err);
        }
    };
    let source = server.binding().policy_source();
    let mut watch = source
        .watch_authorization(&principal, gate.clone())
        .map_err(|_| {
            gate.terminate();
            authorization_failure()
        })?;
    let initial = watch.take_initial().map_err(|_| authorization_failure())?;
    let selected = select_read_request(server.as_ref(), &plan.get_request)?;
    let authorization = Arc::new(StreamAuthorization::new(
        server.binding().schema(),
        source,
        principal.clone(),
        &selected,
        initial,
        watch.revision(),
        gate.clone(),
    )?);
    plan.authorization = Some(authorization.clone());
    watch
        .initial_evaluated()
        .map_err(|_| authorization_failure())?;
    let _guard = active_stream(plan.metric_mode());
    let data_outbound = outbound.clone();
    let work = async move {
        audit_subscribe_result(
            server.as_ref(),
            request_id,
            &principal,
            AuditOutcome::Success,
            plan.audit_paths.clone(),
        )
        .await?;
        match plan.mode {
            SubscribeListMode::Once => serve_once(&server, &principal, &plan, &data_outbound).await,
            SubscribeListMode::Poll => {
                serve_poll(server, request_id, principal, plan, inbound, data_outbound).await
            }
            SubscribeListMode::Stream => {
                serve_stream(server, request_id, principal, plan, inbound, data_outbound).await
            }
        }
    };
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            change = watch.changed() => {
                let change = match change {
                    Ok(change) => change,
                    Err(_) => { gate.terminate(); return Err(authorization_failure()); }
                };
                if authorization.reevaluate().is_err() {
                    gate.terminate();
                    // Dropping the notification acknowledges server-side closure.
                    drop(change);
                    return Err(authorization_failure());
                }
                if watch.acknowledge(change).is_err() {
                    gate.terminate();
                    return Err(authorization_failure());
                }
            }
            _ = outbound.closed() => return Ok(()),
            result = &mut work => return result,
        }
    }
}

async fn serve_once<C, B>(
    server: &Arc<GnmiServer<C, B>>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    if !plan.updates_only {
        let mut dedupe = SnapshotDedupe::default();
        if !send_snapshot(server, principal, plan, outbound, &mut dedupe, true).await? {
            return Ok(());
        }
    }
    send_sync(outbound).await?;
    Ok(())
}

async fn serve_poll<C, B>(
    server: Arc<GnmiServer<C, B>>,
    request_id: RequestId,
    principal: TrustedPrincipal,
    plan: SubscribePlan,
    mut inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    send_sync(&outbound).await?;
    loop {
        let Some(request) = inbound
            .message()
            .await
            .map_err(|_| GnmiError::unavailable("gNMI Subscribe poll stream failed"))?
        else {
            return Ok(());
        };
        if let Err(err) = validate_extensions_for_operation(
            server.extensions(),
            &request.extension,
            ExtensionOperation::Subscribe,
        ) {
            audit_subscribe_result(
                server.as_ref(),
                request_id,
                &principal,
                outcome_for_error(&err),
                plan.audit_paths.clone(),
            )
            .await?;
            return Err(err);
        }
        match request.request {
            Some(gnmi::subscribe_request::Request::Poll(_)) => {
                if !plan.updates_only {
                    let mut dedupe = SnapshotDedupe::default();
                    if !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, true)
                        .await?
                    {
                        return Ok(());
                    }
                }
                send_sync(&outbound).await?;
            }
            Some(gnmi::subscribe_request::Request::Subscribe(_)) => {
                let err = GnmiError::invalid(
                    "gNMI Subscribe stream cannot replace an active subscription",
                );
                audit_subscribe_result(
                    server.as_ref(),
                    request_id,
                    &principal,
                    outcome_for_error(&err),
                    plan.audit_paths.clone(),
                )
                .await?;
                return Err(err);
            }
            None => {
                let err = GnmiError::invalid("empty gNMI Subscribe request");
                audit_subscribe_result(
                    server.as_ref(),
                    request_id,
                    &principal,
                    outcome_for_error(&err),
                    plan.audit_paths.clone(),
                )
                .await?;
                return Err(err);
            }
        }
    }
}

async fn serve_stream<C, B>(
    server: Arc<GnmiServer<C, B>>,
    request_id: RequestId,
    principal: TrustedPrincipal,
    plan: SubscribePlan,
    mut inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let queue_capacity = subscribe_queue_capacity(server.limits())?;
    let mut operational_rx = match plan
        .stream
        .as_ref()
        .and_then(|stream| stream.operational_request.as_ref())
    {
        Some(request) => {
            let server = server.clone();
            let plan = plan.clone();
            let request = request.clone();
            tokio::task::spawn_blocking(move || {
                subscribe_operational_events(server.as_ref(), &plan, &request)
            })
            .await
            .map_err(|_| GnmiError::unavailable("gNMI event subscription failed"))??
        }
        None => None,
    };
    let config_rx = plan
        .stream
        .as_ref()
        .filter(|stream| stream.has_config_on_change)
        .map(|_| {
            server
                .binding()
                .config_bus()
                .subscribe(SubscriberLagPolicy::ForceResync, queue_capacity)
        });
    let mut dedupe = SnapshotDedupe::default();
    if !plan.updates_only
        && !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, true).await?
    {
        return Ok(());
    }
    if plan.updates_only {
        let responses = render_snapshot_async(&server, &principal, &plan).await?;
        dedupe.last = Some(fingerprint_responses(&responses));
    }
    send_sync(&outbound).await?;

    let mut sample = plan
        .stream
        .as_ref()
        .and_then(|stream| stream.sample_interval)
        .map(tokio::time::interval);
    if let Some(sample) = sample.as_mut() {
        sample.tick().await;
    }
    let mut heartbeat = plan
        .stream
        .as_ref()
        .and_then(|stream| stream.heartbeat_interval)
        .map(tokio::time::interval);
    if let Some(heartbeat) = heartbeat.as_mut() {
        heartbeat.tick().await;
    }

    loop {
        tokio::select! {
            request = inbound.message() => {
                let request = request
                    .map_err(|_| GnmiError::unavailable("gNMI Subscribe stream failed"))?;
                let Some(request) = request else {
                    return Ok(());
                };
                if let Err(err) = validate_extensions_for_operation(
                    server.extensions(),
                    &request.extension,
                    ExtensionOperation::Subscribe,
                ) {
                    audit_subscribe_result(
                        server.as_ref(),
                        request_id,
                        &principal,
                        outcome_for_error(&err),
                        plan.audit_paths.clone(),
                    )
                    .await?;
                    return Err(err);
                }
                match request.request {
                    Some(gnmi::subscribe_request::Request::Poll(_)) => {
                        let err = GnmiError::invalid("poll request sent to STREAM subscription");
                        audit_subscribe_result(
                            server.as_ref(),
                            request_id,
                            &principal,
                            outcome_for_error(&err),
                            plan.audit_paths.clone(),
                        )
                        .await?;
                        return Err(err);
                    }
                    Some(gnmi::subscribe_request::Request::Subscribe(_)) => {
                        let err = GnmiError::invalid("gNMI Subscribe stream cannot replace an active subscription");
                        audit_subscribe_result(
                            server.as_ref(),
                            request_id,
                            &principal,
                            outcome_for_error(&err),
                            plan.audit_paths.clone(),
                        )
                        .await?;
                        return Err(err);
                    }
                    None => {
                        let err = GnmiError::invalid("empty gNMI Subscribe request");
                        audit_subscribe_result(
                            server.as_ref(),
                            request_id,
                            &principal,
                            outcome_for_error(&err),
                            plan.audit_paths.clone(),
                        )
                        .await?;
                        return Err(err);
                    }
                }
            }
            event = async {
                match config_rx.as_ref() {
                    Some(rx) => rx.recv().await,
                    None => future::pending().await,
                }
            }, if config_rx.is_some() => {
                match event {
                    Some(ConfigEvent::Change(_)) => {
                        if !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, false).await? {
                            return Ok(());
                        }
                    }
                    Some(ConfigEvent::ResyncRequired { .. }) => {
                        if !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, false).await? {
                            return Ok(());
                        }
                        if dedupe.changed { send_sync(&outbound).await?; }
                    }
                    None => return Ok(()),
                }
            }
            event = async {
                match operational_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => future::pending().await,
                }
            }, if operational_rx.is_some() => {
                match event {
                    Some(Ok(event)) => {
                        if !send_operational_event_owned(&server, &principal, &plan, event, &outbound).await? {
                            return Ok(());
                        }
                    }
                    Some(Err(err)) => return Err(operational_error(err)),
                    None => return Ok(()),
                }
            }
            _ = async {
                match sample.as_mut() {
                    Some(sample) => sample.tick().await,
                    None => future::pending().await,
                }
            }, if sample.is_some() => {
                let suppress = plan.stream.as_ref().is_some_and(|stream| stream.suppress_redundant);
                if !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, !suppress).await? {
                    return Ok(());
                }
            }
            _ = async {
                match heartbeat.as_mut() {
                    Some(heartbeat) => heartbeat.tick().await,
                    None => future::pending().await,
                }
            }, if heartbeat.is_some() => {
                if !send_snapshot(&server, &principal, &plan, &outbound, &mut dedupe, true).await? {
                    return Ok(());
                }
            }
        }
    }
}

/// Sends a terminal stream error without leaking server-local detail.
pub(crate) async fn send_subscribe_error(
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    err: GnmiError,
) {
    record_rpc_error(GnmiOperation::Subscribe, err.status(), Duration::ZERO);
    let _ = outbound.send(Err(status_from_error(err))).await;
}

async fn render_snapshot_async<C, B>(
    server: &Arc<GnmiServer<C, B>>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
) -> Result<Vec<gnmi::SubscribeResponse>, GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let server = server.clone();
    let principal = principal.clone();
    let plan = plan.clone();
    tokio::task::spawn_blocking(move || {
        render_snapshot_responses(server.as_ref(), &principal, &plan)
    })
    .await
    .map_err(|_| GnmiError::unavailable("gNMI snapshot work failed"))?
}

async fn send_snapshot<C, B>(
    server: &Arc<GnmiServer<C, B>>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    dedupe: &mut SnapshotDedupe,
    force: bool,
) -> Result<bool, GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let responses = render_snapshot_async(server, principal, plan).await?;
    let fingerprint = fingerprint_responses(&responses);
    dedupe.changed = dedupe.last.as_ref() != Some(&fingerprint);
    dedupe.last = Some(fingerprint);
    if !force && !dedupe.changed {
        return Ok(true);
    }
    for response in responses {
        if outbound.send(Ok(response)).await.is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Renders the current subscribed snapshot as gNMI Subscribe update responses.
pub(crate) fn render_snapshot_responses<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
) -> Result<Vec<gnmi::SubscribeResponse>, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let response = match &plan.authorization {
        Some(authorization) => {
            handle_subscribed_read(server, principal, &plan.get_request, authorization)?
        }
        None => handle_read_request(
            server,
            principal,
            &plan.get_request,
            ReadAction::Subscribe,
            GnmiNacmAction::Subscribe,
        )?,
    };
    Ok(response
        .notification
        .into_iter()
        .map(|notification| gnmi::SubscribeResponse {
            response: Some(gnmi::subscribe_response::Response::Update(notification)),
            extension: Vec::new(),
        })
        .collect())
}

fn subscribe_operational_events<C, B>(
    server: &GnmiServer<C, B>,
    plan: &SubscribePlan,
    request: &OperationalSubscriptionRequest,
) -> Result<Option<OperationalEventReceiver>, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let paths = request
        .paths()
        .iter()
        .filter(|path| {
            event_schema_node(server.binding().schema(), path.as_str()).is_some_and(|node| {
                plan.authorization
                    .as_ref()
                    .is_some_and(|auth| auth.permits_request(node.path))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(None);
    }
    let request = OperationalSubscriptionRequest::new(paths)
        .with_max_queued_events(request.max_queued_events());
    server
        .binding()
        .operational_events()
        .ok_or_else(|| {
            GnmiError::unimplemented("gNMI operational on-change event source is not configured")
        })?
        .subscribe(&request)
        .map(Some)
        .map_err(operational_error)
}

#[cfg(test)]
pub(crate) async fn send_operational_event<C, B>(
    server: &GnmiServer<C, B>,
    _request_id: RequestId,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    event: OperationalEvent,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<bool, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    match prepare_operational_event(server, principal, plan, event)? {
        Some(response) => Ok(outbound.send(Ok(response)).await.is_ok()),
        None => Ok(true),
    }
}

async fn send_operational_event_owned<C, B>(
    server: &Arc<GnmiServer<C, B>>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    event: OperationalEvent,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<bool, GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let server = server.clone();
    let principal = principal.clone();
    let plan = plan.clone();
    let response = tokio::task::spawn_blocking(move || {
        prepare_operational_event(server.as_ref(), &principal, &plan, event)
    })
    .await
    .map_err(|_| GnmiError::unavailable("gNMI event work failed"))??;
    let Some(response) = response else {
        return Ok(true);
    };
    Ok(outbound.send(Ok(response)).await.is_ok())
}

fn prepare_operational_event<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    event: OperationalEvent,
) -> Result<Option<gnmi::SubscribeResponse>, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let stream = plan
        .stream
        .as_ref()
        .ok_or_else(|| GnmiError::schema("operational event sent to non-stream subscription"))?;
    let request = stream
        .operational_request
        .as_ref()
        .ok_or_else(|| GnmiError::schema("operational event sent without subscription request"))?;
    let registry = server.binding().schema();
    let Some(node) = event_schema_node(registry, event.path().as_str()) else {
        return Ok(None);
    };
    let allowed = match &plan.authorization {
        Some(auth) => auth.event(node.path)?,
        None => {
            let policy = server.binding().policy_source();
            let authz = ReadAuthorizer::new(server.binding().schema(), policy.as_ref())
                .map_err(|_| authorization_failure())?;
            authz
                .authorize_selection(
                    principal,
                    ReadAction::Subscribe,
                    &[read_node(registry, node.path)],
                    &Default::default(),
                )
                .map_err(|_| authorization_failure())?
                .decisions
                .first()
                .is_some_and(|decision| decision.allowed)
        }
    };
    if !allowed {
        return Ok(None);
    }
    server
        .limits()
        .check_value_bytes(event.path().as_str().len())
        .map_err(GnmiError::from_limits)?;
    if let OperationalEvent::Update(value) = &event {
        server
            .limits()
            .check_value_bytes(value.value_json().len())
            .map_err(GnmiError::from_limits)?;
    }
    opc_mgmt_path::resolve_instance(registry, event.path())
        .map_err(|_| GnmiError::schema("invalid operational instance"))?;
    if node.config {
        return Err(GnmiError::schema(
            "operational event path resolved to config data",
        ));
    }
    event
        .validate_for_request(request)
        .map_err(|_| GnmiError::schema("invalid operational event"))?;

    let encoding = encoding_from_proto(plan.get_request.encoding)?;
    if !server.profile().encodings().supports(encoding) {
        return Err(GnmiError::from(encoding));
    }

    let notification = match event {
        OperationalEvent::Update(value) => {
            let value = project_operational_value(registry, &value, node)?;
            let update = GnmiJsonUpdate::new(value.path().clone(), value.value_json().to_string())
                .map_err(|err| GnmiError::schema(err.detail().to_string()))?;
            gnmi::Notification {
                timestamp: now_nanos(),
                prefix: None,
                update: vec![update_to_proto(&update, encoding, server.limits())?],
                delete: Vec::new(),
                atomic: true,
            }
        }
        OperationalEvent::Delete { path } => {
            validate_operational_identity(registry, &path)?;
            gnmi::Notification {
                timestamp: now_nanos(),
                prefix: None,
                update: Vec::new(),
                delete: vec![yang_path_to_proto(&path)?],
                atomic: true,
            }
        }
    };

    let response = gnmi::SubscribeResponse {
        response: Some(gnmi::subscribe_response::Response::Update(notification)),
        extension: Vec::new(),
    };
    Ok(Some(response))
}

fn event_schema_node(
    registry: &dyn opc_mgmt_schema::SchemaRegistry,
    path: &str,
) -> Option<&'static opc_mgmt_schema::NodeMeta> {
    registry
        .nodes()
        .iter()
        .find(|node| opc_mgmt_path::instance_schema_matches(node.path, path))
}

async fn audit_subscribe_result<C, B>(
    server: &GnmiServer<C, B>,
    request_id: RequestId,
    principal: &TrustedPrincipal,
    outcome: AuditOutcome,
    paths: Vec<SchemaNodePath>,
) -> Result<(), GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    record_audit(
        server.audit(),
        request_id,
        principal,
        AuditOperation::Subscribe,
        outcome,
        paths,
    )
    .await
}

async fn send_sync(
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError> {
    let response = gnmi::SubscribeResponse {
        response: Some(gnmi::subscribe_response::Response::SyncResponse(true)),
        extension: Vec::new(),
    };
    let _ = outbound.send(Ok(response)).await;
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "prost encode_length_delimited into a Vec is infallible (buffer grows)"
)]
fn fingerprint_responses(responses: &[gnmi::SubscribeResponse]) -> Vec<u8> {
    let mut out = Vec::new();
    for response in responses {
        let mut content = response.clone();
        let mut keys = Vec::new();
        if let Some(gnmi::subscribe_response::Response::Update(notification)) =
            &mut content.response
        {
            notification.timestamp = 0;
            if let Some(prefix) = &mut notification.prefix {
                fingerprint_path_keys(prefix, &mut keys);
            }
            for update in &mut notification.update {
                if let Some(path) = &mut update.path {
                    fingerprint_path_keys(path, &mut keys);
                }
            }
            for path in &mut notification.delete {
                fingerprint_path_keys(path, &mut keys);
            }
        }
        content
            .encode_length_delimited(&mut out)
            .expect("encoding SubscribeResponse to Vec cannot fail");
        out.extend_from_slice(&(keys.len() as u64).to_le_bytes());
        out.extend_from_slice(&keys);
    }
    out
}

// Protobuf map encoding follows HashMap iteration order. Extract the keys in a
// stable order before encoding the remaining message, preserving every literal
// value and boundary in the fingerprint.
fn fingerprint_path_keys(path: &mut gnmi::Path, out: &mut Vec<u8>) {
    for element in &mut path.elem {
        let mut keys: Vec<_> = element.key.iter().collect();
        keys.sort_unstable_by_key(|(name, _)| *name);
        out.extend_from_slice(&(keys.len() as u64).to_le_bytes());
        for (name, value) in keys {
            for text in [name, value] {
                out.extend_from_slice(&(text.len() as u64).to_le_bytes());
                out.extend_from_slice(text.as_bytes());
            }
        }
        element.key.clear();
    }
}

#[derive(Default)]
struct SnapshotDedupe {
    last: Option<Vec<u8>>,
    changed: bool,
}

/// Parsed and validated Subscribe request plan.
#[derive(Debug, Clone)]
pub(crate) struct SubscribePlan {
    mode: SubscribeListMode,
    updates_only: bool,
    get_request: gnmi::GetRequest,
    stream: Option<StreamPlan>,
    audit_paths: Vec<SchemaNodePath>,
    authorization: Option<Arc<StreamAuthorization>>,
}

impl SubscribePlan {
    pub(crate) fn from_first_request<C, B>(
        server: &GnmiServer<C, B>,
        request: gnmi::SubscribeRequest,
    ) -> Result<Self, GnmiError>
    where
        C: OpcConfig,
        B: GnmiConfigBinding<C>,
    {
        let list = match request.request {
            Some(gnmi::subscribe_request::Request::Subscribe(list)) => list,
            Some(gnmi::subscribe_request::Request::Poll(_)) => {
                return Err(GnmiError::invalid(
                    "first gNMI Subscribe request must carry a subscription list",
                ))
            }
            None => return Err(GnmiError::invalid("empty gNMI Subscribe request")),
        };
        Self::from_subscription_list(server, list)
    }

    pub(crate) fn from_subscription_list<C, B>(
        server: &GnmiServer<C, B>,
        list: gnmi::SubscriptionList,
    ) -> Result<Self, GnmiError>
    where
        C: OpcConfig,
        B: GnmiConfigBinding<C>,
    {
        if list.subscription.is_empty() {
            return Err(GnmiError::invalid(
                "gNMI Subscribe requires at least one path",
            ));
        }
        server
            .limits()
            .check_paths(list.subscription.len())
            .map_err(GnmiError::from_limits)?;
        if list.qos.is_some() {
            return Err(GnmiError::unimplemented(
                "gNMI Subscribe QoS marking is not supported by this profile",
            ));
        }
        if list.allow_aggregation {
            return Err(GnmiError::unimplemented(
                "gNMI Subscribe aggregation is not supported by this profile",
            ));
        }
        let encoding = encoding_from_proto(list.encoding)?;
        if !server.profile().encodings().supports(encoding) {
            return Err(GnmiError::from(encoding));
        }

        let mode = match gnmi::subscription_list::Mode::try_from(list.mode) {
            Ok(gnmi::subscription_list::Mode::Once) => SubscribeListMode::Once,
            Ok(gnmi::subscription_list::Mode::Poll) => SubscribeListMode::Poll,
            Ok(gnmi::subscription_list::Mode::Stream) => SubscribeListMode::Stream,
            Err(_) => return Err(GnmiError::invalid("unknown gNMI Subscribe mode")),
        };
        let stream = (mode == SubscribeListMode::Stream)
            .then(|| stream_plan(server, &list))
            .transpose()?;
        let audit_paths = subscribe_audit_paths(server, &list)?;
        let paths = list
            .subscription
            .iter()
            .map(|subscription| subscription.path.clone().unwrap_or_default())
            .collect::<Vec<_>>();
        let get_request = gnmi::GetRequest {
            prefix: list.prefix,
            path: paths,
            r#type: gnmi::get_request::DataType::All as i32,
            encoding: list.encoding,
            use_models: list.use_models,
            extension: Vec::new(),
        };
        Ok(Self {
            mode,
            updates_only: list.updates_only,
            get_request,
            stream,
            audit_paths,
            authorization: None,
        })
    }

    const fn metric_mode(&self) -> SubscribeModeMetric {
        match self.mode {
            SubscribeListMode::Once => SubscribeModeMetric::Once,
            SubscribeListMode::Poll => SubscribeModeMetric::Poll,
            SubscribeListMode::Stream => SubscribeModeMetric::Stream,
        }
    }

    #[cfg(test)]
    pub(crate) fn audit_paths(&self) -> &[SchemaNodePath] {
        &self.audit_paths
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn enforce_min_interval_boundary() {
        let floor = Duration::from_millis(100);
        let err = enforce_min_interval(Duration::from_nanos(1), floor)
            .expect_err("interval below floor rejected");
        assert!(matches!(
            err,
            GnmiError::InvalidArgument { ref detail }
                if detail.contains("below server minimum")
        ));
        assert!(enforce_min_interval(floor, floor).is_ok());
        assert!(enforce_min_interval(Duration::from_millis(101), floor).is_ok());
    }
}

fn subscribe_audit_paths<C, B>(
    server: &GnmiServer<C, B>,
    list: &gnmi::SubscriptionList,
) -> Result<Vec<SchemaNodePath>, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let registry = server.binding().schema();
    let model_filter = ModelFilter::new(registry, &list.use_models)?;
    let prefix = list.prefix.as_ref().map(path_from_proto).transpose()?;
    let request_paths = list
        .subscription
        .iter()
        .map(|subscription| {
            subscription
                .path
                .as_ref()
                .map(path_from_proto)
                .transpose()
                .map(|path| path.unwrap_or_default())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let entries = select_paths(
        registry,
        server.limits(),
        prefix.as_ref(),
        &request_paths,
        GetDataType::All,
        &model_filter,
    )?;
    schema_paths_for_schema(entries.iter().map(|entry| entry.schema_path()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscribeListMode {
    Once,
    Poll,
    Stream,
}

#[derive(Debug, Clone)]
struct StreamPlan {
    has_config_on_change: bool,
    operational_request: Option<OperationalSubscriptionRequest>,
    sample_interval: Option<Duration>,
    heartbeat_interval: Option<Duration>,
    suppress_redundant: bool,
}

fn enforce_min_interval(interval: Duration, floor: Duration) -> Result<Duration, GnmiError> {
    if interval < floor {
        return Err(GnmiError::invalid("gNMI interval below server minimum"));
    }
    Ok(interval)
}

fn stream_plan<C, B>(
    server: &GnmiServer<C, B>,
    list: &gnmi::SubscriptionList,
) -> Result<StreamPlan, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let mut has_on_change = false;
    let mut sample_interval = None;
    let mut heartbeat_interval = None;
    let mut suppress_redundant = false;

    for subscription in &list.subscription {
        match gnmi::SubscriptionMode::try_from(subscription.mode) {
            Ok(gnmi::SubscriptionMode::OnChange) => has_on_change = true,
            Ok(gnmi::SubscriptionMode::Sample) => {
                if subscription.sample_interval == 0 {
                    return Err(GnmiError::invalid(
                        "gNMI SAMPLE subscription requires sample_interval",
                    ));
                }
                sample_interval = Some(min_duration(
                    sample_interval,
                    nanos(subscription.sample_interval).and_then(|duration| {
                        enforce_min_interval(duration, server.limits().min_sample_interval)
                    })?,
                ));
            }
            Ok(gnmi::SubscriptionMode::TargetDefined) => {
                return Err(GnmiError::unimplemented(
                    "gNMI TARGET_DEFINED subscriptions are not supported by this profile",
                ));
            }
            Err(_) => return Err(GnmiError::invalid("unknown gNMI subscription mode")),
        }
        if subscription.suppress_redundant {
            suppress_redundant = true;
        }
        if subscription.heartbeat_interval > 0 {
            if !subscription.suppress_redundant {
                return Err(GnmiError::invalid(
                    "gNMI heartbeat_interval requires suppress_redundant",
                ));
            }
            heartbeat_interval = Some(min_duration(
                heartbeat_interval,
                nanos(subscription.heartbeat_interval).and_then(|duration| {
                    enforce_min_interval(duration, server.limits().min_sample_interval)
                })?,
            ));
        }
    }

    let on_change_classes = has_on_change
        .then(|| classify_on_change_paths(server, list))
        .transpose()?
        .unwrap_or_default();
    if !on_change_classes.operational_paths.is_empty()
        && server.binding().operational_events().is_none()
    {
        return Err(GnmiError::unimplemented(
            "gNMI operational on-change subscriptions require an event source",
        ));
    }
    let operational_request = if on_change_classes.operational_paths.is_empty() {
        None
    } else {
        Some(
            OperationalSubscriptionRequest::new(on_change_classes.operational_paths)
                .with_max_queued_events(subscribe_queue_capacity(server.limits())?),
        )
    };
    Ok(StreamPlan {
        has_config_on_change: on_change_classes.has_config,
        operational_request,
        sample_interval,
        heartbeat_interval,
        suppress_redundant,
    })
}

#[derive(Debug, Default)]
struct OnChangePathClasses {
    has_config: bool,
    operational_paths: Vec<YangPath>,
}

fn classify_on_change_paths<C, B>(
    server: &GnmiServer<C, B>,
    list: &gnmi::SubscriptionList,
) -> Result<OnChangePathClasses, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let registry = server.binding().schema();
    let model_filter = SubscribeModelFilter::new(registry, &list.use_models)?;
    let prefix = list.prefix.as_ref().map(path_from_proto).transpose()?;
    if prefix.as_ref().is_some_and(path_has_target) {
        return Err(GnmiError::unimplemented(
            "non-empty gNMI target is not supported",
        ));
    }
    let mut classes = OnChangePathClasses::default();
    for subscription in &list.subscription {
        if !matches!(
            gnmi::SubscriptionMode::try_from(subscription.mode),
            Ok(gnmi::SubscriptionMode::OnChange)
        ) {
            continue;
        }
        let path = subscription
            .path
            .as_ref()
            .map(path_from_proto)
            .transpose()?
            .unwrap_or_default();
        if path_has_target(&path) {
            return Err(GnmiError::unimplemented(
                "non-empty gNMI target is not supported",
            ));
        }
        if path.elems.is_empty() {
            let origin_modules = root_origin_modules(registry, prefix.as_ref(), Some(&path))?;
            if let Some(prefix) = prefix.as_ref().filter(|prefix| !prefix.elems.is_empty()) {
                if let Some(resolved) = crate::path::resolve_read_path(registry, None, prefix)? {
                    classify_from_resolved(registry, &resolved, &model_filter, &mut classes)?;
                }
            } else {
                classify_all_matching(
                    registry,
                    &model_filter,
                    origin_modules.as_ref(),
                    &mut classes,
                )?;
            }
            continue;
        }
        if let Some(resolved) = crate::path::resolve_read_path(registry, prefix.as_ref(), &path)? {
            classify_from_resolved(registry, &resolved, &model_filter, &mut classes)?;
        }
    }
    classes
        .operational_paths
        .sort_by(|a, b| a.as_str().cmp(b.as_str()));
    classes
        .operational_paths
        .dedup_by(|a, b| a.as_str() == b.as_str());
    server
        .limits()
        .check_paths(classes.operational_paths.len())
        .map_err(GnmiError::from_limits)?;
    Ok(classes)
}

struct SubscribeModelFilter {
    modules: Option<Vec<&'static str>>,
}

impl SubscribeModelFilter {
    fn new(
        registry: &'static dyn opc_mgmt_schema::SchemaRegistry,
        requested: &[gnmi::ModelData],
    ) -> Result<Self, GnmiError> {
        if requested.is_empty() {
            return Ok(Self { modules: None });
        }

        let mut modules = Vec::new();
        for model in requested {
            let Some(served) = registry.served_models().iter().find(|served| {
                served.name == model.name
                    && (model.version.is_empty() || served.revision == model.version)
            }) else {
                return Err(GnmiError::invalid(
                    "gNMI Subscribe requested an unserved model",
                ));
            };
            modules.push(served.name);
        }
        modules.sort();
        modules.dedup();
        Ok(Self {
            modules: Some(modules),
        })
    }

    fn allows(&self, module: &str) -> bool {
        self.modules
            .as_ref()
            .is_none_or(|modules| modules.contains(&module))
    }
}

fn classify_all_matching(
    registry: &'static dyn opc_mgmt_schema::SchemaRegistry,
    model_filter: &SubscribeModelFilter,
    origin_modules: Option<&std::collections::HashSet<&'static str>>,
    classes: &mut OnChangePathClasses,
) -> Result<(), GnmiError> {
    for node in registry.nodes() {
        if !model_filter.allows(node.module)
            || origin_modules.is_some_and(|modules| !modules.contains(node.module))
        {
            continue;
        }
        if node.config {
            classes.has_config = true;
        } else {
            classes.operational_paths.push(
                YangPath::new(node.path).map_err(|_| GnmiError::schema("invalid schema path"))?,
            );
        }
    }
    Ok(())
}

fn classify_from_resolved(
    registry: &'static dyn opc_mgmt_schema::SchemaRegistry,
    resolved: &ResolvedGnmiPath,
    model_filter: &SubscribeModelFilter,
    classes: &mut OnChangePathClasses,
) -> Result<(), GnmiError> {
    if !model_filter.allows(resolved.node.module) {
        return Err(GnmiError::invalid(
            "gNMI Subscribe path is outside the requested model set",
        ));
    }

    let root = resolved.schema_path.as_str();
    for node in registry.nodes() {
        let under_root = node.path == root
            || node
                .path
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/'));
        if !under_root || !model_filter.allows(node.module) {
            continue;
        }
        if node.config {
            classes.has_config = true;
        } else {
            classes
                .operational_paths
                .push(canonical_descendant_path(resolved, node.path)?);
        }
    }
    Ok(())
}

fn canonical_descendant_path(
    resolved: &ResolvedGnmiPath,
    schema_path: &'static str,
) -> Result<YangPath, GnmiError> {
    if schema_path == resolved.schema_path {
        return Ok(resolved.canonical.clone());
    }
    let suffix = schema_path
        .strip_prefix(resolved.schema_path.as_str())
        .ok_or_else(|| GnmiError::schema("invalid selected schema descendant"))?;
    YangPath::new(format!("{}{}", resolved.canonical.as_str(), suffix))
        .map_err(|_| GnmiError::schema("invalid selected canonical path"))
}

fn root_origin_modules(
    registry: &'static dyn opc_mgmt_schema::SchemaRegistry,
    prefix: Option<&crate::GnmiPath>,
    path: Option<&crate::GnmiPath>,
) -> Result<Option<std::collections::HashSet<&'static str>>, GnmiError> {
    let prefix_origin = prefix.and_then(|path| path.origin.as_deref());
    let path_origin = path.and_then(|path| path.origin.as_deref());
    let origin = match (prefix_origin, path_origin) {
        (Some(prefix), Some(path)) if prefix != path => {
            return Err(GnmiError::invalid(
                "gNMI prefix origin and path origin differ",
            ));
        }
        (Some(origin), _) | (_, Some(origin)) => Some(origin),
        (None, None) => None,
    };
    let Some(origin) = origin else {
        return Ok(None);
    };
    let modules = registry
        .modules_for_origin(origin)
        .ok_or_else(|| GnmiError::invalid("unknown gNMI origin"))?;
    Ok(Some(modules.iter().copied().collect()))
}

fn path_has_target(path: &crate::GnmiPath) -> bool {
    path.target.is_some()
}

fn subscribe_queue_capacity(limits: &opc_mgmt_limits::MgmtLimits) -> Result<usize, GnmiError> {
    limits
        .check_subscriber_queue_bytes(limits.max_subscriber_queue_bytes)
        .map_err(GnmiError::from_limits)?;
    Ok(
        (limits.max_subscriber_queue_bytes / RESPONSE_QUEUE_BYTES_ESTIMATE)
            .clamp(1, MAX_SUBSCRIBE_QUEUE_MESSAGES),
    )
}

fn min_duration(current: Option<Duration>, candidate: Duration) -> Duration {
    current.map_or(candidate, |current| current.min(candidate))
}

fn nanos(value: u64) -> Result<Duration, GnmiError> {
    if value == 0 {
        return Err(GnmiError::invalid("zero duration is invalid"));
    }
    Ok(Duration::from_nanos(value))
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn equal_key_maps_have_equal_fingerprints_despite_distinct_wire_order() {
        let mut responses = Vec::new();
        for _ in 0..32 {
            let keys = (0..8)
                .map(|index| (format!("key{index}"), format!("value{index}")))
                .collect();
            responses.push(gnmi::SubscribeResponse {
                response: Some(gnmi::subscribe_response::Response::Update(
                    gnmi::Notification {
                        update: vec![gnmi::Update {
                            path: Some(gnmi::Path {
                                elem: vec![gnmi::PathElem {
                                    name: "list".into(),
                                    key: keys,
                                }],
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                )),
                ..Default::default()
            });
        }
        let first_wire = responses[0].encode_to_vec();
        assert!(
            responses
                .iter()
                .skip(1)
                .any(|response| response.encode_to_vec() != first_wire),
            "fixture must exercise distinct protobuf map orders"
        );
        let first = fingerprint_responses(&responses[..1]);
        for response in responses {
            assert_eq!(fingerprint_responses(&[response]), first);
        }
    }
}
