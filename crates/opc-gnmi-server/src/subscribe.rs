//! gNMI Subscribe handling.

#![allow(deprecated)]

use std::future;
use std::sync::Arc;
use std::time::Duration;

use opc_config_bus::{ConfigEvent, SubscriberLagPolicy};
use opc_config_model::{OpcConfig, TrustedPrincipal};
use opc_mgmt_authz::ReadAction;
use prost::Message;
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

use crate::get::handle_read_request;
use crate::metrics::{
    active_stream, record_rpc_error, GnmiNacmAction, GnmiOperation, SubscribeModeMetric,
};
use crate::proto::gnmi;
use crate::proto_adapter::path_from_proto;
use crate::service::{status_from_error, validate_extensions};
use crate::{GnmiConfigBinding, GnmiError, GnmiServer};

const RESPONSE_QUEUE_BYTES_ESTIMATE: usize = 4096;
const MAX_SUBSCRIBE_QUEUE_MESSAGES: usize = 1024;

/// Serves one authenticated gNMI Subscribe request stream.
pub(crate) async fn serve_subscribe_stream<C, B>(
    server: Arc<GnmiServer<C, B>>,
    principal: TrustedPrincipal,
    mut inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let first = inbound
        .message()
        .await
        .map_err(|_| GnmiError::unavailable("gNMI Subscribe request stream failed"))?
        .ok_or_else(|| GnmiError::invalid("gNMI Subscribe stream ended before subscription"))?;
    validate_extensions(server.extensions(), &first.extension)?;
    let plan = SubscribePlan::from_first_request(server.as_ref(), first)?;
    let _guard = active_stream(plan.metric_mode());

    match plan.mode {
        SubscribeListMode::Once => serve_once(server.as_ref(), &principal, &plan, &outbound).await,
        SubscribeListMode::Poll => serve_poll(server, principal, plan, inbound, outbound).await,
        SubscribeListMode::Stream => serve_stream(server, principal, plan, inbound, outbound).await,
    }
}

async fn serve_once<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
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
        validate_extensions(server.extensions(), &request.extension)?;
        match request.request {
            Some(gnmi::subscribe_request::Request::Poll(_)) => {
                if !plan.updates_only {
                    let mut dedupe = SnapshotDedupe::default();
                    if !send_snapshot(
                        server.as_ref(),
                        &principal,
                        &plan,
                        &outbound,
                        &mut dedupe,
                        true,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
                send_sync(&outbound).await?;
            }
            Some(gnmi::subscribe_request::Request::Subscribe(_)) => {
                return Err(GnmiError::invalid(
                    "gNMI Subscribe stream cannot replace an active subscription",
                ));
            }
            None => return Err(GnmiError::invalid("empty gNMI Subscribe request")),
        }
    }
}

async fn serve_stream<C, B>(
    server: Arc<GnmiServer<C, B>>,
    principal: TrustedPrincipal,
    plan: SubscribePlan,
    mut inbound: Streaming<gnmi::SubscribeRequest>,
    outbound: mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
) -> Result<(), GnmiError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    let mut dedupe = SnapshotDedupe::default();
    if !plan.updates_only
        && !send_snapshot(
            server.as_ref(),
            &principal,
            &plan,
            &outbound,
            &mut dedupe,
            true,
        )
        .await?
    {
        return Ok(());
    }
    send_sync(&outbound).await?;

    let queue_capacity = subscribe_queue_capacity(server.limits())?;
    let config_rx = plan
        .stream
        .as_ref()
        .filter(|stream| stream.has_on_change)
        .map(|_| {
            server
                .binding()
                .config_bus()
                .subscribe(SubscriberLagPolicy::ForceResync, queue_capacity)
        });
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
                validate_extensions(server.extensions(), &request.extension)?;
                match request.request {
                    Some(gnmi::subscribe_request::Request::Poll(_)) => {
                        return Err(GnmiError::invalid("poll request sent to STREAM subscription"));
                    }
                    Some(gnmi::subscribe_request::Request::Subscribe(_)) => {
                        return Err(GnmiError::invalid("gNMI Subscribe stream cannot replace an active subscription"));
                    }
                    None => return Err(GnmiError::invalid("empty gNMI Subscribe request")),
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
                        if !send_snapshot(server.as_ref(), &principal, &plan, &outbound, &mut dedupe, false).await? {
                            return Ok(());
                        }
                    }
                    Some(ConfigEvent::ResyncRequired { .. }) => {
                        if !send_snapshot(server.as_ref(), &principal, &plan, &outbound, &mut dedupe, true).await? {
                            return Ok(());
                        }
                        send_sync(&outbound).await?;
                    }
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
                if !send_snapshot(server.as_ref(), &principal, &plan, &outbound, &mut dedupe, !suppress).await? {
                    return Ok(());
                }
            }
            _ = async {
                match heartbeat.as_mut() {
                    Some(heartbeat) => heartbeat.tick().await,
                    None => future::pending().await,
                }
            }, if heartbeat.is_some() => {
                if !send_snapshot(server.as_ref(), &principal, &plan, &outbound, &mut dedupe, true).await? {
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

async fn send_snapshot<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    plan: &SubscribePlan,
    outbound: &mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    dedupe: &mut SnapshotDedupe,
    force: bool,
) -> Result<bool, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let responses = render_snapshot_responses(server, principal, plan)?;
    if responses.is_empty() {
        return Ok(true);
    }
    let fingerprint = fingerprint_responses(&responses);
    if !force && dedupe.last.as_ref() == Some(&fingerprint) {
        return Ok(true);
    }
    for response in responses {
        if outbound.send(Ok(response)).await.is_err() {
            return Ok(false);
        }
    }
    dedupe.last = Some(fingerprint);
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
    let response = handle_read_request(
        server,
        principal,
        &plan.get_request,
        ReadAction::Subscribe,
        GnmiNacmAction::Subscribe,
    )?;
    Ok(response
        .notification
        .into_iter()
        .map(|notification| gnmi::SubscribeResponse {
            response: Some(gnmi::subscribe_response::Response::Update(notification)),
            extension: Vec::new(),
        })
        .collect())
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

fn fingerprint_responses(responses: &[gnmi::SubscribeResponse]) -> Vec<u8> {
    let mut out = Vec::new();
    for response in responses {
        response
            .encode_length_delimited(&mut out)
            .expect("encoding SubscribeResponse to Vec cannot fail");
    }
    out
}

#[derive(Default)]
struct SnapshotDedupe {
    last: Option<Vec<u8>>,
}

/// Parsed and validated Subscribe request plan.
#[derive(Debug, Clone)]
pub(crate) struct SubscribePlan {
    mode: SubscribeListMode,
    updates_only: bool,
    get_request: gnmi::GetRequest,
    stream: Option<StreamPlan>,
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
                "gNMI Subscribe QoS marking is not implemented",
            ));
        }
        if list.allow_aggregation {
            return Err(GnmiError::unimplemented(
                "gNMI Subscribe aggregation is not implemented",
            ));
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
        })
    }

    const fn metric_mode(&self) -> SubscribeModeMetric {
        match self.mode {
            SubscribeListMode::Once => SubscribeModeMetric::Once,
            SubscribeListMode::Poll => SubscribeModeMetric::Poll,
            SubscribeListMode::Stream => SubscribeModeMetric::Stream,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscribeListMode {
    Once,
    Poll,
    Stream,
}

#[derive(Debug, Clone)]
struct StreamPlan {
    has_on_change: bool,
    sample_interval: Option<Duration>,
    heartbeat_interval: Option<Duration>,
    suppress_redundant: bool,
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
                    nanos(subscription.sample_interval)?,
                ));
            }
            Ok(gnmi::SubscriptionMode::TargetDefined) => {
                return Err(GnmiError::unimplemented(
                    "gNMI TARGET_DEFINED subscriptions are not implemented",
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
                nanos(subscription.heartbeat_interval)?,
            ));
        }
    }

    if has_on_change && !subscription_paths_are_config_only(server, list)? {
        return Err(GnmiError::unimplemented(
            "gNMI operational on-change subscriptions are not implemented",
        ));
    }
    Ok(StreamPlan {
        has_on_change,
        sample_interval,
        heartbeat_interval,
        suppress_redundant,
    })
}

fn subscription_paths_are_config_only<C, B>(
    server: &GnmiServer<C, B>,
    list: &gnmi::SubscriptionList,
) -> Result<bool, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let prefix = list.prefix.as_ref().map(path_from_proto).transpose()?;
    for subscription in &list.subscription {
        let path = subscription
            .path
            .as_ref()
            .map(path_from_proto)
            .transpose()?
            .unwrap_or_default();
        if path.elems.is_empty() {
            return Ok(false);
        }
        let resolved = crate::resolve_path(server.binding().schema(), prefix.as_ref(), &path)?;
        for node in server.binding().schema().nodes() {
            let under_root = node.path == resolved.schema_path.as_str()
                || node
                    .path
                    .strip_prefix(resolved.schema_path.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'));
            if under_root && !node.config {
                return Ok(false);
            }
        }
    }
    Ok(true)
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
