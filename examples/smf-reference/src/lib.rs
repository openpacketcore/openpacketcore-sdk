//! Reference SMF consumer for the OpenPacketCore SDK.
//!
//! This is a deliberately bounded control-plane skeleton: it exercises the
//! SDK's runtime chassis, SBI/NRF client, PFCP codec, and session store from
//! outside the workspace. It is not a product-grade SMF.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use opc_alarm::SharedAlarmManager;
use opc_proto_pfcp::ie::{
    ApplyAction, Cause, CauseValue, CreateFar, CreatePdr, CreateQer, DestinationInterface,
    DurationMeasurement, FSeid, FarId, ForwardingParameters, Gate, GateStatus, Gbr, Mbr,
    NetworkInstance, NodeId, NodeIdType, OuterHeaderCreation, Pdi, PdrId, Precedence, QerId, Qfi,
    RemovePdr, ReportType, SourceInterface, TypedIe, UpdateFar, UpdateForwardingParameters, UrSeqn,
    UrrId, UsageReport, UsageReportTrigger, VolumeMeasurement,
};
use opc_proto_pfcp::{Header, InformationElement, MessageType, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use opc_runtime::{
    Criticality, Readiness, RuntimeError, RuntimeHandle, RuntimeProfile, Supervisor, TaskError,
    TaskKind, TaskSpec,
};
use opc_sbi::nrf::{HeartbeatDriver, NfProfile, NfStatus, NrfClient, NrfOperations};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend, Generation,
    LeaseError, OwnedSession, OwnerId, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, SessionStore, StateClass, StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, NfInstanceId, NfType, PlmnId, Snssai, TenantId};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};

/// Errors surfaced by the reference SMF.
#[derive(Debug, Error)]
pub enum SmfError {
    /// Runtime-level failure.
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),
    /// I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// PFCP encode failure.
    #[error("pfcp encode error: {0}")]
    PfcpEncode(String),
    /// PFCP decode failure.
    #[error("pfcp decode error: {0}")]
    PfcpDecode(String),
    /// Session store failure.
    #[error("session store error: {0}")]
    SessionStore(String),
    /// Lease failure.
    #[error("lease error: {0}")]
    Lease(String),
    /// NRF registration failure.
    #[error("nrf error: {0}")]
    Nrf(String),
    /// Identifier parse failure.
    #[error("identifier error: {0}")]
    Identifier(String),
    /// Socket address parse failure.
    #[error("address parse error: {0}")]
    AddrParse(String),
}

impl From<opc_protocol::EncodeError> for SmfError {
    fn from(e: opc_protocol::EncodeError) -> Self {
        SmfError::PfcpEncode(e.to_string())
    }
}

impl From<opc_protocol::DecodeError> for SmfError {
    fn from(e: opc_protocol::DecodeError) -> Self {
        SmfError::PfcpDecode(e.to_string())
    }
}

impl From<opc_session_store::StoreError> for SmfError {
    fn from(e: opc_session_store::StoreError) -> Self {
        SmfError::SessionStore(e.to_string())
    }
}

impl From<opc_session_store::LeaseError> for SmfError {
    fn from(e: opc_session_store::LeaseError) -> Self {
        SmfError::Lease(e.to_string())
    }
}

impl From<opc_types::ParseError> for SmfError {
    fn from(e: opc_types::ParseError) -> Self {
        SmfError::Identifier(e.to_string())
    }
}

/// Reference SMF configuration.
#[derive(Debug, Clone)]
pub struct SmfConfig {
    /// Local N4 endpoint address.
    pub n4_addr: SocketAddr,
    /// Remote UPF N4 endpoint address.
    pub upf_addr: SocketAddr,
    /// NRF base URI (scheme + authority, no trailing slash).
    pub nrf_uri: String,
    /// PLMN served by this SMF.
    pub plmn: PlmnId,
    /// S-NSSAI served by this SMF.
    pub s_nssai: Snssai,
    /// SMF instance identifier.
    pub instance_id: NfInstanceId,
}

impl SmfConfig {
    /// A default reference configuration for local loopback testing.
    pub fn default_ref() -> Result<Self, SmfError> {
        Ok(Self {
            n4_addr: "127.0.0.1:8805"
                .parse()
                .map_err(|e: std::net::AddrParseError| SmfError::AddrParse(e.to_string()))?,
            upf_addr: "127.0.0.1:8806"
                .parse()
                .map_err(|e: std::net::AddrParseError| SmfError::AddrParse(e.to_string()))?,
            nrf_uri: "http://127.0.0.1:8000".to_string(),
            plmn: PlmnId::new("001", "01")?,
            s_nssai: Snssai::with_sd(1, "010203")?,
            instance_id: NfInstanceId::new("smf-ref-01")?,
        })
    }
}

/// A PFCP association state tracked by the reference SMF.
#[derive(Debug, Clone, Default)]
pub struct PfcpAssociationState {
    /// Whether an association is established with the peer.
    pub associated: bool,
    /// Local F-SEID used for this association.
    pub local_fseid: Option<u64>,
}

/// A single PDU session stored in the session store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PduSessionRecord {
    /// Local SEID for this session.
    pub local_seid: u64,
    /// Remote SEID for this session (from Created PDR).
    pub remote_seid: u64,
    /// PDR IDs allocated.
    pub pdr_ids: Vec<u16>,
    /// FAR IDs allocated.
    pub far_ids: Vec<u32>,
    /// QER IDs allocated.
    pub qer_ids: Vec<u32>,
}

/// Reference SMF handle.
pub struct Smf {
    config: SmfConfig,
    runtime: RuntimeHandle,
    next_seid: Arc<Mutex<u64>>,
    store: SessionStore<FakeSessionBackend>,
    owner: OwnerId,
    // Held for the lifetime of the SMF: keeps the instance-ownership lease
    // renewed in the background. Renewal failures surface through the
    // supervised "store-lease" watch task.
    #[allow(dead_code)]
    ownership: OwnedSession<FakeSessionBackend>,
    // Outbound N4 message channel: consumed by the N4 worker task.
    n4_out: mpsc::UnboundedSender<OwnedMessage>,
}

impl std::fmt::Debug for Smf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smf")
            .field("config", &self.config)
            .field("owner", &self.owner)
            .finish()
    }
}

impl Smf {
    /// Build and start a reference SMF using the supplied configuration.
    pub async fn start(config: SmfConfig) -> Result<Self, SmfError> {
        let profile = RuntimeProfile::conformance("smf");
        let alarm_manager = SharedAlarmManager::default();

        let store = SessionStore::new(FakeSessionBackend::new());
        let owner = OwnerId::new(config.instance_id.as_str().to_string())
            .map_err(SmfError::SessionStore)?;

        let (ownership, ownership_failures) = OwnedSession::acquire(
            store.clone(),
            ownership_key(&owner)?,
            owner.clone(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await?;
        write_ownership_marker(&store, &ownership).await?;

        let nrf_client: Arc<NrfClient> = Arc::new(
            NrfClient::with_default_client(config.nrf_uri.clone()).map_err(SmfError::Nrf)?,
        );
        let nrf_drain_hook =
            opc_sbi::nrf::NrfDrainHook::new(nrf_client.clone(), config.instance_id.clone());

        let (n4_out_tx, n4_out_rx) = mpsc::unbounded_channel();

        let config_clone = config.clone();
        let nrf_client_clone: Arc<dyn NrfOperations> = nrf_client.clone();

        let runtime = opc_runtime::Builder::new(profile)
            .with_alarm_manager(alarm_manager)
            .with_drain_hook(Arc::new(nrf_drain_hook))
            .with_init(move |supervisor: Supervisor, shutdown| {
                Box::pin(async move {
                    if let Err(e) = spawn_n4_task(
                        supervisor.clone(),
                        shutdown.clone(),
                        config_clone.clone(),
                        n4_out_rx,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "failed to spawn n4 task");
                    }
                    if let Err(e) = spawn_nrf_task(
                        supervisor.clone(),
                        shutdown.clone(),
                        config_clone.clone(),
                        nrf_client_clone,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "failed to spawn nrf task");
                    }
                    if let Err(e) =
                        spawn_lease_watch_task(supervisor.clone(), ownership_failures).await
                    {
                        tracing::error!(error = %e, "failed to spawn lease watch task");
                    }
                })
            })
            .build()
            .await?;

        Ok(Self {
            config,
            runtime,
            next_seid: Arc::new(Mutex::new(1)),
            store,
            owner,
            ownership,
            n4_out: n4_out_tx,
        })
    }

    /// Allocate a fresh local SEID.
    pub async fn allocate_seid(&self) -> u64 {
        let mut guard = self.next_seid.lock().await;
        let seid = *guard;
        *guard = guard.saturating_add(1);
        seid
    }

    /// Send a PFCP message to the configured UPF over the N4 socket.
    ///
    /// The message is handed to the supervised N4 worker for encoding and
    /// transmission, so the same local endpoint is used for outbound requests
    /// and inbound responses.
    pub fn send_pfcp(&self, msg: OwnedMessage) -> Result<(), SmfError> {
        self.n4_out
            .send(msg)
            .map_err(|_| SmfError::PfcpEncode("N4 outbound channel closed".to_string()))
    }

    /// Create a PDU session record in the session store.
    ///
    /// Each PDU session record is written under its own short-lived lease;
    /// the long-lived [`OwnedSession`] covers only the instance-ownership
    /// marker.
    pub async fn create_session(&self) -> Result<u64, SmfError> {
        let seid = self.allocate_seid().await;
        let key = session_key(&self.owner, seid)?;
        let lease = self
            .store
            .acquire(&key, self.owner.clone(), Duration::from_secs(60))
            .await?;
        let record = PduSessionRecord {
            local_seid: seid,
            remote_seid: 0,
            pdr_ids: vec![1],
            far_ids: vec![1],
            qer_ids: vec![1],
        };
        let stored = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: self.owner.clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from(
                serde_json::to_vec(&record).map_err(|e| SmfError::SessionStore(e.to_string()))?,
            )),
        };
        match self
            .store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: stored,
            })
            .await?
        {
            CompareAndSetResult::Success => Ok(seid),
            CompareAndSetResult::Conflict { .. } => {
                Err(SmfError::SessionStore("session already exists".to_string()))
            }
        }
    }

    /// Read a PDU session record from the session store.
    pub async fn get_session(&self, seid: u64) -> Result<Option<PduSessionRecord>, SmfError> {
        let key = session_key(&self.owner, seid)?;
        let maybe_record = self.store.get(&key).await?;
        match maybe_record {
            Some(record) => {
                let bytes = record.payload.as_bytes();
                let pdu = serde_json::from_slice(bytes).map_err(|e| {
                    SmfError::SessionStore(format!("failed to decode session payload: {e}"))
                })?;
                Ok(Some(pdu))
            }
            None => Ok(None),
        }
    }

    /// Return the runtime readiness state.
    pub async fn readiness(&self) -> Readiness {
        self.runtime.readiness().await
    }

    /// Initiate graceful shutdown.
    pub async fn shutdown(self) {
        self.runtime.shutdown().await;
    }
}

fn ownership_key(owner: &OwnerId) -> Result<SessionKey, SmfError> {
    Ok(SessionKey {
        tenant: TenantId::from_static("ref-smf"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::other("smf-ownership").map_err(SmfError::SessionStore)?,
        stable_id: opc_session_store::StableId::new(Bytes::copy_from_slice(
            owner.as_str().as_bytes(),
        ))
        .map_err(|error| SmfError::SessionStore(error.to_string()))?,
    })
}

fn session_key(owner: &OwnerId, seid: u64) -> Result<SessionKey, SmfError> {
    let mut stable_id = owner.as_str().as_bytes().to_vec();
    stable_id.extend_from_slice(&seid.to_be_bytes());
    Ok(SessionKey {
        tenant: TenantId::from_static("ref-smf"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: opc_session_store::StableId::new(Bytes::from(stable_id))
            .map_err(|error| SmfError::SessionStore(error.to_string()))?,
    })
}

fn build_smf_profile(config: &SmfConfig) -> NfProfile {
    NfProfile {
        nf_instance_id: config.instance_id.clone(),
        nf_type: NfType::smf(),
        nf_status: NfStatus::Registered,
        ipv4_addresses: vec![config.n4_addr.ip().to_string()],
        fqdn: None,
        plmn_list: vec![config.plmn.clone()],
        s_nssais: vec![config.s_nssai.clone()],
        nf_services: vec![opc_sbi::nrf::services::NSMF_PDUSESSION.to_string()],
        priority: 10,
        capacity: 100,
    }
}

/// Register the SMF profile with the NRF and start the heartbeat driver.
async fn spawn_nrf_task(
    supervisor: Supervisor,
    shutdown: opc_runtime::ShutdownToken,
    config: SmfConfig,
    nrf_client: Arc<dyn NrfOperations>,
) -> Result<(), SmfError> {
    let profile = build_smf_profile(&config);
    let interval = nrf_client.register(&profile).await.map_err(SmfError::Nrf)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (degraded_tx, _degraded_rx) = watch::channel(false);

    let driver = HeartbeatDriver::new(
        nrf_client.clone(),
        config.instance_id.clone(),
        interval,
        shutdown_rx,
        degraded_tx,
    );

    supervisor
        .spawn_spec(TaskSpec::new(
            "nrf-heartbeat",
            TaskKind::BackgroundSync,
            Criticality::Degrade,
            async move {
                tokio::select! {
                    _ = driver.run() => Ok(()),
                    _ = shutdown.shutdown_acknowledged() => {
                        let _ = shutdown_tx.send(true);
                        Ok(())
                    }
                }
            },
        ))
        .await
        .map_err(SmfError::Runtime)?;

    Ok(())
}

/// Watch the ownership lease's renewal channel under supervision.
///
/// [`OwnedSession`] renews the lease in the background; this task turns a
/// renewal failure into a degrade-criticality task failure so the runtime
/// sees the loss of write authority. A closed channel means the owned
/// session was released or dropped during shutdown, which is a clean exit.
async fn spawn_lease_watch_task(
    supervisor: Supervisor,
    mut failures: watch::Receiver<Result<(), LeaseError>>,
) -> Result<(), SmfError> {
    supervisor
        .spawn_spec(TaskSpec::new(
            "store-lease",
            TaskKind::BackgroundSync,
            Criticality::Degrade,
            async move {
                loop {
                    if failures.changed().await.is_err() {
                        return Ok(());
                    }
                    let failure = failures.borrow_and_update().as_ref().err().cloned();
                    if let Some(e) = failure {
                        tracing::warn!(error = %e, "store lease renewal failed");
                        return Err(TaskError::Failed(
                            "lease renewal failed".to_string(),
                            Arc::new(e),
                        ));
                    }
                }
            },
        ))
        .await
        .map_err(SmfError::Runtime)?;
    Ok(())
}

/// Spawn the N4 UDP endpoint task.
async fn spawn_n4_task(
    supervisor: Supervisor,
    shutdown: opc_runtime::ShutdownToken,
    config: SmfConfig,
    n4_out_rx: mpsc::UnboundedReceiver<OwnedMessage>,
) -> Result<(), SmfError> {
    supervisor
        .spawn_spec(TaskSpec::new(
            "n4-udp",
            TaskKind::Listener,
            Criticality::Fatal,
            n4_worker(config, shutdown, n4_out_rx),
        ))
        .await
        .map_err(SmfError::Runtime)?;
    Ok(())
}

/// Write the SMF ownership marker using the owned-session lease.
async fn write_ownership_marker(
    store: &SessionStore<FakeSessionBackend>,
    ownership: &OwnedSession<FakeSessionBackend>,
) -> Result<(), SmfError> {
    let key = ownership.key().clone();
    let lease = ownership.lease().lock().await;
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: ownership.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::EphemeralProcedure,
        state_type: StateType::from_static("smf-ownership"),
        // The marker must not outlive the lease that authorizes this owner.
        expires_at: Some(lease.expires_at()),
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"smf-ref-ok")),
    };

    match store
        .compare_and_set(CompareAndSet {
            key,
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await?
    {
        CompareAndSetResult::Success => Ok(()),
        CompareAndSetResult::Conflict { .. } => {
            tracing::warn!("ownership marker already present in store");
            Ok(())
        }
    }
}

async fn n4_worker(
    config: SmfConfig,
    shutdown: opc_runtime::ShutdownToken,
    mut n4_out_rx: mpsc::UnboundedReceiver<OwnedMessage>,
) -> Result<(), TaskError> {
    let socket = Arc::new(
        UdpSocket::bind(config.n4_addr)
            .await
            .map_err(|e| TaskError::Failed("n4 bind failed".to_string(), Arc::new(e)))?,
    );
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            res = socket.recv_from(&mut buf) => {
                let (len, peer) = res.map_err(|e| TaskError::Failed("n4 recv failed".to_string(), Arc::new(e)))?;
                let data = &buf[..len];
                if let Err(e) = handle_n4_message(&socket, peer, data).await {
                    tracing::warn!(error = %e, peer = %peer, "n4 message handling failed");
                }
            }
            maybe_msg = n4_out_rx.recv() => {
                match maybe_msg {
                    Some(msg) => {
                        let mut out = BytesMut::new();
                        if let Err(e) = msg.encode(&mut out, EncodeContext::default()) {
                            tracing::warn!(error = %e, "failed to encode outbound N4 message");
                            continue;
                        }
                        if let Err(e) = socket.send_to(&out, config.upf_addr).await {
                            tracing::warn!(error = %e, "failed to send outbound N4 message");
                        }
                    }
                    None => {
                        tracing::info!("n4 outbound channel closed");
                        break;
                    }
                }
            }
            _ = shutdown.shutdown_acknowledged() => {
                tracing::info!("n4 worker shutting down");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_n4_message(
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    data: &[u8],
) -> Result<(), SmfError> {
    let ctx = DecodeContext::default();
    let (_, msg) = opc_proto_pfcp::Message::decode(data, ctx)?;
    let response = match msg.header.message_type {
        t if t == MessageType::HeartbeatRequest as u8 => Some(opc_proto_pfcp::heartbeat_response(
            msg.header.sequence_number,
        )),
        t if t == MessageType::HeartbeatResponse as u8 => {
            tracing::debug!("heartbeat response from {peer}");
            None
        }
        t if t == MessageType::AssociationSetupRequest as u8 => {
            Some(association_setup_response(msg.header.sequence_number)?)
        }
        t if t == MessageType::AssociationReleaseRequest as u8 => {
            Some(association_release_response(msg.header.sequence_number)?)
        }
        t if t == MessageType::SessionEstablishmentRequest as u8 => {
            Some(session_establishment_response(msg.header.sequence_number)?)
        }
        t if t == MessageType::SessionModificationRequest as u8 => {
            Some(session_modification_response(msg.header.sequence_number)?)
        }
        t if t == MessageType::SessionDeletionRequest as u8 => {
            Some(session_deletion_response(msg.header.sequence_number)?)
        }
        t if t == MessageType::SessionReportRequest as u8 => Some(session_report_response(
            msg.header.sequence_number,
            msg.header.seid.unwrap_or(0),
        )?),
        other => {
            tracing::warn!(msg_type = other, "unhandled PFCP message type");
            None
        }
    };

    if let Some(resp) = response {
        let mut out = BytesMut::new();
        resp.encode(&mut out, EncodeContext::default())?;
        socket.send_to(&out, peer).await?;
    }
    Ok(())
}

fn association_setup_response(seq: u32) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: false,
            message_type: MessageType::AssociationSetupResponse as u8,
            length: 0,
            seid: None,
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![
            InformationElement::from_typed(&TypedIe::NodeId(NodeId {
                node_id_type: NodeIdType::Fqdn,
                value: b"ref".to_vec(),
            }))?,
            InformationElement::from_typed(&TypedIe::Cause(Cause {
                value: CauseValue::RequestAccepted,
            }))?,
        ],
    })
}

fn association_release_response(seq: u32) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: false,
            message_type: MessageType::AssociationReleaseResponse as u8,
            length: 0,
            seid: None,
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![InformationElement::from_typed(&TypedIe::Cause(Cause {
            value: CauseValue::RequestAccepted,
        }))?],
    })
}

fn session_establishment_response(seq: u32) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionEstablishmentResponse as u8,
            length: 0,
            seid: Some(1),
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![
            InformationElement::from_typed(&TypedIe::NodeId(NodeId {
                node_id_type: NodeIdType::Fqdn,
                value: b"ref".to_vec(),
            }))?,
            InformationElement::from_typed(&TypedIe::Cause(Cause {
                value: CauseValue::RequestAccepted,
            }))?,
            InformationElement::from_typed(&TypedIe::FSeid(FSeid {
                v4: true,
                v6: false,
                seid: 1,
                ipv4: Some([127, 0, 0, 1]),
                ipv6: None,
            }))?,
        ],
    })
}

fn session_modification_response(seq: u32) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionModificationResponse as u8,
            length: 0,
            seid: Some(1),
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![InformationElement::from_typed(&TypedIe::Cause(Cause {
            value: CauseValue::RequestAccepted,
        }))?],
    })
}

fn session_deletion_response(seq: u32) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionDeletionResponse as u8,
            length: 0,
            seid: Some(1),
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![InformationElement::from_typed(&TypedIe::Cause(Cause {
            value: CauseValue::RequestAccepted,
        }))?],
    })
}

fn session_report_response(seq: u32, seid: u64) -> Result<OwnedMessage, SmfError> {
    Ok(OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionReportResponse as u8,
            length: 0,
            seid: Some(seid),
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![InformationElement::from_typed(&TypedIe::Cause(Cause {
            value: CauseValue::RequestAccepted,
        }))?],
    })
}

/// Build a Create PDR IE from a static rule template.
///
/// This is the primary SDK API exercised by the SMF: it composes typed IEs
/// and encodes them through the PFCP typed layer.
pub fn build_create_pdr(pdr_id: u16, precedence: u32, far_id: u32) -> Result<TypedIe, SmfError> {
    let pdi = Pdi {
        members: vec![
            TypedIe::SourceInterface(SourceInterface {
                value: 0, // Access
                spare: 0,
            }),
            TypedIe::NetworkInstance(NetworkInstance {
                value: b"internet".to_vec(),
            }),
        ],
    };

    let create_pdr = CreatePdr {
        members: vec![
            TypedIe::PdrId(PdrId { value: pdr_id }),
            TypedIe::Precedence(Precedence { value: precedence }),
            TypedIe::Pdi(pdi),
            TypedIe::FarId(FarId { value: far_id }),
        ],
    };

    Ok(TypedIe::CreatePdr(create_pdr))
}

/// Build a Create FAR IE from a static rule template.
pub fn build_create_far(
    far_id: u32,
    drop: bool,
    forward: bool,
    dst_interface: Option<u8>,
) -> Result<TypedIe, SmfError> {
    let mut members = vec![
        TypedIe::FarId(FarId { value: far_id }),
        TypedIe::ApplyAction(ApplyAction {
            drop,
            forward,
            buffer: false,
            notify_cp: false,
            duplicate: false,
            ip_masquerade: false,
            ip_masquerade_decap: false,
            dfrt: false,
            edrt: false,
            bdpn: false,
            ddpn: false,
            spare: 0,
        }),
    ];

    if let Some(iface) = dst_interface {
        members.push(TypedIe::ForwardingParameters(ForwardingParameters {
            members: vec![
                TypedIe::DestinationInterface(DestinationInterface {
                    value: iface,
                    spare: 0,
                }),
                TypedIe::NetworkInstance(NetworkInstance {
                    value: b"internet".to_vec(),
                }),
                TypedIe::OuterHeaderCreation(OuterHeaderCreation {
                    description: 0x0100, // GTP-U/UDP/IPv4
                    teid: Some(0x1234_5678),
                    ipv4: Some([10, 0, 0, 1]),
                    ipv6: None,
                    port: None,
                    c_tag: None,
                    s_tag: None,
                }),
            ],
        }));
    }

    Ok(TypedIe::CreateFar(CreateFar { members }))
}

/// Build a Create QER IE from a static QoS template.
///
/// This exercises the typed QoS IEs added in P2: Gate Status, MBR, GBR, QFI.
pub fn build_create_qer(qer_id: u32, qfi: u8) -> Result<TypedIe, SmfError> {
    let qer = CreateQer {
        members: vec![
            TypedIe::QerId(QerId { value: qer_id }),
            TypedIe::GateStatus(GateStatus {
                ul: Gate::Open,
                dl: Gate::Open,
            }),
            TypedIe::Mbr(Mbr {
                ul_kbps: 1_000_000,
                dl_kbps: 2_000_000,
            }),
            TypedIe::Gbr(Gbr {
                ul_kbps: 500_000,
                dl_kbps: 1_000_000,
            }),
            TypedIe::Qfi(Qfi { value: qfi }),
        ],
    };

    Ok(TypedIe::CreateQer(qer))
}

/// Build an Update FAR IE that changes the destination interface and applies
/// forwarding parameters.
pub fn build_update_far(far_id: u32, dst_interface: u8) -> Result<TypedIe, SmfError> {
    let update_fwd = UpdateForwardingParameters {
        members: vec![
            TypedIe::DestinationInterface(DestinationInterface {
                value: dst_interface,
                spare: 0,
            }),
            TypedIe::NetworkInstance(NetworkInstance {
                value: b"internet".to_vec(),
            }),
            TypedIe::OuterHeaderCreation(OuterHeaderCreation {
                description: 0x0100, // GTP-U/UDP/IPv4
                teid: Some(0x1234_5678),
                ipv4: Some([10, 0, 0, 1]),
                ipv6: None,
                port: None,
                c_tag: None,
                s_tag: None,
            }),
        ],
    };

    let update_far = UpdateFar {
        members: vec![
            TypedIe::FarId(FarId { value: far_id }),
            TypedIe::ApplyAction(ApplyAction {
                drop: false,
                forward: true,
                buffer: false,
                notify_cp: false,
                duplicate: false,
                ip_masquerade: false,
                ip_masquerade_decap: false,
                dfrt: false,
                edrt: false,
                bdpn: false,
                ddpn: false,
                spare: 0,
            }),
            TypedIe::UpdateForwardingParameters(update_fwd),
        ],
    };

    Ok(TypedIe::UpdateFar(update_far))
}

/// Build a Remove PDR IE that removes a single PDR by ID.
pub fn build_remove_pdr(pdr_id: u16) -> Result<TypedIe, SmfError> {
    Ok(TypedIe::RemovePdr(RemovePdr {
        pdr_id: PdrId { value: pdr_id },
    }))
}

/// Build a Usage Report grouped IE for the Session Report flow.
pub fn build_usage_report(
    urr_id: u32,
    ur_seqn: u32,
    total_volume: u64,
    duration_seconds: u32,
) -> Result<TypedIe, SmfError> {
    let usage_report = UsageReport {
        members: vec![
            TypedIe::UrrId(UrrId { value: urr_id }),
            TypedIe::UrSeqn(UrSeqn { value: ur_seqn }),
            TypedIe::UsageReportTrigger(UsageReportTrigger {
                periodic_reporting: false,
                volume_threshold: false,
                time_threshold: false,
                quota_holding_time: false,
                start_of_traffic: false,
                stop_of_traffic: false,
                dropped_dl_traffic_threshold: false,
                immediate_report: true,
                volume_quota: false,
                time_quota: false,
                linked_usage_reporting: false,
                termination_report: false,
                monitoring_time: false,
                envelope_closure: false,
                mac_addresses_reporting: false,
                event_threshold: false,
                event_quota: false,
                termination_by_up_report: false,
                ip_multicast_join_leave: false,
                quota_validity_time: false,
                end_marker_reception_report: false,
                user_plane_inactivity_timer: false,
            }),
            TypedIe::VolumeMeasurement(VolumeMeasurement {
                total_volume: Some(total_volume),
                uplink_volume: None,
                downlink_volume: None,
                total_packets: None,
                uplink_packets: None,
                downlink_packets: None,
            }),
            TypedIe::DurationMeasurement(DurationMeasurement {
                seconds: duration_seconds,
            }),
        ],
    };

    Ok(TypedIe::UsageReport(usage_report))
}

/// Build a Session Report Request message carrying a typed Usage Report.
pub fn build_session_report_request(
    seq: u32,
    seid: u64,
    urr_id: u32,
    ur_seqn: u32,
    total_volume: u64,
    duration_seconds: u32,
) -> Result<OwnedMessage, SmfError> {
    let usage_report = build_usage_report(urr_id, ur_seqn, total_volume, duration_seconds)?;
    let mut msg = opc_proto_pfcp::session_report_request(seq, seid);
    msg.ies
        .push(InformationElement::from_typed(&TypedIe::ReportType(
            ReportType {
                downlink_data_report: false,
                usage_report: true,
                error_indication_report: false,
                user_plane_inactivity_report: false,
                tsc_management_info_report: false,
                session_report: false,
                up_initiated_session_request: false,
            },
        ))?);
    msg.ies.push(InformationElement::from_typed(&usage_report)?);
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_ownership_marker_uses_the_held_lease_deadline() -> Result<(), SmfError> {
        let store = SessionStore::new(FakeSessionBackend::new());
        let owner = OwnerId::new("smf-marker-test").map_err(SmfError::SessionStore)?;
        let key = ownership_key(&owner)?;
        let (ownership, _failures) = OwnedSession::acquire(
            store.clone(),
            key.clone(),
            owner,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await?;
        let expected_expiry = ownership.lease().lock().await.expires_at();

        write_ownership_marker(&store, &ownership).await?;

        let Some(record) = store.get(&key).await? else {
            panic!("ownership marker was not written");
        };
        assert_eq!(record.state_class, StateClass::EphemeralProcedure);
        assert_eq!(record.expires_at, Some(expected_expiry));

        ownership.release().await?;
        Ok(())
    }
}
