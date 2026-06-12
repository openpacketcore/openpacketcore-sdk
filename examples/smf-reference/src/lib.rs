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
    ApplyAction, CauseValue, CreateFar, CreatePdr, DestinationInterface, FSeid, FarId,
    ForwardingParameters, NetworkInstance, NodeIdType, OuterHeaderCreation, Pdi, PdrId, Precedence,
    SourceInterface, TypedIe,
};
use opc_proto_pfcp::{Header, InformationElement, MessageType, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use opc_runtime::{
    Criticality, Readiness, RuntimeError, RuntimeHandle, RuntimeProfile, Supervisor, TaskError,
    TaskKind, TaskSpec,
};
use opc_sbi::nrf::{
    HeartbeatDriver, NfProfile, NfStatus, NrfClient, NrfDeregNotifier, NrfOperations,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend, Generation,
    OwnerId, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, StateClass,
    StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, NfInstanceId, NfType, PlmnId, Snssai, TenantId};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};

/// Wrapper that implements [`NrfDeregNotifier`] for the concrete [`NrfClient`].
///
/// FRACTURE-JOURNAL: `NrfClient` implements `NrfOperations` but not
/// `NrfDeregNotifier`, even though it has a `deregister` method with the same
/// semantics. A reference consumer should not need this boilerplate to wire a
/// real NRF client into the runtime drain sequence.
pub struct NrfDeregWrapper(Arc<NrfClient>);

#[async_trait::async_trait]
impl NrfDeregNotifier for NrfDeregWrapper {
    async fn deregister(
        &self,
        nf_instance_id: &NfInstanceId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.deregister(nf_instance_id).await.map_err(|e| {
            Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send + Sync>
        })
    }
}

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
            s_nssai: Snssai::new(1, Some("010203"))?, // FRACTURE-JOURNAL: Snssai::new takes Option<impl Into<String>>, but the SD hex validation is strict; passing a &str works only because it impls Into<String>. A helper for literal SD would reduce friction.
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
    store: Arc<dyn SessionBackend>,
    lease_manager: Arc<dyn SessionLeaseManager>,
    owner: OwnerId,
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

        // FRACTURE-JOURNAL: SessionBackend and SessionLeaseManager are separate
        // traits, so a reference consumer must wrap the same backend twice. There
        // is no single "session store" handle that owns both storage and leases,
        // which makes it easy to accidentally split state across two backends.
        let store_backend = Arc::new(FakeSessionBackend::new());
        let store: Arc<dyn SessionBackend> = store_backend.clone();
        let lease_manager: Arc<dyn SessionLeaseManager> = store_backend;
        let owner = OwnerId::new(config.instance_id.as_str().to_string())
            .map_err(SmfError::SessionStore)?;

        let client = opc_sbi::client::SbiClientBuilder::new()
            .with_http2_only(false)
            .build()
            .map_err(SmfError::Nrf)?;
        let nrf_client: Arc<NrfClient> = Arc::new(NrfClient::new(client, config.nrf_uri.clone()));
        let nrf_dereg = Arc::new(NrfDeregWrapper(nrf_client.clone()));
        let nrf_drain_hook = opc_sbi::nrf::NrfDrainHook::new(nrf_dereg, config.instance_id.clone());

        let config_clone = config.clone();
        let store_clone = store.clone();
        let lease_clone = lease_manager.clone();
        let owner_clone = owner.clone();
        let nrf_client_clone: Arc<dyn NrfOperations> = nrf_client.clone();

        let runtime = opc_runtime::Builder::new(profile)
            .with_alarm_manager(alarm_manager)
            .with_drain_hook(Arc::new(nrf_drain_hook))
            .with_init(move |supervisor: Supervisor, shutdown| {
                Box::pin(async move {
                    if let Err(e) =
                        spawn_n4_task(supervisor.clone(), shutdown.clone(), config_clone.clone())
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
                    if let Err(e) = spawn_store_maintenance_task(
                        supervisor,
                        shutdown,
                        store_clone,
                        lease_clone,
                        owner_clone,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "failed to spawn store maintenance task");
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
            lease_manager,
            owner,
        })
    }

    /// Allocate a fresh local SEID.
    pub async fn allocate_seid(&self) -> u64 {
        let mut guard = self.next_seid.lock().await;
        let seid = *guard;
        *guard = guard.saturating_add(1);
        seid
    }

    /// Create a PDU session record in the session store.
    ///
    /// FRACTURE-JOURNAL: Every session-store write needs a `LeaseGuard`, which
    /// means a reference consumer must juggle lease acquisition/renewal per key
    /// even for simple test records. A higher-level "owned session" helper in
    /// opc-session-store would remove this boilerplate.
    pub async fn create_session(&self) -> Result<u64, SmfError> {
        let seid = self.allocate_seid().await;
        let key = session_key(&self.owner, seid)?;
        let lease = self
            .lease_manager
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
            state_type: StateType::new("pdu-session").map_err(SmfError::SessionStore)?,
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
    // FRACTURE-JOURNAL: TenantId::new and NetworkFunctionKind::new return Result, so even
    // deterministic literal keys need error handling. A const-construction path for
    // well-known tenant/NF-kind literals would remove noise in reference code.
    Ok(SessionKey {
        tenant: TenantId::new("ref-smf")?,
        nf_kind: NetworkFunctionKind::new("smf")?,
        key_type: SessionKeyType::Other("smf-ownership".to_string()),
        stable_id: Bytes::copy_from_slice(owner.as_str().as_bytes()),
    })
}

fn session_key(owner: &OwnerId, seid: u64) -> Result<SessionKey, SmfError> {
    let mut stable_id = owner.as_str().as_bytes().to_vec();
    stable_id.extend_from_slice(&seid.to_be_bytes());
    Ok(SessionKey {
        tenant: TenantId::new("ref-smf")?,
        nf_kind: NetworkFunctionKind::new("smf")?,
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(stable_id),
    })
}

fn build_smf_profile(config: &SmfConfig) -> Result<NfProfile, SmfError> {
    Ok(NfProfile {
        nf_instance_id: config.instance_id.clone(),
        nf_type: NfType::new("smf")?,
        nf_status: NfStatus::Registered,
        ipv4_addresses: vec![config.n4_addr.ip().to_string()],
        fqdn: None,
        plmn_list: vec![config.plmn.clone()],
        s_nssais: vec![config.s_nssai.clone()],
        nf_services: vec!["nsmf-pdusession".to_string()],
        priority: 10,
        capacity: 100,
    })
}

/// Register the SMF profile with the NRF and start the heartbeat driver.
async fn spawn_nrf_task(
    supervisor: Supervisor,
    shutdown: opc_runtime::ShutdownToken,
    config: SmfConfig,
    nrf_client: Arc<dyn NrfOperations>,
) -> Result<(), SmfError> {
    let profile = build_smf_profile(&config)?;
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

    // FRACTURE-JOURNAL: NrfDrainHook requires the notifier to implement NrfDeregNotifier.
    // MockNrf implements it, but NrfClient does not, so a real SMF cannot use the
    // runtime-hooks feature with NrfClient directly. We register the hook manually below
    // by constructing a notifier wrapper, which is extra boilerplate for a reference consumer.
    // The hook is registered on the runtime builder before `build`; here we only run the
    // heartbeat driver.

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

/// Spawn the N4 UDP endpoint task.
async fn spawn_n4_task(
    supervisor: Supervisor,
    shutdown: opc_runtime::ShutdownToken,
    config: SmfConfig,
) -> Result<(), SmfError> {
    supervisor
        .spawn_spec(TaskSpec::new(
            "n4-udp",
            TaskKind::Listener,
            Criticality::Fatal,
            n4_worker(config, shutdown),
        ))
        .await
        .map_err(SmfError::Runtime)?;
    Ok(())
}

/// Placeholder store-maintenance task: acquires and renews a lease for
/// the SMF's own ownership key so the session-store integration is real.
async fn spawn_store_maintenance_task(
    supervisor: Supervisor,
    _shutdown: opc_runtime::ShutdownToken,
    store: Arc<dyn SessionBackend>,
    lease_manager: Arc<dyn SessionLeaseManager>,
    owner: OwnerId,
) -> Result<(), SmfError> {
    let key = ownership_key(&owner)?;
    let lease = lease_manager
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await?;

    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner.clone(),
        fence: lease.fence(),
        state_class: StateClass::EphemeralProcedure,
        state_type: StateType::new("smf-ownership").map_err(SmfError::SessionStore)?,
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"smf-ref-ok")),
    };

    match store
        .compare_and_set(CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record,
        })
        .await?
    {
        CompareAndSetResult::Success => {}
        CompareAndSetResult::Conflict { .. } => {
            tracing::warn!("ownership marker already present in store");
        }
    }

    supervisor
        .spawn_spec(TaskSpec::new(
            "store-lease",
            TaskKind::BackgroundSync,
            Criticality::Degrade,
            store_lease_renewal_loop(lease_manager, owner),
        ))
        .await
        .map_err(SmfError::Runtime)?;

    Ok(())
}

async fn store_lease_renewal_loop(
    lease_manager: Arc<dyn SessionLeaseManager>,
    owner: OwnerId,
) -> Result<(), TaskError> {
    let key = ownership_key(&owner)
        .map_err(|e| TaskError::Failed("invalid ownership key".to_string(), Arc::new(e)))?;
    let mut lease = lease_manager
        .acquire(&key, owner, Duration::from_secs(60))
        .await
        .map_err(|e| TaskError::Failed("initial store lease failed".to_string(), Arc::new(e)))?;

    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        match lease_manager.renew(&lease, Duration::from_secs(60)).await {
            Ok(new_lease) => lease = new_lease,
            Err(e) => {
                tracing::warn!(error = %e, "store lease renewal failed");
                return Err(TaskError::Failed(
                    "lease renewal failed".to_string(),
                    Arc::new(e),
                ));
            }
        }
    }
}

async fn n4_worker(
    config: SmfConfig,
    shutdown: opc_runtime::ShutdownToken,
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
            Some(association_setup_response(msg.header.sequence_number))
        }
        t if t == MessageType::AssociationReleaseRequest as u8 => {
            Some(association_release_response(msg.header.sequence_number))
        }
        t if t == MessageType::SessionEstablishmentRequest as u8 => {
            Some(session_establishment_response(msg.header.sequence_number))
        }
        t if t == MessageType::SessionModificationRequest as u8 => {
            Some(session_modification_response(msg.header.sequence_number))
        }
        t if t == MessageType::SessionDeletionRequest as u8 => {
            Some(session_deletion_response(msg.header.sequence_number))
        }
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

fn association_setup_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
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
            InformationElement {
                ie_type: opc_proto_pfcp::IeType::NodeId as u16,
                enterprise_id: 0,
                value: Bytes::from(vec![u8::from(NodeIdType::Fqdn), b'r', b'e', b'f']),
            },
            InformationElement {
                ie_type: opc_proto_pfcp::IeType::Cause as u16,
                enterprise_id: 0,
                value: Bytes::from(vec![u8::from(CauseValue::RequestAccepted)]),
            },
        ],
    }
}

fn association_release_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
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
        ies: vec![InformationElement {
            ie_type: opc_proto_pfcp::IeType::Cause as u16,
            enterprise_id: 0,
            value: Bytes::from(vec![u8::from(CauseValue::RequestAccepted)]),
        }],
    }
}

fn session_establishment_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
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
            InformationElement {
                ie_type: opc_proto_pfcp::IeType::NodeId as u16,
                enterprise_id: 0,
                value: Bytes::from(vec![u8::from(NodeIdType::Fqdn), b'r', b'e', b'f']),
            },
            InformationElement {
                ie_type: opc_proto_pfcp::IeType::Cause as u16,
                enterprise_id: 0,
                value: Bytes::from(vec![u8::from(CauseValue::RequestAccepted)]),
            },
            InformationElement {
                ie_type: opc_proto_pfcp::IeType::FSeid as u16,
                enterprise_id: 0,
                value: encode_fseid_value(),
            },
        ],
    }
}

fn session_modification_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
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
        ies: vec![InformationElement {
            ie_type: opc_proto_pfcp::IeType::Cause as u16,
            enterprise_id: 0,
            value: Bytes::from(vec![u8::from(CauseValue::RequestAccepted)]),
        }],
    }
}

fn session_deletion_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
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
        ies: vec![InformationElement {
            ie_type: opc_proto_pfcp::IeType::Cause as u16,
            enterprise_id: 0,
            value: Bytes::from(vec![u8::from(CauseValue::RequestAccepted)]),
        }],
    }
}

fn encode_fseid_value() -> Bytes {
    let fseid = FSeid {
        v4: true,
        v6: false,
        seid: 1,
        ipv4: Some([127, 0, 0, 1]),
        ipv6: None,
    };
    let typed = TypedIe::FSeid(fseid);
    let mut ie_buf = BytesMut::new();
    // FRACTURE-JOURNAL: TypedIe::encode returns Result but the error type does not impl
    // Display in a way that lets us recover a value here. We decode the encoded IE to
    // strip the TLV header and return just the value bytes for the raw response path.
    match typed.encode(&mut ie_buf, EncodeContext::default()) {
        Ok(()) => match opc_proto_pfcp::InformationElement::decode(&ie_buf) {
            Ok((_, raw)) => raw.value,
            Err(_) => Bytes::new(),
        },
        Err(_) => Bytes::new(),
    }
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

/// Build a Create QER IE using raw member IEs when typed QoS IEs are not yet
/// available in the SDK (P1 honest workaround; P2 replaces with typed IEs).
pub fn build_create_qer_raw(qer_id: u32) -> Result<InformationElement, SmfError> {
    let mut value = BytesMut::new();
    // QER ID
    value.extend_from_slice(&[
        0x00, 0x6D, // QER ID IE type
        0x00, 0x04, // length
    ]);
    value.extend_from_slice(&qer_id.to_be_bytes());
    // Gate Status (open)
    value.extend_from_slice(&[
        0x00, 0x19, // Gate Status IE type
        0x00, 0x01, // length
        0x00, // both gates open
    ]);
    // MBR (UL+DL)
    value.extend_from_slice(&[
        0x00, 0x1A, // MBR IE type
        0x00, 0x0A, // length
    ]);
    value.extend_from_slice(&[0u8; 10]);
    // GBR (UL+DL)
    value.extend_from_slice(&[
        0x00, 0x1B, // GBR IE type
        0x00, 0x0A, // length
    ]);
    value.extend_from_slice(&[0u8; 10]);

    Ok(InformationElement {
        ie_type: opc_proto_pfcp::IeType::CreateQer as u16,
        enterprise_id: 0,
        value: value.freeze(),
    })
}
