//! Deterministic dataplane traffic and packet-continuity testkit.
//!
//! The crate is intentionally pure and deterministic: callers inject
//! timestamps and choose which packets are delivered. No unit test needs real
//! network sockets, clocks, or random numbers.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod evidence;
pub mod gtpu;
pub mod measurement;
pub mod reflector;
pub mod traffic;

pub use error::DataplaneTestkitError;
pub use evidence::{
    LatencySummary, PacketContinuityBudget, PacketContinuityReport,
    PACKET_CONTINUITY_SCHEMA_VERSION,
};
pub use gtpu::{
    decode_gtpu, encode_echo_request, encode_gpdu, encode_gpdu_with_extensions,
    validate_error_indication_ies, GTPU_MSG_ECHO_REQUEST, GTPU_MSG_ECHO_RESPONSE,
    GTPU_MSG_END_MARKER, GTPU_MSG_ERROR_INDICATION, GTPU_MSG_GPDU,
    GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION, GTPU_UDP_PORT,
};
pub use measurement::{
    build_measurement_tpdu, decode_measurement_tpdu, echo_tpdu, DecodedTpdu, InnerIpFlow,
    MeasurementHeader, MEASUREMENT_HEADER_LEN, MEASUREMENT_MAGIC,
};
pub use opc_proto_gtpu::GTPU_EXT_PDU_SESSION_CONTAINER;
pub use reflector::{
    GtpuReflector, MultiSessionReflectorConfig, ReflectorAction, ReflectorConfig, ReflectorPolicy,
    ReflectorSendReason, ReflectorSession, ReflectorStats, RouteTarget, MAX_REFLECTOR_SESSIONS,
};
pub use traffic::{
    ContinuityObserver, GeneratedPacket, GtpuReturnDatagramOutcome, TrafficEngine, TrafficPlan,
};
