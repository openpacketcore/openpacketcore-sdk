#![allow(dead_code, unused_imports)]

#[path = "../support/schema_support.rs"]
pub mod schema_support;

pub use opc_evidence::ConformanceStatus;
pub use opc_testbed::evidence::{ScenarioEvidence, ScenarioOutcome};
pub use opc_testbed::simulators::fake::{FakeSimulator, Fidelity};
pub use opc_testbed::*;
pub use opc_types::Timestamp;
pub use std::collections::HashMap;
pub use std::str::FromStr;

pub const SCENARIO_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc012/v1/scenario.schema.json"
));
