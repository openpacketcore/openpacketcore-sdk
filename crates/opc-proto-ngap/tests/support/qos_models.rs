//! Constructors from independent synthetic reference values, for semantic tests.
use opc_proto_ngap::n3iwf::qos_fields::*;
use opc_proto_ngap::n3iwf::resource_fields::QosFlowId;
use serde_json::Value;

pub fn parameters(model: &Value) -> QosParameters {
    let d = &model["descriptor"];
    let characteristics = if d["kind"] == "non_dynamic" {
        QosCharacteristics::NonDynamic(NonDynamicQos {
            five_qi: d["five_qi"].as_u64().unwrap() as u8,
            priority: d["priority"].as_u64().map(|v| v as u8),
            averaging_window: d["window"].as_u64().map(|v| v as u16),
            maximum_data_burst: d["burst"].as_u64().map(|v| v as u16),
        })
    } else {
        QosCharacteristics::Dynamic(DynamicQos {
            priority: d["priority"].as_u64().unwrap() as u8,
            packet_delay_budget: d["delay"].as_u64().unwrap() as u16,
            error_scalar: d["scalar"].as_u64().unwrap() as u8,
            error_exponent: d["exponent"].as_u64().unwrap() as u8,
            five_qi: d["five_qi"].as_u64().map(|v| v as u8),
            delay_critical: d["delay_critical"].as_bool(),
            averaging_window: d["window"].as_u64().map(|v| v as u16),
            maximum_data_burst: d["burst"].as_u64().map(|v| v as u16),
        })
    };
    let a = &model["arp"];
    QosParameters::new(
        characteristics,
        AllocationRetentionPriority::new(
            a["priority"].as_u64().unwrap() as u8,
            a["may_preempt"].as_bool().unwrap(),
            a["preemptable"].as_bool().unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .with_gbr(model.get("gbr").map(|v| GbrQosInformation {
        maximum_downlink: v["max_dl"].as_u64().unwrap(),
        maximum_uplink: v["max_ul"].as_u64().unwrap(),
        guaranteed_downlink: v["guaranteed_dl"].as_u64().unwrap(),
        guaranteed_uplink: v["guaranteed_ul"].as_u64().unwrap(),
        notification_control: v["notification"].as_bool().unwrap_or(false),
        maximum_packet_loss_downlink: v["loss_dl"].as_u64().map(|v| v as u16),
        maximum_packet_loss_uplink: v["loss_ul"].as_u64().map(|v| v as u16),
    }))
    .unwrap()
    .with_attributes(
        model["reflective"].as_bool().unwrap_or(false),
        model["additional"].as_bool().unwrap_or(false),
    )
}

pub fn flow(model: &Value) -> QosFlow {
    QosFlow::new(
        QosFlowId::new(model["qfi"].as_u64().unwrap() as u8).unwrap(),
        parameters(&model["parameters"]),
    )
    .with_erab(model["erab"].as_u64().map(|v| v as u8))
    .unwrap()
}
