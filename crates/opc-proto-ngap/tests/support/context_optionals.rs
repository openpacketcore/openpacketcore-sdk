use opc_proto_ngap::n3iwf::context_fields::PartiallyAllowedNssai;
use opc_proto_ngap::n3iwf::nas_fields::{ExtendedAmfName, MaskedImeisv};
use opc_proto_ngap::n3iwf::resource_setup::InitialContextRequest;
use opc_proto_ngap::n3iwf::setup_fields::AmfName;
use opc_proto_ngap::n3iwf::trace_fields::{TraceActivation, TraceDepth};
use opc_protocol::{DecodeContext, EncodeContext};

fn trace(value: TraceActivation) -> TraceActivation {
    TraceActivation::new(
        *value.trace_id(),
        value.interfaces(),
        TraceDepth::new(value.depth().value()).unwrap(),
        value.address_bits(),
        value.address(),
    )
    .unwrap()
}

pub fn reconstruct(value: &mut InitialContextRequest<'_>) {
    value.old_amf = value
        .old_amf
        .as_ref()
        .map(|v| AmfName::new(v.as_str()).unwrap());
    value.extended_old_amf = value
        .extended_old_amf
        .as_ref()
        .map(|v| ExtendedAmfName::new(v.visible(), v.utf8()).unwrap());
    value.partially_allowed_nssai = value
        .partially_allowed_nssai
        .as_ref()
        .map(|v| PartiallyAllowedNssai::new(v.values().to_vec()).unwrap());
    value.masked_imeisv = value
        .masked_imeisv
        .map(|v| MaskedImeisv::new(*v.as_bytes()));
    value.trace = value.trace.map(trace);
}

pub fn exercise_leaf(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = TraceActivation::decode(data, ctx) {
        let wire = trace(value).encode(output).unwrap();
        assert!(TraceActivation::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
}
