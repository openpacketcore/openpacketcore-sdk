//! Public semantic reconstruction shared by bounded replay and actual fuzzing.
use opc_proto_ngap::n3iwf::reset_fields::{CriticalityDiagnostics, DiagnosticItems};
use opc_proto_ngap::n3iwf::resource_results::SetupFailureTransfer;
use opc_protocol::{DecodeContext, EncodeContext};

pub fn reconstruct(value: &SetupFailureTransfer) -> SetupFailureTransfer {
    SetupFailureTransfer {
        cause: value.cause,
        diagnostics: value.diagnostics.as_ref().map(|v| CriticalityDiagnostics {
            procedure_code: v.procedure_code,
            triggering_outcome: v.triggering_outcome,
            procedure_criticality: v.procedure_criticality,
            ies: v
                .ies
                .as_ref()
                .map(|items| DiagnosticItems::new(items.values().to_vec()).unwrap()),
        }),
    }
}

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = SetupFailureTransfer::decode(data, ctx) {
        let rebuilt = reconstruct(&value);
        assert!(rebuilt == value);
        let wire = rebuilt.encode(output).unwrap();
        assert!(SetupFailureTransfer::decode(wire.as_bytes(), ctx).unwrap() == rebuilt);
    }
}
