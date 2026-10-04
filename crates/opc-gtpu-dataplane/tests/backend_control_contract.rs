use opc_gtpu_dataplane::{
    GtpDevice, GtpuDataplaneBackend, GtpuError, LinuxGtpuDataplaneBackend,
    MockGtpuDataplaneBackend, UnsupportedGtpuDataplaneBackend,
};

#[tokio::test]
async fn unqualified_backends_report_exact_control_port_unsupported() {
    let backends: Vec<Box<dyn GtpuDataplaneBackend>> = vec![
        Box::new(MockGtpuDataplaneBackend::new()),
        Box::new(LinuxGtpuDataplaneBackend::new()),
        Box::new(UnsupportedGtpuDataplaneBackend::new()),
    ];
    let device = GtpDevice {
        name: "sensitive-synthetic-device".into(),
        ifindex: 73,
    };
    for backend in backends {
        let error = backend.open_gtpu_control_port(&device).await.unwrap_err();
        assert!(matches!(
            error,
            GtpuError::UnsupportedFeature {
                feature: "gtpu_control_port"
            }
        ));
        assert!(!format!("{error:?} {error}").contains(&device.name));
    }
}
