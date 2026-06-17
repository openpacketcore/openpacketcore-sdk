use std::path::PathBuf;
use std::process::Command;

#[test]
fn gnmic_interop_script_skips_unless_enabled() {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/gnmi-interop-gnmic-smoke.sh");

    let output = Command::new("bash")
        .arg(script)
        .env_remove("OPC_GNMI_INTEROP")
        .output()
        .expect("run gnmic interop script");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("script stdout utf8");
    assert!(stdout.contains("SKIP: set OPC_GNMI_INTEROP=1"));
}
