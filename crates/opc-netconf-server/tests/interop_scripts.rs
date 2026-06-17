use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn netconf_interop_scripts_skip_unless_enabled() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_script_skips(&repo_root.join("scripts/netconf-interop-netopeer2-smoke.sh"));
    assert_script_skips(&repo_root.join("scripts/netconf-interop-ncclient-smoke.sh"));
}

fn assert_script_skips(script: &Path) {
    let output = Command::new("bash")
        .arg(script)
        .env_remove("OPC_NETCONF_INTEROP")
        .output()
        .expect("run NETCONF interop script");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("script stdout utf8");
    assert!(stdout.contains("SKIP: set OPC_NETCONF_INTEROP=1"));
}
