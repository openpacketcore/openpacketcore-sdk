#[test]
fn rpc_timeout_help_describes_one_logical_deadline() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_opc-consensus-node"))
        .arg("--help")
        .output()
        .expect("run opc-consensus-node --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("One end-to-end logical peer-RPC deadline"));
    assert!(stdout.contains("includes setup, TCP, mTLS, write/read"));
    assert!(stdout.contains("response decoding, retries, and backoff"));
}
