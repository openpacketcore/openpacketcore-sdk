#![forbid(unsafe_code)]

use std::{env, fs, path::PathBuf};

const GNMI_PROTO: &str = "proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto";
const GNMI_EXT_PROTO: &str = "proto/github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto";

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    env::set_var("PROTOC", protoc);

    println!("cargo:rerun-if-changed={GNMI_PROTO}");
    println!("cargo:rerun-if-changed={GNMI_EXT_PROTO}");
    println!("cargo:rerun-if-changed=proto/README.md");

    let version = gnmi_version_from_proto(GNMI_PROTO);
    println!("cargo:rustc-env=OPC_GNMI_PROTO_VERSION={version}");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("gnmi_descriptor.bin"))
        .compile_protos(&[GNMI_PROTO, GNMI_EXT_PROTO], &["proto"])
        .expect("vendored OpenConfig gNMI protos compile");
}

fn gnmi_version_from_proto(path: &str) -> String {
    let text = fs::read_to_string(path).expect("vendored gnmi.proto is readable");
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("option (gnmi_service) = ") {
            let value = rest.trim_end_matches(';').trim().trim_matches('"');
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    panic!("vendored gnmi.proto does not declare option (gnmi_service)");
}
