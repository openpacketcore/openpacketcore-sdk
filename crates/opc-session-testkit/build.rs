use std::env;

fn allowed_environment_value(
    name: &str,
    allowed: &[&str],
    error: &'static str,
) -> Result<String, &'static str> {
    match env::var(name) {
        Ok(value) if allowed.contains(&value.as_str()) => Ok(value),
        _ => Err(error),
    }
}

fn main() -> Result<(), &'static str> {
    println!("cargo:rerun-if-changed=build.rs");
    let profile = allowed_environment_value(
        "PROFILE",
        &["debug", "release"],
        "unsupported Cargo build profile",
    )?;
    let opt_level = allowed_environment_value(
        "OPT_LEVEL",
        &["0", "1", "2", "3", "s", "z"],
        "unsupported Cargo optimization level",
    )?;
    println!("cargo:rustc-env=OPC_SESSION_TESTKIT_CARGO_PROFILE_FAMILY={profile}");
    println!("cargo:rustc-env=OPC_SESSION_TESTKIT_CARGO_OPT_LEVEL={opt_level}");
    Ok(())
}
