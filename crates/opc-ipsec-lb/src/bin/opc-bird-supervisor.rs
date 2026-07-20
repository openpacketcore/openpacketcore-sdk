//! Minimal Linux parent-death helper for the supervised BIRD adapter.
//!
//! This binary is an implementation detail of `opc-ipsec-lb`. It installs a
//! parent-death signal before acknowledging a bounded, nonce-bound handshake,
//! closes the fork/exec race by checking the expected parent PID, and then
//! replaces itself with foreground BIRD. It never accepts an arbitrary BIRD
//! argument vector.

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};

    const HANDSHAKE_VERSION: &str = "1";
    const HANDSHAKE_BYTES_MAX: u64 = 160;
    const NONCE_HEX_LEN: usize = 64;
    const PATH_BYTES_MAX: usize = 4_096;
    const ARG_COUNT: usize = 9;

    struct HelperConfig {
        expected_parent_pid: i32,
        bird_executable: PathBuf,
        bird_config: PathBuf,
        control_socket: PathBuf,
    }

    pub(super) fn main() -> ExitCode {
        match run() {
            Ok(error) => {
                eprintln!("opc-bird-supervisor: foreground BIRD exec failed: {error}");
                ExitCode::FAILURE
            }
            Err(()) => ExitCode::FAILURE,
        }
    }

    fn run() -> Result<io::Error, ()> {
        let config = parse_args().map_err(|()| report("invalid bounded helper arguments"))?;
        rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
            .map_err(|_| report("could not install parent-death signal"))?;
        let actual_parent = rustix::process::getppid()
            .map(rustix::process::Pid::as_raw_pid)
            .ok_or_else(|| report("parent process is unavailable"))?;
        if actual_parent != config.expected_parent_pid {
            report("parent changed before supervision was armed");
            return Err(());
        }

        let nonce = read_challenge()?;
        let actual_parent = rustix::process::getppid()
            .map(rustix::process::Pid::as_raw_pid)
            .ok_or_else(|| report("parent process is unavailable"))?;
        if actual_parent != config.expected_parent_pid {
            report("parent changed during helper handshake");
            return Err(());
        }
        let response = format!("OPC_BIRD_SUPERVISOR_READY {HANDSHAKE_VERSION} {nonce}\n");
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(response.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(|_| report("could not acknowledge helper handshake"))?;
        drop(stdout);

        // The SDK supplies the complete supported invocation. There is no
        // caller argument vector to smuggle `-d` or another daemonizing mode;
        // `-f` is unconditional and precedes the typed config/socket paths.
        Ok(Command::new(config.bird_executable)
            .arg("-f")
            .arg("-c")
            .arg(config.bird_config)
            .arg("-s")
            .arg(config.control_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .exec())
    }

    fn parse_args() -> Result<HelperConfig, ()> {
        let args: Vec<OsString> = env::args_os().collect();
        if args.len() != ARG_COUNT
            || args[1] != OsStr::new("--expected-parent-pid")
            || args[3] != OsStr::new("--bird-executable")
            || args[5] != OsStr::new("--config")
            || args[7] != OsStr::new("--control-socket")
        {
            return Err(());
        }
        if args
            .iter()
            .skip(1)
            .any(|argument| argument.as_bytes().len() > PATH_BYTES_MAX)
        {
            return Err(());
        }
        let expected_parent_pid = parse_expected_parent_pid(&args[2])?;
        let bird_executable = bounded_absolute_path(&args[4])?;
        let bird_config = bounded_absolute_path(&args[6])?;
        let control_socket = bounded_absolute_path(&args[8])?;
        let executable_metadata = std::fs::metadata(&bird_executable).map_err(|_| ())?;
        if !executable_metadata.is_file()
            || executable_metadata.permissions().mode() & 0o111 == 0
            || executable_metadata.permissions().mode() & 0o6000 != 0
            || !std::fs::metadata(&bird_config)
                .map(|metadata| metadata.is_file())
                .unwrap_or(false)
        {
            return Err(());
        }
        let mut capability = vec![0_u8; 256];
        match rustix::fs::getxattr(&bird_executable, "security.capability", &mut capability) {
            Ok(capability_len) if capability_len != 0 => return Err(()),
            Ok(_) | Err(rustix::io::Errno::NODATA) => {}
            Err(_) => return Err(()),
        }
        Ok(HelperConfig {
            expected_parent_pid,
            bird_executable,
            bird_config,
            control_socket,
        })
    }

    fn parse_expected_parent_pid(raw: &OsStr) -> Result<i32, ()> {
        raw.to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid >= 1)
            .ok_or(())
    }

    fn bounded_absolute_path(raw: &OsStr) -> Result<PathBuf, ()> {
        if raw.is_empty() || raw.as_bytes().len() > PATH_BYTES_MAX {
            return Err(());
        }
        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(());
        }
        Ok(path.to_owned())
    }

    fn read_challenge() -> Result<String, ()> {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .take(HANDSHAKE_BYTES_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| report("could not read helper handshake"))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > HANDSHAKE_BYTES_MAX {
            report("helper handshake exceeds its bound");
            return Err(());
        }
        let line = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .ok_or_else(|| report("helper handshake framing is invalid"))?;
        let mut fields = line.split(' ');
        if fields.next() != Some("OPC_BIRD_SUPERVISOR") || fields.next() != Some(HANDSHAKE_VERSION)
        {
            report("helper handshake version is invalid");
            return Err(());
        }
        let nonce = fields
            .next()
            .filter(|nonce| {
                nonce.len() == NONCE_HEX_LEN && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| report("helper handshake nonce is invalid"))?;
        if fields.next().is_some() {
            report("helper handshake has trailing fields");
            return Err(());
        }
        Ok(nonce.to_owned())
    }

    fn report(message: &'static str) {
        eprintln!("opc-bird-supervisor: {message}");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn expected_parent_pid_accepts_container_init() {
            assert_eq!(parse_expected_parent_pid(OsStr::new("1")), Ok(1));
            assert!(parse_expected_parent_pid(OsStr::new("0")).is_err());
            assert!(parse_expected_parent_pid(OsStr::new("-1")).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("opc-bird-supervisor: unsupported platform");
    std::process::ExitCode::FAILURE
}
