//! Cold static-multihoming qualification in an explicitly private netns.
//!
//! Run this test only from a fresh privileged network namespace:
//!
//! ```text
//! sudo unshare -n -- sh -c 'ip link set lo up; OPC_SCTP_RUN_PRIVILEGED=1 \
//!   cargo test --locked -p opc-sctp --test cold_multihoming_netns -- \
//!   --ignored --exact cold_primary_down_secondary_up_establishes_within_five_seconds --nocapture'
//! ```
//!
//! The client owns a disconnected primary route and a veth-connected secondary
//! route. The listener owns both remote addresses in one SCTP endpoint, while
//! the connector receives both as one `SctpConnectConfig::remote_addrs` set.
//! This deliberately tests the cold (no pre-existing association) case.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use opc_sctp::{InitConfig, SctpAssociation, SctpConnectConfig, SctpEndpoint, SctpEndpointConfig};

const PRIMARY_REMOTE: &str = "198.18.0.2:38768";
const SECONDARY_REMOTE: &str = "198.19.0.2:38768";
const FORCED_LOCAL: &str = "198.19.0.1:0";
const OUTER_DEADLINE: Duration = Duration::from_secs(5);
const SERVER_READY_DEADLINE: Duration = Duration::from_secs(5);
const ROLE_ENV: &str = "OPC_SCTP_COLD_MULTIHOMING_ROLE";
const READY_PATH_ENV: &str = "OPC_SCTP_COLD_MULTIHOMING_READY_PATH";
const ACCEPTED_PATH_ENV: &str = "OPC_SCTP_COLD_MULTIHOMING_ACCEPTED_PATH";
const RELEASE_PATH_ENV: &str = "OPC_SCTP_COLD_MULTIHOMING_RELEASE_PATH";

fn command_error(program: &str, args: &[&str], output: &Output) -> io::Error {
    io::Error::other(format!(
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, args, &output))
    }
}

fn output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => format!(
            "status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("spawn_error={error}"),
    }
}

fn require_private_netns() -> io::Result<()> {
    if env::var("OPC_SCTP_RUN_PRIVILEGED").as_deref() != Ok("1") {
        return Err(io::Error::other(
            "set OPC_SCTP_RUN_PRIVILEGED=1 only inside a fresh privileged network namespace",
        ));
    }
    let current = fs::read_link("/proc/self/ns/net")?;
    let init = fs::read_link("/proc/1/ns/net")?;
    if current == init {
        return Err(io::Error::other(
            "refusing to mutate the initial network namespace; run under sudo unshare -n",
        ));
    }
    Ok(())
}

struct Topology {
    server_namespace: String,
    ready_path: PathBuf,
    accepted_path: PathBuf,
    release_path: PathBuf,
    server: Option<Child>,
}

impl Topology {
    fn create() -> io::Result<Self> {
        let server_namespace = format!("opc-sctp-cold-{}", std::process::id());
        let ready_path = env::temp_dir().join(format!("{server_namespace}.ready"));
        let accepted_path = env::temp_dir().join(format!("{server_namespace}.accepted"));
        let release_path = env::temp_dir().join(format!("{server_namespace}.release"));
        let _ = fs::remove_file(&ready_path);
        let _ = fs::remove_file(&accepted_path);
        let _ = fs::remove_file(&release_path);

        run("ip", &["netns", "add", &server_namespace])?;
        let topology = Self {
            server_namespace,
            ready_path,
            accepted_path,
            release_path,
            server: None,
        };
        topology.configure()?;
        Ok(topology)
    }

    fn configure(&self) -> io::Result<()> {
        // `cprim` has no peer. It provides a valid routed primary destination
        // that cannot reach the server namespace; `csec` is the only live
        // transport path to the secondary remote address.
        run("ip", &["link", "set", "lo", "up"])?;
        run("ip", &["link", "add", "cprim", "type", "dummy"])?;
        run("ip", &["addr", "add", "198.18.0.1/24", "dev", "cprim"])?;
        run("ip", &["link", "set", "cprim", "up"])?;
        run(
            "ip",
            &[
                "link", "add", "csec", "type", "veth", "peer", "name", "ssec",
            ],
        )?;
        run(
            "ip",
            &["link", "set", "ssec", "netns", &self.server_namespace],
        )?;
        run("ip", &["addr", "add", "198.19.0.1/24", "dev", "csec"])?;
        run("ip", &["link", "set", "csec", "up"])?;

        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "link",
                "add",
                "sprim",
                "type",
                "dummy",
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "addr",
                "add",
                "198.18.0.2/24",
                "dev",
                "sprim",
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "link",
                "set",
                "sprim",
                "up",
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "addr",
                "add",
                "198.19.0.2/24",
                "dev",
                "ssec",
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ip",
                "link",
                "set",
                "ssec",
                "up",
            ],
        )
    }

    fn start_server(&mut self) -> io::Result<()> {
        let executable = env::current_exe()?;
        let child = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.server_namespace,
                executable
                    .to_str()
                    .ok_or_else(|| io::Error::other("test executable path is not UTF-8"))?,
                "--ignored",
                "--exact",
                "cold_primary_down_secondary_up_establishes_within_five_seconds",
                "--nocapture",
            ])
            .env(ROLE_ENV, "server")
            .env(READY_PATH_ENV, &self.ready_path)
            .env(ACCEPTED_PATH_ENV, &self.accepted_path)
            .env(RELEASE_PATH_ENV, &self.release_path)
            .spawn()?;
        self.server = Some(child);

        let deadline = Instant::now() + SERVER_READY_DEADLINE;
        while !self.ready_path.exists() {
            if let Some(status) = self
                .server
                .as_mut()
                .ok_or_else(|| io::Error::other("server process was not retained"))?
                .try_wait()?
            {
                return Err(io::Error::other(format!(
                    "server exited before listener readiness: {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "server listener did not become ready",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn chronology(&self) -> String {
        let server_ss = output(
            "ip",
            &[
                "netns",
                "exec",
                &self.server_namespace,
                "ss",
                "-H",
                "-n",
                "-a",
                "-A",
                "sctp",
            ],
        );
        format!(
            "route_primary=[{}]; client_ss=[{}]; client_primary_link=[{}]; client_secondary_link=[{}]; server_ss=[{}]; server_secondary_link=[{}]",
            output("ip", &["route", "get", "198.18.0.2", "from", "198.19.0.1"]),
            output("ss", &["-H", "-n", "-a", "-A", "sctp"]),
            output("ip", &["-s", "link", "show", "dev", "cprim"]),
            output("ip", &["-s", "link", "show", "dev", "csec"]),
            server_ss,
            output(
                "ip",
                &[
                    "netns",
                    "exec",
                    &self.server_namespace,
                    "ip",
                    "-s",
                    "link",
                    "show",
                    "dev",
                    "ssec",
                ],
            ),
        )
    }

    fn wait_for_server_accept(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let server = self
                .server
                .as_mut()
                .ok_or_else(|| io::Error::other("server process was not retained"))?;
            if let Some(status) = server.try_wait()? {
                if status.success() {
                    return Err(io::Error::other(
                        "server exited before recording the accepted association",
                    ));
                }
                return Err(io::Error::other(format!(
                    "server listener failed after connector success: {status}"
                )));
            }
            if self.accepted_path.exists() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "server did not report accept after connector success",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_server(&mut self) -> io::Result<()> {
        fs::write(&self.release_path, b"release")?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let server = self
                .server
                .as_mut()
                .ok_or_else(|| io::Error::other("server process was not retained"))?;
            if let Some(status) = server.try_wait()? {
                return status.success().then_some(()).ok_or_else(|| {
                    io::Error::other(format!("server listener failed after accept: {status}"))
                });
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "server did not exit after release",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        if let Some(mut server) = self.server.take() {
            let _ = server.kill();
            let _ = server.wait();
        }
        let _ = fs::remove_file(&self.ready_path);
        let _ = fs::remove_file(&self.accepted_path);
        let _ = fs::remove_file(&self.release_path);
        let _ = Command::new("ip")
            .args(["netns", "del", &self.server_namespace])
            .status();
    }
}

async fn run_server() -> io::Result<()> {
    let primary: SocketAddr = PRIMARY_REMOTE.parse().map_err(io::Error::other)?;
    let secondary: SocketAddr = SECONDARY_REMOTE.parse().map_err(io::Error::other)?;
    let mut config = SctpEndpointConfig::one_to_one(primary);
    config.local_addrs.push(secondary);
    let endpoint = SctpEndpoint::bind(config).map_err(io::Error::other)?;

    let ready_path = env::var_os(READY_PATH_ENV)
        .ok_or_else(|| io::Error::other("server readiness path is missing"))?;
    fs::write(ready_path, b"listener-ready")?;
    let accepted = tokio::time::timeout(OUTER_DEADLINE + Duration::from_secs(1), endpoint.accept())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server accept timed out"))?
        .map_err(io::Error::other)?;
    let accepted_path = env::var_os(ACCEPTED_PATH_ENV)
        .ok_or_else(|| io::Error::other("server accepted path is missing"))?;
    fs::write(accepted_path, b"association-accepted")?;
    let release_path = env::var_os(RELEASE_PATH_ENV)
        .ok_or_else(|| io::Error::other("server release path is missing"))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while !PathBuf::from(&release_path).exists() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server did not receive post-connect release",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(accepted);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux SCTP and CAP_NET_ADMIN in a fresh network namespace"]
async fn cold_primary_down_secondary_up_establishes_within_five_seconds() -> io::Result<()> {
    if env::var(ROLE_ENV).as_deref() == Ok("server") {
        return run_server().await;
    }
    require_private_netns()?;

    let mut topology = Topology::create()?;
    topology.start_server()?;

    let primary: SocketAddr = PRIMARY_REMOTE.parse().map_err(io::Error::other)?;
    let secondary: SocketAddr = SECONDARY_REMOTE.parse().map_err(io::Error::other)?;
    let forced_local: SocketAddr = FORCED_LOCAL.parse().map_err(io::Error::other)?;
    let mut config = SctpConnectConfig::new(primary);
    config.remote_addrs.push(secondary);
    config.local_addrs.push(forced_local);

    // Keep the production defaults exact: one multihomed peer, one forced
    // local bind, four INIT attempts, and 1 s maximum INIT timeout. This
    // socket-level test neither claims nor substitutes for ePDG's mandatory
    // external-IPsec protection assertion.
    assert_eq!(config.init, InitConfig::default());
    assert_eq!(config.init.max_attempts, 4);
    assert_eq!(config.init.max_init_timeout_ms, 1_000);
    assert_eq!(config.remote_addrs, vec![primary, secondary]);
    assert_eq!(config.local_addrs, vec![forced_local]);
    config.validate().map_err(io::Error::other)?;

    let started = Instant::now();
    let result = tokio::time::timeout(OUTER_DEADLINE, SctpAssociation::connect(config)).await;
    let elapsed = started.elapsed();
    let chronology = topology.chronology();
    match result {
        Ok(Ok(association)) => {
            // The connector's success is paired with a real accept in the
            // secondary namespace. The exact configured local and remote
            // sets above prove this remained one logical multihomed peer.
            topology.wait_for_server_accept()?;
            eprintln!(
                "cold SCTP multihoming connector=connected elapsed={elapsed:?}; {chronology}"
            );
            drop(association);
            topology.release_server()?;
            Ok(())
        }
        Ok(Err(error)) => Err(io::Error::other(format!(
            "cold multihomed connect failed before the five-second deadline: {error}; {chronology}"
        ))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "cold multihomed connect did not establish through the reachable secondary within five seconds; {chronology}"
            ),
        )),
    }
}
