//! Transport liveness independent of scan admission and page progress.
use std::{io, net::SocketAddr};
use tokio::net::TcpStream;

pub(super) async fn connect(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = TcpStream::connect(address).await?;
    configure(&socket)?;
    Ok(socket)
}

pub(super) fn configure(socket: &TcpStream) -> io::Result<()> {
    socket.set_nodelay(true)?;
    #[cfg(target_os = "linux")]
    {
        use socket2::{SockRef, TcpKeepalive};
        use std::time::Duration;
        let socket = SockRef::from(socket);
        // Healthy queued reads answer these in the kernel without releasing
        // their server-side queue position. Only a lost TCP peer times out.
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(2))
                .with_interval(Duration::from_secs(2))
                .with_retries(4),
        )?;
        socket.set_tcp_user_timeout(Some(Duration::from_secs(10)))?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use socket2::SockRef;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        time::Duration,
    };
    use tokio::{io::AsyncReadExt, net::TcpListener};

    #[tokio::test]
    async fn scope_socket_configures_liveness_on_client_and_accepted_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = connect(listener.local_addr().unwrap()).await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        configure(&peer).unwrap();
        for stream in [&client, &peer] {
            let socket = SockRef::from(stream);
            assert!(socket.keepalive().unwrap());
            assert_eq!(socket.tcp_keepalive_time().unwrap(), Duration::from_secs(2));
            assert_eq!(
                socket.tcp_keepalive_interval().unwrap(),
                Duration::from_secs(2)
            );
            assert_eq!(socket.tcp_keepalive_retries().unwrap(), 4);
            assert_eq!(
                socket.tcp_user_timeout().unwrap(),
                Some(Duration::from_secs(10))
            );
        }
    }

    struct TestPeer(Child);
    impl Drop for TestPeer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn scope_socket_dead_peer_times_out_without_a_scan_progress_deadline() {
        // The helper silences only its own TCP socket. It needs no privilege,
        // host firewall, Rust unsafe code or production fault-injection hook.
        let mut peer = TestPeer(
            Command::new("python3")
                .arg("-c")
                .arg(include_str!("socket_test_peer.py"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let output = peer.0.stdout.take().unwrap();
        let (ready, messages) = std::sync::mpsc::sync_channel(2);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines().take(2) {
                if ready.send(line).is_err() {
                    break;
                }
            }
        });
        let line = messages
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap();
        let port = line.trim().parse::<u16>().unwrap();
        let mut client = connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        let line = messages
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(line.trim(), "silent");
        reader.join().unwrap();
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(30), client.read(&mut byte))
            .await
            .expect("lost peer must not wait until a restore's long deadline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
