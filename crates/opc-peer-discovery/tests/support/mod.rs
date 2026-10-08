use std::io;

use tokio::net::{TcpListener, UdpSocket};

pub async fn bind_dns_pair(mut listener: TcpListener) -> io::Result<(TcpListener, UdpSocket)> {
    for _ in 0..32 {
        let address = listener.local_addr()?;
        match UdpSocket::bind(address).await {
            Ok(socket) => return Ok((listener, socket)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                // TCP and UDP allocate ports independently. Keep this listener
                // bound until a new one exists, so the next pair uses a new port.
                listener = TcpListener::bind((address.ip(), 0)).await?;
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "could not allocate a TCP/UDP port pair after 32 attempts",
    ))
}
