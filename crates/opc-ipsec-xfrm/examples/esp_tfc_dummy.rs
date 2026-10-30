//! Send bounded zero-filled ESP dummies on a caller-installed SA.
//! Usage: esp_tfc_dummy MODE SOURCE DESTINATION SPI REQID BYTES COUNT [THREADS]

use opc_ipsec_xfrm::{EspTfcDummySender, IpAddress, XfrmId, XfrmMode, XfrmRequestId, XfrmTemplate};
use std::{error::Error, io, net::IpAddr, sync::Arc};

fn ip(text: &str) -> Result<IpAddress, std::net::AddrParseError> {
    Ok(match text.parse::<IpAddr>()? {
        IpAddr::V4(ip) => IpAddress::Ipv4(ip.octets()),
        IpAddr::V6(ip) => IpAddress::Ipv6(ip.octets()),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(7..=8).contains(&args.len()) {
        return Err(
            "usage: esp_tfc_dummy MODE SOURCE DESTINATION SPI REQID BYTES COUNT [THREADS]".into(),
        );
    }
    let mode = match args[0].as_str() {
        "transport" => XfrmMode::Transport,
        "tunnel" => XfrmMode::Tunnel,
        _ => return Err("mode must be transport or tunnel".into()),
    };
    let source = ip(&args[1])?;
    let destination = ip(&args[2])?;
    let payload_len = args[5].parse()?;
    let count: usize = args[6].parse()?;
    let threads: usize = args.get(7).map_or(Ok(1), |text| text.parse())?;
    if !(1..=10_000).contains(&count) || !(1..=8).contains(&threads) {
        return Err("count must be 1..=10000 and threads 1..=8".into());
    }
    let sender = Arc::new(EspTfcDummySender::open_current_namespace(
        source,
        destination,
        XfrmTemplate {
            id: XfrmId {
                destination,
                spi: args[3].parse()?,
                protocol: 50,
            },
            source_address: source,
            request_id: XfrmRequestId::new(args[4].parse()?),
            mode,
        },
    )?);
    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let sender = Arc::clone(&sender);
        workers.push(std::thread::spawn(move || {
            for _ in 0..count {
                sender.send(payload_len)?;
            }
            Ok::<_, opc_ipsec_xfrm::XfrmError>(())
        }));
    }
    let mut failure = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                failure.get_or_insert_with(|| io::Error::other(error));
            }
            Err(_) => {
                failure.get_or_insert_with(|| io::Error::other("dummy sender thread failed"));
            }
        }
    }
    if let Some(error) = failure {
        return Err(error.into());
    }
    println!("submitted={}", count * threads);
    Ok(())
}
