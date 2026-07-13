//! Post-transform tc egress companion for fixed outer XFRM DSCP.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use opc_ipsec_xfrm_ebpf_common::{
    classify_esp_carrier, rewrite_ipv4_dscp, rewrite_ipv6_dscp, valid_esp_spi, EspCarrier,
    MarkProfile, MarkToken, ESP_SPI_LEN, ETH_HDR_LEN, ETH_P_IPV4, ETH_P_IPV6, IPV4_HEADER_LEN,
    IPV6_HEADER_LEN, MARK_CONFIG_VALUE_LEN, UDP_HEADER_LEN,
};

/// Single-slot reserved-mark profile, provisioned before program attach.
#[map]
static XFRM_DSCP_CFG: Array<[u8; MARK_CONFIG_VALUE_LEN]> = Array::pinned(1, 0);

#[classifier]
pub fn opc_xfrm_dscp(mut ctx: TcContext) -> i32 {
    try_egress_dscp(&mut ctx).unwrap_or(TC_ACT_SHOT as i32)
}

fn try_egress_dscp(ctx: &mut TcContext) -> Result<i32, ()> {
    let profile_ptr = XFRM_DSCP_CFG.get_ptr(0).ok_or(())?;
    // SAFETY: slot zero is an array-map value and remains valid for this
    // invocation. The value is copied before any packet mutation.
    let profile_raw = unsafe { *profile_ptr };
    let profile = MarkProfile::decode(&profile_raw).ok_or(())?;
    // SAFETY: tc guarantees a valid skb pointer for the classifier lifetime.
    let mark = unsafe { (*ctx.skb.skb).mark };
    let dscp = match profile.decode_token(mark) {
        MarkToken::Absent => return Ok(TC_ACT_OK as i32),
        MarkToken::Malformed => return Ok(TC_ACT_SHOT as i32),
        MarkToken::Dscp(value) => value,
    };

    let eth_proto = u16::from_be(ctx.load(12).map_err(|_| ())?);
    match eth_proto {
        ETH_P_IPV4 => rewrite_ipv4(ctx, dscp)?,
        ETH_P_IPV6 => rewrite_ipv6(ctx, dscp)?,
        _ => return Ok(TC_ACT_SHOT as i32),
    }

    // The companion owns only its reserved seven bits. Clearing them avoids
    // leaking the internal token beyond this host while retaining all caller
    // and policy marks outside the configured mask.
    // SAFETY: same tc skb lifetime as the read above.
    unsafe { (*ctx.skb.skb).mark = profile.clear_token(mark) };
    Ok(TC_ACT_OK as i32)
}

fn rewrite_ipv4(ctx: &mut TcContext, dscp: u8) -> Result<(), ()> {
    let mut header: [u8; IPV4_HEADER_LEN] = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
    if !valid_esp_carrier(ctx, header[9], ETH_HDR_LEN + IPV4_HEADER_LEN)? {
        return Err(());
    }
    if !rewrite_ipv4_dscp(&mut header, dscp) {
        return Err(());
    }
    ctx.store(ETH_HDR_LEN, &header, 0).map_err(|_| ())
}

fn rewrite_ipv6(ctx: &mut TcContext, dscp: u8) -> Result<(), ()> {
    let mut header: [u8; IPV6_HEADER_LEN] = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
    if !valid_esp_carrier(ctx, header[6], ETH_HDR_LEN + IPV6_HEADER_LEN)? {
        return Err(());
    }
    if !rewrite_ipv6_dscp(&mut header, dscp) {
        return Err(());
    }
    ctx.store(ETH_HDR_LEN, &header, 0).map_err(|_| ())
}

/// Accept direct ESP or XFRM ESP-in-UDP. A zero SPI is the NAT-T non-ESP
/// marker used by IKE and is never a transformed data packet.
fn valid_esp_carrier(ctx: &TcContext, protocol: u8, payload_offset: usize) -> Result<bool, ()> {
    let udp_ports = if protocol == opc_ipsec_xfrm_ebpf_common::IPPROTO_UDP {
        ctx.load(payload_offset).map_err(|_| ())?
    } else {
        [0; 4]
    };
    let spi_offset = match classify_esp_carrier(protocol, udp_ports) {
        Some(EspCarrier::Direct) => payload_offset,
        Some(EspCarrier::UdpEncapsulated) => payload_offset + UDP_HEADER_LEN,
        None => return Ok(false),
    };
    let spi: [u8; ESP_SPI_LEN] = ctx.load(spi_offset).map_err(|_| ())?;
    Ok(valid_esp_spi(spi))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
