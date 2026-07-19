//! Shared backend-neutral request validation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::RouteSteeringError;
use crate::model::{FirewallMark, IpPrefix, RouteRequest, RuleRequest};

pub(crate) fn validate_route_request(request: &RouteRequest) -> Result<(), RouteSteeringError> {
    validate_prefix(request.destination, "route.destination")?;
    validate_ifindex(request.oif_ifindex, "route.oif_ifindex")?;
    validate_table(request.table, "route.table")
}

/// Canonical route metric as represented by the Linux FIB.
///
/// IPv4 omits `0`. IPv6 assigns the effective default metric `1024` when the
/// attribute is omitted or zero.
pub(crate) fn canonical_route_priority(request: &RouteRequest) -> Option<u32> {
    match request.destination.address {
        std::net::IpAddr::V4(_) => request.priority.filter(|priority| *priority != 0),
        std::net::IpAddr::V6(_) => Some(
            request
                .priority
                .filter(|priority| *priority != 0)
                .unwrap_or(1024),
        ),
    }
}

pub(crate) fn canonical_route_request(request: &RouteRequest) -> RouteRequest {
    RouteRequest {
        destination: canonical_route_destination(request.destination),
        oif_ifindex: request.oif_ifindex,
        table: request.table,
        priority: canonical_route_priority(request),
    }
}

fn canonical_route_destination(destination: IpPrefix) -> IpPrefix {
    let address = match destination.address {
        IpAddr::V4(address) if destination.prefix_len <= 32 => {
            let host_bits = 32_u32.saturating_sub(u32::from(destination.prefix_len));
            let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) if destination.prefix_len <= 128 => {
            let host_bits = 128_u32.saturating_sub(u32::from(destination.prefix_len));
            let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        address => address,
    };
    IpPrefix::new(address, destination.prefix_len)
}

pub(crate) fn validate_rule_request(request: &RuleRequest) -> Result<(), RouteSteeringError> {
    if request.source.is_none() && request.destination.is_none() && request.fwmark.is_none() {
        return Err(RouteSteeringError::invalid_config(
            "rule.selector",
            "rule requires at least one selector",
        ));
    }
    if let Some(source) = request.source {
        validate_prefix(source, "rule.source")?;
    }
    if let Some(destination) = request.destination {
        validate_prefix(destination, "rule.destination")?;
    }
    if let (Some(source), Some(destination)) = (request.source, request.destination) {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(RouteSteeringError::invalid_config(
                "rule.family",
                "source and destination selectors must use the same family",
            ));
        }
    }
    if matches!(request.fwmark, Some(FirewallMark { mask: 0, .. })) {
        return Err(RouteSteeringError::invalid_config(
            "rule.fwmark.mask",
            "fwmark mask must be nonzero",
        ));
    }
    validate_table(request.table, "rule.table")?;
    if request.priority == 0 {
        return Err(RouteSteeringError::invalid_config(
            "rule.priority",
            "priority must be nonzero",
        ));
    }
    Ok(())
}

/// Validate the stricter request subset used by protocol-owned convergence.
///
/// The legacy mutation API accepted `/0` selectors and a zero firewall-mark
/// value. Linux treats those values as wildcards in rule deletion, so they
/// cannot participate in the exact owned-removal contract. Keeping this check
/// separate preserves the existing install/read request surface.
pub(crate) fn validate_owned_rule_request(request: &RuleRequest) -> Result<(), RouteSteeringError> {
    validate_rule_request(request)?;
    if let Some(source) = request.source {
        validate_owned_rule_selector_prefix(source, "rule.source")?;
    }
    if let Some(destination) = request.destination {
        validate_owned_rule_selector_prefix(destination, "rule.destination")?;
    }
    if matches!(request.fwmark, Some(FirewallMark { value: 0, .. })) {
        return Err(RouteSteeringError::invalid_config(
            "rule.fwmark.value",
            "zero cannot identify an exact convergence-owned rule",
        ));
    }
    Ok(())
}

fn validate_owned_rule_selector_prefix(
    prefix: IpPrefix,
    field: &'static str,
) -> Result<(), RouteSteeringError> {
    if prefix.prefix_len == 0 {
        return Err(RouteSteeringError::invalid_config(
            field,
            "a /0 selector cannot identify an exact convergence-owned rule",
        ));
    }
    Ok(())
}

fn validate_prefix(prefix: IpPrefix, field: &'static str) -> Result<(), RouteSteeringError> {
    let limit = if prefix.is_ipv4() { 32 } else { 128 };
    if prefix.prefix_len > limit {
        return Err(RouteSteeringError::invalid_config(
            field,
            "prefix length exceeds address family",
        ));
    }
    Ok(())
}

fn validate_ifindex(ifindex: u32, field: &'static str) -> Result<(), RouteSteeringError> {
    if ifindex == 0 {
        return Err(RouteSteeringError::invalid_config(
            field,
            "ifindex must be nonzero",
        ));
    }
    if i32::try_from(ifindex).is_err() {
        return Err(RouteSteeringError::invalid_config(
            field,
            "ifindex exceeds i32 range",
        ));
    }
    Ok(())
}

fn validate_table(table: u32, field: &'static str) -> Result<(), RouteSteeringError> {
    if table == 0 {
        return Err(RouteSteeringError::invalid_config(
            field,
            "table must be nonzero",
        ));
    }
    Ok(())
}
