//! Explicit endpoint resolution, source-address validation, and exact weighted plans.

use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};

use crate::config::LoadScenario;

/// One startup-resolved persistent connection assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAssignment {
    pub region_index: usize,
    pub endpoint_index: usize,
    pub endpoint_name: String,
    pub target: SocketAddr,
    pub source_ip: IpAddr,
    pub connection_index: u32,
}

/// Resolved topology and exact per-endpoint rate partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTopology {
    pub connections: Vec<ConnectionAssignment>,
    /// Nested by region then endpoint; sums exactly to scenario offered rate.
    pub endpoint_rates: Vec<Vec<u64>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TopologyError {
    #[error("cannot bind configured source IP {address}: {reason}")]
    SourceUnavailable { address: IpAddr, reason: String },
    #[error("endpoint `{endpoint}` cannot be resolved: {reason}")]
    Resolve { endpoint: String, reason: String },
    #[error("endpoint `{endpoint}` has no address matching source family {source_ip}")]
    AddressFamily { endpoint: String, source_ip: IpAddr },
    #[error(
        "source {source_ip} requests {connections} connections to `{endpoint}`, exceeding the conservative 60000-port preflight ceiling"
    )]
    SourcePortCapacity {
        source_ip: IpAddr,
        endpoint: String,
        connections: u32,
    },
    #[error("weighted partition has no positive healthy weight")]
    NoCapacity,
    #[error("topology arithmetic overflow")]
    Overflow,
}

/// Resolve DNS and validate source addresses before the timed phase. No name lookup
/// or local-interface discovery occurs in the hot path.
pub fn preflight_topology(scenario: &LoadScenario) -> Result<ResolvedTopology, TopologyError> {
    let region_weights = scenario
        .regions
        .iter()
        .map(|region| u64::from(region.users))
        .collect::<Vec<_>>();
    let region_rates = partition_weighted(scenario.orders_per_second, &region_weights)?;
    let mut endpoint_rates = Vec::with_capacity(scenario.regions.len());
    let connection_count =
        usize::try_from(scenario.total_connections()).map_err(|_| TopologyError::Overflow)?;
    let mut connections = Vec::new();
    connections
        .try_reserve_exact(connection_count)
        .map_err(|_| TopologyError::Overflow)?;

    for (region_index, region) in scenario.regions.iter().enumerate() {
        let weights = region
            .endpoints
            .iter()
            .map(|endpoint| u64::from(endpoint.weight))
            .collect::<Vec<_>>();
        endpoint_rates.push(partition_weighted(region_rates[region_index], &weights)?);

        let sources = region
            .source_ips
            .iter()
            .map(|source| {
                source
                    .parse::<IpAddr>()
                    .map_err(|_| TopologyError::SourceUnavailable {
                        address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        reason: format!("`{source}` is not an IP address"),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for source in &sources {
            validate_local_source(*source)?;
        }

        for (endpoint_index, endpoint) in region.endpoints.iter().enumerate() {
            let resolved = endpoint
                .address
                .to_socket_addrs()
                .map_err(|error| TopologyError::Resolve {
                    endpoint: endpoint.name.clone(),
                    reason: error.to_string(),
                })?
                .collect::<Vec<_>>();
            if resolved.is_empty() {
                return Err(TopologyError::Resolve {
                    endpoint: endpoint.name.clone(),
                    reason: "no addresses returned".to_string(),
                });
            }
            for source in &sources {
                if endpoint.connections_per_source_ip > 60_000 {
                    return Err(TopologyError::SourcePortCapacity {
                        source_ip: *source,
                        endpoint: endpoint.name.clone(),
                        connections: endpoint.connections_per_source_ip,
                    });
                }
                let matching = resolved
                    .iter()
                    .copied()
                    .find(|target| target.is_ipv4() == source.is_ipv4())
                    .ok_or_else(|| TopologyError::AddressFamily {
                        endpoint: endpoint.name.clone(),
                        source_ip: *source,
                    })?;
                for connection_index in 0..endpoint.connections_per_source_ip {
                    connections.push(ConnectionAssignment {
                        region_index,
                        endpoint_index,
                        endpoint_name: endpoint.name.clone(),
                        target: matching,
                        source_ip: *source,
                        connection_index,
                    });
                }
            }
        }
    }
    Ok(ResolvedTopology {
        connections,
        endpoint_rates,
    })
}

/// Exact deterministic largest-remainder partition. Output always sums to `total`.
pub fn partition_weighted(total: u64, weights: &[u64]) -> Result<Vec<u64>, TopologyError> {
    let weight_total = weights.iter().try_fold(0u128, |sum, weight| {
        sum.checked_add(u128::from(*weight))
            .ok_or(TopologyError::Overflow)
    })?;
    if weight_total == 0 {
        return Err(TopologyError::NoCapacity);
    }
    let mut output = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    let mut assigned = 0u64;
    for (index, weight) in weights.iter().enumerate() {
        let product = u128::from(total)
            .checked_mul(u128::from(*weight))
            .ok_or(TopologyError::Overflow)?;
        let share = u64::try_from(product / weight_total).map_err(|_| TopologyError::Overflow)?;
        assigned = assigned.checked_add(share).ok_or(TopologyError::Overflow)?;
        output.push(share);
        remainders.push((product % weight_total, index));
    }
    remainders
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let remainder = total.checked_sub(assigned).ok_or(TopologyError::Overflow)?;
    for (_, index) in remainders
        .into_iter()
        .take(usize::try_from(remainder).map_err(|_| TopologyError::Overflow)?)
    {
        output[index] = output[index]
            .checked_add(1)
            .ok_or(TopologyError::Overflow)?;
    }
    Ok(output)
}

/// Repartition only future work across healthy endpoints. Existing in-flight work and
/// identity namespaces are not moved by this helper.
pub fn redistribute_healthy(
    total: u64,
    weights: &[u64],
    healthy: &[bool],
) -> Result<Vec<u64>, TopologyError> {
    if weights.len() != healthy.len() {
        return Err(TopologyError::NoCapacity);
    }
    let effective = weights
        .iter()
        .zip(healthy)
        .map(|(weight, healthy)| if *healthy { *weight } else { 0 })
        .collect::<Vec<_>>();
    partition_weighted(total, &effective)
}

fn validate_local_source(address: IpAddr) -> Result<(), TopologyError> {
    TcpListener::bind(SocketAddr::new(address, 0))
        .map(drop)
        .map_err(|error| TopologyError::SourceUnavailable {
            address,
            reason: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{EndpointConfig, OperationMix, RegionConfig, RunMode, TargetKind};
    use types::Ratio;

    #[test]
    fn weighted_partition_is_exact_and_deterministic() {
        assert_eq!(partition_weighted(10, &[1, 1, 1]).unwrap(), vec![4, 3, 3]);
        assert_eq!(partition_weighted(100, &[1, 3]).unwrap(), vec![25, 75]);
        assert_eq!(partition_weighted(1, &[0, 5, 5]).unwrap(), vec![0, 1, 0]);
        assert!(partition_weighted(10, &[0, 0]).is_err());
    }

    #[test]
    fn healthy_redistribution_has_no_lost_remainder() {
        let rates = redistribute_healthy(101, &[1, 2, 3], &[true, false, true]).unwrap();
        assert_eq!(rates.iter().sum::<u64>(), 101);
        assert_eq!(rates[1], 0);
        assert!(redistribute_healthy(1, &[1], &[false]).is_err());
    }

    #[test]
    fn preflight_assigns_ten_thousand_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            market_ids: vec![1],
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(1_000_000),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            regions: vec![RegionConfig {
                name: "local".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "sink".to_string(),
                    address: listener.local_addr().unwrap().to_string(),
                    connections_per_source_ip: 10_000,
                    target_kind: TargetKind::ReferenceSink,
                    ..EndpointConfig::default()
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        scenario.validate().unwrap();
        let topology = preflight_topology(&scenario).unwrap();
        assert_eq!(topology.connections.len(), 10_000);
        assert_eq!(topology.endpoint_rates[0][0], scenario.orders_per_second);
        assert_eq!(
            topology.connections[0].source_ip,
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(topology.connections[9_999].connection_index, 9_999);
    }

    #[test]
    fn invalid_unassigned_source_fails_before_connect() {
        let error = validate_local_source("192.0.2.123".parse().unwrap()).unwrap_err();
        assert!(matches!(error, TopologyError::SourceUnavailable { .. }));
    }

    #[test]
    fn ipv4_and_ipv6_loopback_sources_validate() {
        validate_local_source("127.0.0.1".parse().unwrap()).unwrap();
        // IPv6 may be disabled in a minimal CI kernel; when enabled, it must bind.
        if std::net::UdpSocket::bind("[::1]:0").is_ok() {
            validate_local_source("::1".parse().unwrap()).unwrap();
        }
    }
}
