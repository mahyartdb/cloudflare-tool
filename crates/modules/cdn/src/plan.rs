use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use cftool_core::error::ScanError;
use cftool_core::options::ModuleOptions;
use cftool_core::ranges::{
    MAX_CHARGED_PACKETS, MAX_PLAN_ENDPOINTS, PUBLISHED_V4_SNAPSHOT, PUBLISHED_V6_SNAPSHOT,
};
use cftool_core::target::{GenerationRecipe, ScanTarget, TargetPlan};
use ipnet::{Ipv4Net, Ipv6Net};
use rand::random;

use crate::options::{CdnOptions, per_probe_timeout};

/// Parses the published IPv4 CDN ranges.
pub fn published_v4_nets() -> Vec<Ipv4Net> {
    PUBLISHED_V4_SNAPSHOT
        .iter()
        .map(|cidr| {
            cidr.parse::<Ipv4Net>()
                .unwrap_or_else(|_| panic!("published IPv4 snapshot entry is not a CIDR: {cidr}"))
        })
        .collect()
}

/// All /24 subnets contained in `net`; empty when `net` is narrower than /24.
pub fn subnets24(net: Ipv4Net) -> Vec<Ipv4Net> {
    match net.subnets(24) {
        Ok(subnets) => subnets.collect(),
        Err(_) => Vec::new(),
    }
}

/// Addresses the scan will probe, sampled or enumerated per [`CdnOptions`].
pub fn sample_addresses(o: &CdnOptions) -> Vec<IpAddr> {
    let mut addresses = Vec::with_capacity(address_count(o));

    if o.all_ips {
        for net in published_v4_nets() {
            for subnet in subnets24(net) {
                let base = subnet.addr().octets();
                for host in 0..=255u8 {
                    let mut octets = base;
                    octets[3] = host;
                    addresses.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
            }
        }
        // all_ips supersedes v6 sampling so the materialized count matches
        // address_count, which reports only the v4 total in this mode.
        return addresses;
    }

    for net in published_v4_nets() {
        for subnet in subnets24(net) {
            let base = subnet.addr().octets();
            let want = o.sample_per_subnet as usize;
            if want >= 256 {
                for host in 0..=255u8 {
                    let mut octets = base;
                    octets[3] = host;
                    addresses.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                continue;
            }
            let mut seen = HashSet::with_capacity(want);
            while seen.len() < want {
                let host = random::<u8>();
                if seen.insert(host) {
                    let mut octets = base;
                    octets[3] = host;
                    addresses.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
            }
        }
    }

    if o.v6 {
        let mut seen: HashSet<[u8; 16]> = HashSet::new();
        let want = o.v6_samples as usize;
        for cidr in PUBLISHED_V6_SNAPSHOT {
            let net = cidr
                .parse::<Ipv6Net>()
                .unwrap_or_else(|_| panic!("published IPv6 snapshot entry is not a CIDR: {cidr}"));
            let prefix = net.addr().octets();
            for _ in 0..want {
                loop {
                    let mut octets = prefix;
                    for byte in &mut octets[8..] {
                        *byte = random::<u8>();
                    }
                    if seen.insert(octets) {
                        addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                        break;
                    }
                }
            }
        }
    }

    addresses
}

/// Number of addresses [`sample_addresses`] would produce, without allocating them.
///
/// Used for budget checks before materialization so `--all-ips` fails fast.
pub fn address_count(o: &CdnOptions) -> usize {
    let subnet_count: usize = published_v4_nets()
        .into_iter()
        .map(|net| subnets24(net).len())
        .sum();

    if o.all_ips {
        return subnet_count * 256;
    }

    let v4 = subnet_count * o.sample_per_subnet as usize;
    let v6 = if o.v6 {
        PUBLISHED_V6_SNAPSHOT.len() * o.v6_samples as usize
    } else {
        0
    };
    v4 + v6
}

/// Builds the CDN scan plan.
///
/// The module declares `RangePolicy::PublishedCdn`; v1 has no custom range input,
/// so there is no allowlist-violation path to check here. Budget and endpoint
/// checks use [`address_count`] before any address is materialized.
pub fn build_plan(opts: &ModuleOptions) -> Result<TargetPlan, ScanError> {
    let o = CdnOptions::try_from_options(opts)?;

    let count = address_count(&o);
    let plan_endpoints = count;
    let charged = plan_endpoints as u64 * (u64::from(o.attempts) + 1);

    if o.all_ips {
        return Err(ScanError::InvalidPlan(format!(
            "--all-ips plans {} targets and {} charged packets, over the {} charged-packet ceiling; use --sample-per-subnet 2 --scan-timeout 300",
            thousands(count as u64),
            thousands(charged),
            thousands(MAX_CHARGED_PACKETS),
        )));
    }

    if charged > MAX_CHARGED_PACKETS {
        return Err(ScanError::InvalidPlan(format!(
            "plan charges {} packets ({} targets x {} attempts plus warm-up), over the {} charged-packet ceiling",
            thousands(charged),
            thousands(count as u64),
            u64::from(o.attempts) + 1,
            thousands(MAX_CHARGED_PACKETS),
        )));
    }

    if plan_endpoints > MAX_PLAN_ENDPOINTS {
        return Err(ScanError::InvalidPlan(format!(
            "plan has {} endpoints, over the {} endpoint bound that keeps control events within the 1,024 allowance",
            thousands(plan_endpoints as u64),
            thousands(MAX_PLAN_ENDPOINTS as u64),
        )));
    }

    let probe_ms = per_probe_timeout(&o);
    let waves = count.div_ceil(o.concurrency);
    let latency_ms = waves as u64 * probe_ms;
    let speed_term_ms = if o.speed {
        let streams = if o.speed_min > 0.0 {
            10u64
        } else {
            (o.speed_count as u64).min(10)
        };
        streams * (o.speed_time_s) * 1000
    } else {
        0
    };
    let floor_ms = latency_ms + speed_term_ms;

    if (o.scan_timeout_s) * 1000 < floor_ms {
        let floor_s = floor_ms.div_ceil(1000);
        let message = if o.speed {
            format!(
                "scan timeout {}s is below the {}s floor ({} waves x {}ms per probe plus {}s of speed sampling); use --scan-timeout {}",
                o.scan_timeout_s,
                floor_s,
                waves,
                probe_ms,
                speed_term_ms / 1000,
                floor_s,
            )
        } else {
            format!(
                "scan timeout {}s is below the {}s floor ({} waves x {}ms per probe)",
                o.scan_timeout_s, floor_s, waves, probe_ms,
            )
        };
        return Err(ScanError::InvalidPlan(message));
    }

    let targets = sample_addresses(&o)
        .into_iter()
        .map(|addr| ScanTarget {
            addr,
            ports: vec![o.port],
        })
        .collect();

    Ok(TargetPlan {
        recipe: GenerationRecipe::default(),
        targets,
        plan_endpoints,
        stop_on_first_answer: false,
        attempts_per_probe: o.attempts,
        per_attempt_timeout: Duration::from_millis(o.timeout_per_probe_ms),
        probe_overhead: Duration::from_millis(1000),
        per_probe_timeout: Duration::from_millis(probe_ms),
        charged_packet_count: charged,
    })
}

/// Plan built from [`ModuleOptions::default`], for tests that need a valid plan.
pub fn default_plan_for_test() -> TargetPlan {
    build_plan(&ModuleOptions::default())
        .expect("default module options must build a valid CDN plan")
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.char_indices() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}
