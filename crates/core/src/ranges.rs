//! Cloudflare-owned range snapshots and declared range-policy checks.
//!
//! Range decisions run against one of two declared policies:
//!
//! - `RangePolicy::PublishedCdn`: the published Cloudflare CDN list.
//! - `RangePolicy::WarpEndpointPools`: the published WARP endpoint pools.
//!
//! WARP's 8.x pools are Cloudflare-owned but absent from the published CDN
//! list. A module's declared policy is therefore the only thing a plan is
//! checked against, never one global list. The union of both snapshots marks
//! the boundary of what Cloudflare owns; it is a test-time invariant, not a
//! runtime check.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ipnet::IpNet;

use crate::error::ScanError;
use crate::module::RangePolicy;
use crate::target::TargetPlan;

pub const MAX_CHARGED_PACKETS: u64 = 250_000;
pub const MAX_PLAN_ENDPOINTS: usize = 64_512;

pub const PUBLISHED_V4_SNAPSHOT: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

pub const PUBLISHED_V6_SNAPSHOT: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

pub const WARP_V4_POOLS: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "8.6.112.0/24",
    "8.34.70.0/24",
    "8.34.146.0/24",
    "8.35.211.0/24",
    "8.39.125.0/24",
    "8.39.204.0/24",
    "8.39.214.0/24",
    "8.47.69.0/24",
];

pub const WARP_V6_POOLS: &[&str] = &["2606:4700:d0::/48", "2606:4700:d1::/48"];

const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

fn parse_all(entries: &[&str]) -> Vec<IpNet> {
    entries
        .iter()
        .map(|entry| entry.parse().expect("compiled range snapshot must parse"))
        .collect()
}

pub fn published_cdn() -> &'static [IpNet] {
    static SNAPSHOT: OnceLock<Vec<IpNet>> = OnceLock::new();
    SNAPSHOT.get_or_init(|| {
        let mut nets = parse_all(PUBLISHED_V4_SNAPSHOT);
        nets.extend(parse_all(PUBLISHED_V6_SNAPSHOT));
        nets
    })
}

pub fn warp_endpoint_pools() -> &'static [IpNet] {
    static SNAPSHOT: OnceLock<Vec<IpNet>> = OnceLock::new();
    SNAPSHOT.get_or_init(|| {
        let mut nets = parse_all(WARP_V4_POOLS);
        nets.extend(parse_all(WARP_V6_POOLS));
        nets
    })
}

pub fn policy_networks(policy: RangePolicy) -> &'static [IpNet] {
    match policy {
        RangePolicy::PublishedCdn => published_cdn(),
        RangePolicy::WarpEndpointPools => warp_endpoint_pools(),
    }
}

/// True iff `addr` falls inside any network of either compiled snapshot.
pub fn is_cloudflare_owned(addr: IpAddr) -> bool {
    published_cdn()
        .iter()
        .chain(warp_endpoint_pools())
        .any(|net| net.contains(&addr))
}

/// Membership in the declared policy's networks only.
///
/// This is the only runtime plan check. There is no second union check:
/// union membership is a test-time invariant only.
pub fn contains(policy: RangePolicy, addr: IpAddr) -> bool {
    policy_networks(policy)
        .iter()
        .any(|net| net.contains(&addr))
}

/// True iff every address in `net` lies inside the declared policy's COVERAGE,
/// which may span several contiguous networks (a /22 over four WARP /24s).
///
/// Used for module custom-CIDR input: the Union is not a way around a
/// module's narrower declared policy.
pub fn cidr_fully_contained(net: IpNet, policy: RangePolicy) -> bool {
    covered_by(net, policy_networks(policy))
}

fn covered_by(net: IpNet, declared: &[IpNet]) -> bool {
    let (network, broadcast) = (net.network(), net.broadcast());
    if declared
        .iter()
        .any(|d| d.contains(&network) && d.contains(&broadcast))
    {
        return true;
    }
    let max_prefix = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if net.prefix_len() >= max_prefix {
        return false;
    }
    match net.subnets(net.prefix_len() + 1) {
        Ok(mut halves) => halves.all(|half| covered_by(half, declared)),
        Err(_) => false,
    }
}

/// Validates a target plan against the declared range policy, the plan shape,
/// and the charged packet budget.
///
/// The order is load-bearing: a range violation wins over a budget violation.
/// Option validation (step 1) and identity (step 4) are module-owned; core
/// owns range and budget. The result-lane endpoint bound is a plan-time
/// `InvalidPlan`.
pub fn validate_plan(plan: &TargetPlan, policy: RangePolicy) -> Result<(), ScanError> {
    for target in &plan.targets {
        if !contains(policy, target.addr) {
            return Err(ScanError::AllowlistViolation(format!(
                "address {} is outside the declared range policy",
                target.addr
            )));
        }
    }

    if plan.plan_endpoints > MAX_PLAN_ENDPOINTS {
        return Err(ScanError::InvalidPlan(format!(
            "plan endpoint count {} exceeds the plan-time bound {}",
            plan.plan_endpoints, MAX_PLAN_ENDPOINTS
        )));
    }

    if plan.charged_packet_count > MAX_CHARGED_PACKETS {
        return Err(ScanError::InvalidPlan(format!(
            "charged packet count {} exceeds the charged packet ceiling {}",
            plan.charged_packet_count, MAX_CHARGED_PACKETS
        )));
    }

    Ok(())
}

/// Compiled published CDN snapshot that a refresh may replace at runtime.
///
/// The real HTTP fetch and 24 h disk cache are wired when a frontend or module
/// adds an HTTP client. Until then this seam is the fallback contract: a
/// refresh never fails hard and never leaves the tool without a compiled
/// snapshot.
pub struct RangeSource {
    published: Vec<IpNet>,
    refreshed_at: Option<Instant>,
}

impl RangeSource {
    pub fn new() -> Self {
        Self {
            published: published_cdn().to_vec(),
            refreshed_at: None,
        }
    }

    pub fn published(&self) -> &[IpNet] {
        &self.published
    }

    /// True while no refresh has succeeded or the last one is 24 h old.
    pub fn needs_refresh(&self) -> bool {
        match self.refreshed_at {
            None => true,
            Some(at) => at.elapsed() >= REFRESH_INTERVAL,
        }
    }

    pub fn refresh_published<F, E, L>(&mut self, fetch: F, log: L) -> Result<(), E>
    where
        F: FnOnce() -> Result<String, E>,
        L: FnOnce(String),
    {
        let text = match fetch() {
            Ok(text) => text,
            Err(_) => {
                log("published range refresh failed; using compiled snapshot".to_string());
                return Ok(());
            }
        };

        let mut parsed = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.parse::<IpNet>() {
                Ok(net) => parsed.push(net),
                Err(_) => {
                    log(format!(
                        "published range refresh rejected line {line:?}; using compiled snapshot"
                    ));
                    return Ok(());
                }
            }
        }

        if parsed.is_empty() {
            log("published range refresh returned no ranges; using compiled snapshot".to_string());
            return Ok(());
        }

        self.published = parsed;
        self.refreshed_at = Some(Instant::now());
        Ok(())
    }
}

impl Default for RangeSource {
    fn default() -> Self {
        Self::new()
    }
}
