//! Warp endpoint generation and plan validation.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::time::Duration;

use cftool_core::error::ScanError;
use cftool_core::module::RangePolicy;
use cftool_core::options::ModuleOptions;
use cftool_core::ranges::{WARP_V4_POOLS, WARP_V6_POOLS, cidr_fully_contained, validate_plan};
use cftool_core::target::{GenerationRecipe, ScanTarget, TargetPlan};
use ipnet::{IpNet, Ipv4Net};

#[cfg(not(feature = "mock"))]
use crate::identity::load_identity;
use crate::options::{
    PINNED_PORT, PORTS_FULL, PORTS_STANDARD, PoolMode, PortMode, WarpOptions, noise_datagrams,
    noise_overhead_ms,
};

const WALK_SEED: u32 = 0x57A9_1C3D;
const V6_MIN_SAMPLES: u32 = 64;
const CLASSIC_POOLS: usize = 6;
const HOSTS_PER_24: usize = 256;

/// Full-period LCG over `0..=255` (Hull-Dobell: `a = 77`, `c = 1`, modulus 256).
/// Each seed visits every byte exactly once per period; used to shuffle /24 host
/// indices without replacement (T1).
pub struct Lcg {
    state: u32,
}

impl Lcg {
    pub fn new(seed: u32) -> Self {
        Self { state: seed & 0xff }
    }

    pub fn next_byte(&mut self) -> u8 {
        self.state = (77 * self.state + 1) & 0xff;
        self.state as u8
    }
}

/// One full LCG period: all 256 distinct host bytes, shuffled.
pub fn lcg_walk24(seed: u32) -> Vec<u8> {
    let mut lcg = Lcg::new(seed);
    let mut out = Vec::with_capacity(HOSTS_PER_24);
    for _ in 0..HOSTS_PER_24 {
        out.push(lcg.next_byte());
    }
    out
}

pub fn ports_for(mode: PortMode) -> Vec<u16> {
    match mode {
        PortMode::Pinned => vec![PINNED_PORT],
        PortMode::Standard => PORTS_STANDARD.to_vec(),
        PortMode::Full => PORTS_FULL.to_vec(),
    }
}

fn parse_custom_cidrs(o: &WarpOptions) -> Result<Vec<Ipv4Net>, ScanError> {
    let mut nets = Vec::new();
    for raw in &o.cidr {
        let net: IpNet = raw.parse().map_err(|_| {
            ScanError::AllowlistViolation(format!("custom CIDR '{raw}' is not a valid CIDR"))
        })?;
        let v4 = match net {
            IpNet::V4(v4) => v4,
            IpNet::V6(_) => {
                return Err(ScanError::AllowlistViolation(format!(
                    "custom IPv6 CIDR '{raw}' is not accepted; warp v1 generates v6 endpoints \
                     from WARP_V6_POOLS (for example 2606:4700:d0::/48) and takes IPv4 custom input only"
                )));
            }
        };
        if v4.prefix_len() < 20 {
            return Err(ScanError::AllowlistViolation(format!(
                "custom CIDR '{raw}' is wider than the /20 minimum allowed for WARP endpoint pools"
            )));
        }
        if !cidr_fully_contained(IpNet::V4(v4), RangePolicy::WarpEndpointPools) {
            return Err(ScanError::AllowlistViolation(format!(
                "custom CIDR '{raw}' is outside the WARP endpoint pools; only published WARP \
                 ranges are scannable under the warp-endpoints range policy"
            )));
        }
        nets.push(v4);
    }
    Ok(nets)
}

/// Sample one IPv4 CIDR: every covered /24 is walked in LCG order and the first
/// `sample_per_subnet` host bytes are kept. Prefixes wider than /24 iterate
/// their /24 segments; narrower prefixes filter the single segment.
fn sample_v4_cidr(net: &Ipv4Net, sample_per_subnet: usize, salt: u32) -> Vec<Ipv4Addr> {
    let sample = sample_per_subnet.min(HOSTS_PER_24);
    let prefix = net.prefix_len();
    let first_base = u32::from(net.network()) & !0xff;
    let bases: Vec<u32> = if prefix >= 24 {
        vec![first_base]
    } else {
        let count = 1u32 << (24 - prefix);
        (0..count).map(|i| first_base + i * 256).collect()
    };
    let mut out = Vec::with_capacity(bases.len() * sample);
    for (segment, base) in bases.into_iter().enumerate() {
        let seed = WALK_SEED
            ^ salt
            ^ (base >> 8).wrapping_mul(0x9E37_79B9)
            ^ (segment as u32).wrapping_mul(0x85EB_CA6B);
        let mut lcg = Lcg::new(seed);
        let mut taken = 0;
        for _ in 0..HOSTS_PER_24 {
            if taken == sample {
                break;
            }
            let host = lcg.next_byte();
            let addr = Ipv4Addr::from(base | u32::from(host));
            if net.contains(&addr) {
                out.push(addr);
                taken += 1;
            }
        }
    }
    out
}

fn compiled_v4_pools() -> Vec<Ipv4Net> {
    WARP_V4_POOLS
        .iter()
        .map(|s| s.parse().expect("compiled WARP v4 pool must parse"))
        .collect()
}

fn sample_pools(pools: &[Ipv4Net], sample: usize, salt: u32) -> Vec<Ipv4Addr> {
    pools
        .iter()
        .enumerate()
        .flat_map(|(i, net)| sample_v4_cidr(net, sample, salt ^ i as u32))
        .collect()
}

fn v6_available() -> bool {
    TcpListener::bind("[::]:0").is_ok()
}

fn append_v6_addresses(out: &mut Vec<IpAddr>, seen: &mut HashSet<IpAddr>, samples: usize) {
    for pool_text in WARP_V6_POOLS {
        let pool: IpNet = pool_text.parse().expect("compiled WARP v6 pool must parse");
        let IpAddr::V6(prefix_addr) = pool.addr() else {
            continue;
        };
        let prefix = prefix_addr.octets();
        let mut added = 0;
        while added < samples {
            let mut octets = prefix;
            for byte in octets[6..].iter_mut() {
                *byte = rand::random::<u8>();
            }
            let addr = IpAddr::V6(Ipv6Addr::from(octets));
            if seen.insert(addr) {
                out.push(addr);
                added += 1;
            }
        }
    }
}

pub fn build_plan(opts: &ModuleOptions) -> Result<TargetPlan, ScanError> {
    // (a) options
    let o = WarpOptions::try_from_options(opts)?;

    // (b) range allowlist
    let custom = parse_custom_cidrs(&o)?;

    // (c) addresses
    let sample = o.sample_per_subnet as usize;
    let pools = compiled_v4_pools();
    let generated = match &o.pool {
        PoolMode::Custom => custom
            .iter()
            .enumerate()
            .flat_map(|(i, net)| sample_v4_cidr(net, sample, i as u32 + 1))
            .collect(),
        PoolMode::Default => sample_pools(&pools, sample, 0x100),
        PoolMode::Classic => sample_pools(&pools[..CLASSIC_POOLS], sample, 0x200),
    };

    let mut addresses = Vec::with_capacity(generated.len());
    let mut seen = HashSet::new();
    for addr in generated {
        let addr = IpAddr::V4(addr);
        if seen.insert(addr) {
            addresses.push(addr);
        }
    }

    if o.enable_v6 {
        if (o.v6_samples as u32) < V6_MIN_SAMPLES {
            return Err(ScanError::InvalidPlan(format!(
                "enable_v6 requires v6_samples >= {V6_MIN_SAMPLES} (got {})",
                o.v6_samples
            )));
        }
        if v6_available() {
            append_v6_addresses(&mut addresses, &mut seen, o.v6_samples as usize);
        }
    }

    // (d) ports and probe budget
    let ports = ports_for(o.port_mode);
    let stop_on_first_answer = matches!(&o.port_mode, PortMode::Full);
    let per_attempt_timeout = Duration::from_millis(o.timeout_per_probe_ms);
    let probe_overhead = Duration::from_millis(noise_overhead_ms(o.noise));
    let per_probe_timeout = probe_overhead + per_attempt_timeout;
    let plan_endpoints = (addresses.len() * ports.len()) as _;
    let charged_packet_count = (addresses.len() as u64 * ports.len() as u64)
        .saturating_mul(2 + noise_datagrams(o.noise) as u64);

    let targets: Vec<ScanTarget> = addresses
        .iter()
        .map(|&host| ScanTarget {
            addr: host,
            ports: ports.clone(),
        })
        .collect();

    let plan = TargetPlan {
        recipe: GenerationRecipe::default(),
        targets,
        plan_endpoints,
        stop_on_first_answer,
        attempts_per_probe: 1,
        per_attempt_timeout,
        probe_overhead,
        per_probe_timeout,
        charged_packet_count,
    };

    // (e) budget and invariants
    validate_plan(&plan, RangePolicy::WarpEndpointPools)?;

    let concurrency = o.concurrency as u64;
    if concurrency == 0 {
        return Err(ScanError::InvalidPlan(
            "warp plan needs concurrency >= 1".into(),
        ));
    }
    let waves = addresses.len().div_ceil(concurrency as usize) as u64;
    let floor_ms = waves
        .saturating_mul(ports.len() as u64)
        .saturating_mul(per_probe_timeout.as_millis() as u64);
    let floor = Duration::from_millis(floor_ms);
    let scan_timeout = Duration::from_secs(o.scan_timeout_secs);
    if floor > scan_timeout {
        let floor_secs = floor.as_secs() + if floor.subsec_nanos() > 0 { 1 } else { 0 };
        return Err(ScanError::InvalidPlan(format!(
            "warp plan needs at least {floor_secs}s scan_timeout: ceil({} addresses / {concurrency}) \
             = {waves} waves * {} ports * {}ms per probe; configured scan_timeout is {}s",
            addresses.len(),
            ports.len(),
            per_probe_timeout.as_millis(),
            scan_timeout.as_secs(),
        )));
    }

    // (f) identity, after every plan check
    #[cfg(not(feature = "mock"))]
    load_identity()?;

    #[cfg(feature = "mock")]
    {
        let _ = crate::identity::scripted_identity();
    }

    Ok(plan)
}

pub fn default_plan_for_test() -> TargetPlan {
    let opts = ModuleOptions::with_static_defaults(&crate::options::OPTIONS_SPEC);
    build_plan(&opts).expect("default warp options must produce a valid plan")
}
