use std::net::IpAddr;
use std::time::Duration;

use cftool_core::error::ScanError;
use cftool_core::module::RangePolicy;
use cftool_core::ranges::{
    MAX_CHARGED_PACKETS, MAX_PLAN_ENDPOINTS, PUBLISHED_V4_SNAPSHOT, PUBLISHED_V6_SNAPSHOT,
    RangeSource, WARP_V4_POOLS, WARP_V6_POOLS, cidr_fully_contained, contains, is_cloudflare_owned,
    published_cdn, validate_plan, warp_endpoint_pools,
};
use cftool_core::target::{GenerationRecipe, ScanTarget, TargetPlan};
use ipnet::IpNet;

fn make_plan(addrs: &[&str], endpoints: usize, packets: u64) -> TargetPlan {
    TargetPlan {
        recipe: GenerationRecipe::resolved(),
        targets: addrs
            .iter()
            .map(|s| ScanTarget {
                addr: s.parse::<IpAddr>().expect("test address parses"),
                ports: vec![2408],
            })
            .collect(),
        plan_endpoints: endpoints,
        stop_on_first_answer: false,
        attempts_per_probe: 1,
        per_attempt_timeout: Duration::from_millis(1500),
        probe_overhead: Duration::ZERO,
        per_probe_timeout: Duration::from_millis(1500),
        charged_packet_count: packets,
    }
}

fn parse_net(s: &str) -> IpNet {
    s.parse::<IpNet>().expect("test cidr parses")
}

#[test]
fn c1_warp_snapshot_plan_validates() {
    let plan = make_plan(&["8.6.112.5"], 1, 1);
    assert!(validate_plan(&plan, RangePolicy::WarpEndpointPools).is_ok());
    assert!(
        !contains(
            RangePolicy::PublishedCdn,
            "8.6.112.5".parse::<IpAddr>().unwrap()
        ),
        "8.6.112.5 must be WARP-only, not published CDN"
    );
}

#[test]
fn c1_published_snapshot_plan_validates() {
    let plan = make_plan(&["104.16.5.5"], 1, 1);
    assert!(validate_plan(&plan, RangePolicy::PublishedCdn).is_ok());
}

#[test]
fn c1_outside_declared_policy_is_allowlist_violation() {
    let plan = make_plan(&["192.0.2.1"], 1, 1);
    match validate_plan(&plan, RangePolicy::WarpEndpointPools) {
        Err(ScanError::AllowlistViolation(msg)) => {
            assert!(
                msg.contains("192.0.2.1"),
                "message should name the offending address, got: {msg}"
            );
        }
        other => panic!("expected AllowlistViolation, got {other:?}"),
    }
}

#[test]
fn c1_range_wins_over_budget() {
    let plan = make_plan(&["192.0.2.1"], 1, 300_000);
    const { assert!(300_000 > MAX_CHARGED_PACKETS) };
    match validate_plan(&plan, RangePolicy::WarpEndpointPools) {
        Err(ScanError::AllowlistViolation(_)) => {}
        Err(ScanError::InvalidPlan(msg)) => {
            panic!("range check must precede budget check, got InvalidPlan: {msg}")
        }
        other => panic!("expected AllowlistViolation, got {other:?}"),
    }
}

#[test]
fn c1_packet_ceiling_is_invalid_plan() {
    let plan = make_plan(&["8.6.112.5"], 1, 250_001);
    assert_eq!(250_001, MAX_CHARGED_PACKETS + 1);
    match validate_plan(&plan, RangePolicy::WarpEndpointPools) {
        Err(ScanError::InvalidPlan(msg)) => {
            assert!(
                msg.contains("250001"),
                "message should name the packet count, got: {msg}"
            );
        }
        other => panic!("expected InvalidPlan, got {other:?}"),
    }
}

#[test]
fn c1_endpoint_bound_is_invalid_plan() {
    let plan = make_plan(&["8.6.112.5"], 64_513, 1);
    assert_eq!(64_513, MAX_PLAN_ENDPOINTS + 1);
    match validate_plan(&plan, RangePolicy::WarpEndpointPools) {
        Err(ScanError::InvalidPlan(msg)) => {
            assert!(
                msg.contains(&MAX_PLAN_ENDPOINTS.to_string()),
                "message should name the endpoint bound {}, got: {msg}",
                MAX_PLAN_ENDPOINTS
            );
        }
        other => panic!("expected InvalidPlan, got {other:?}"),
    }
}

#[test]
fn c1_union_subset_invariant() {
    let all = PUBLISHED_V4_SNAPSHOT
        .iter()
        .chain(PUBLISHED_V6_SNAPSHOT.iter())
        .chain(WARP_V4_POOLS.iter())
        .chain(WARP_V6_POOLS.iter());
    for s in all {
        let net = parse_net(s);
        assert!(
            is_cloudflare_owned(net.network()),
            "{s} network address not owned"
        );
        assert!(
            is_cloudflare_owned(net.broadcast()),
            "{s} broadcast address not owned"
        );
    }
    assert!(!is_cloudflare_owned("192.0.2.1".parse().unwrap()));
}

#[test]
fn c1_custom_cidr_containment() {
    assert!(cidr_fully_contained(
        parse_net("188.114.96.0/22"),
        RangePolicy::WarpEndpointPools
    ));
    assert!(!cidr_fully_contained(
        parse_net("188.114.96.0/21"),
        RangePolicy::WarpEndpointPools
    ));
    assert!(cidr_fully_contained(
        parse_net("162.159.192.0/24"),
        RangePolicy::WarpEndpointPools
    ));
    assert!(!cidr_fully_contained(
        parse_net("104.16.0.0/13"),
        RangePolicy::WarpEndpointPools
    ));
}

#[test]
fn c2_snapshot_counts_and_parsing() {
    let published = published_cdn();
    assert_eq!(published.len(), 22);
    let warp = warp_endpoint_pools();
    assert_eq!(warp.len(), 16);

    for net in published {
        assert!(
            net.addr().is_ipv4() || net.addr().is_ipv6(),
            "published net {net} has no address family"
        );
    }
    for net in warp {
        assert!(
            net.addr().is_ipv4() || net.addr().is_ipv6(),
            "warp net {net} has no address family"
        );
    }

    for s in PUBLISHED_V4_SNAPSHOT.iter().chain(WARP_V4_POOLS.iter()) {
        assert!(parse_net(s).addr().is_ipv4(), "{s} should be IPv4");
    }
    for s in PUBLISHED_V6_SNAPSHOT.iter().chain(WARP_V6_POOLS.iter()) {
        assert!(parse_net(s).addr().is_ipv6(), "{s} should be IPv6");
    }
}

#[test]
fn c2_refresh_failure_falls_back_with_one_log() {
    let mut source = RangeSource::new();
    let mut logs: Vec<String> = Vec::new();
    let result =
        source.refresh_published(|| -> Result<String, ()> { Err(()) }, |msg| logs.push(msg));
    assert!(result.is_ok(), "fallback must succeed, got {result:?}");

    let expected = published_cdn();
    assert_eq!(
        source.published(),
        expected,
        "fallback snapshot must equal compiled snapshot"
    );
    assert_eq!(logs.len(), 1, "exactly one log line expected: {logs:?}");
    assert!(
        logs[0].contains("compiled snapshot"),
        "log should mention compiled snapshot, got: {}",
        logs[0]
    );
}

#[test]
fn c2_refresh_success_replaces_snapshot() {
    let mut source = RangeSource::new();
    let mut logs: Vec<String> = Vec::new();
    let result = source.refresh_published(
        || -> Result<String, ()> { Ok("103.21.244.0/22\n# comment\n\n173.245.48.0/20\n".into()) },
        |msg| logs.push(msg),
    );
    assert!(result.is_ok(), "refresh should succeed, got {result:?}");
    assert_eq!(source.published().len(), 2);
    assert!(!source.needs_refresh());
    assert!(logs.is_empty(), "no log expected on success, got: {logs:?}");
}

#[test]
fn c2_malformed_line_falls_back_with_one_log() {
    let mut source = RangeSource::new();
    let mut logs: Vec<String> = Vec::new();
    let result = source.refresh_published(
        || -> Result<String, ()> { Ok("not-a-cidr\n".into()) },
        |msg| logs.push(msg),
    );
    assert!(result.is_ok(), "fallback must succeed, got {result:?}");

    let expected = published_cdn();
    assert_eq!(
        source.published(),
        expected,
        "malformed input must leave compiled snapshot in place"
    );
    assert_eq!(logs.len(), 1, "exactly one log line expected: {logs:?}");
    assert!(
        logs[0].contains("not-a-cidr"),
        "log should name the malformed line, got: {}",
        logs[0]
    );
}
