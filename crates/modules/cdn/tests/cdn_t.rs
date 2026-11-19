use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use cftool_core::error::ScanError;
use cftool_core::options::{ModuleOptions, OptionValue};
use cftool_core::probe::AttemptRecord;

use cftool_cdn::{
    CdnOptions, address_count, build_plan, extract_colo, loss_pct, mean_rtt_us, published_v4_nets,
    sample_addresses, subnets24,
};

fn opts(pairs: &[(&str, OptionValue)]) -> ModuleOptions {
    let mut options = ModuleOptions::default();
    for (key, value) in pairs {
        options.set(*key, value.clone());
    }
    options
}

fn expect_invalid_plan(options: &ModuleOptions) -> String {
    match build_plan(options) {
        Err(ScanError::InvalidPlan(message)) => message,
        Err(_) => panic!("expected InvalidPlan, got a different error"),
        Ok(_) => panic!("expected InvalidPlan, got a plan"),
    }
}

fn expect_options_invalid(options: &ModuleOptions) {
    match build_plan(options) {
        Err(ScanError::OptionsInvalid { .. }) => {}
        Err(_) => panic!("expected OptionsInvalid, got a different error"),
        Ok(_) => panic!("expected OptionsInvalid, got a plan"),
    }
}

#[test]
fn t1_sampler_counts() {
    let nets = published_v4_nets();
    assert_eq!(nets.len(), 15);

    let total_subnets24: usize = nets.iter().map(|net| subnets24(*net).len()).sum();
    assert_eq!(total_subnets24, 5_956);

    let defaults = CdnOptions::default();
    assert_eq!(address_count(&defaults), 5_956);
    assert_eq!(sample_addresses(&defaults).len(), 5_956);

    let doubled = CdnOptions {
        sample_per_subnet: 2,
        ..Default::default()
    };
    assert_eq!(address_count(&doubled), 11_912);
    let sampled = sample_addresses(&doubled);
    assert_eq!(sampled.len(), 11_912);

    let mut per_subnet24: BTreeMap<u32, Vec<IpAddr>> = BTreeMap::new();
    for address in &sampled {
        match *address {
            IpAddr::V4(v4) => per_subnet24
                .entry(u32::from(v4) & 0xFFFF_FF00)
                .or_default()
                .push(*address),
            IpAddr::V6(_) => panic!("v4-only sampling returned a v6 address"),
        }
    }
    for (prefix, addresses) in &per_subnet24 {
        let unique: BTreeSet<IpAddr> = addresses.iter().copied().collect();
        assert_eq!(
            unique.len(),
            addresses.len(),
            "duplicate sampled address in /24 {prefix:#010x}"
        );
    }
}

#[test]
fn t1_v6_sampling() {
    let options = CdnOptions {
        v6: true,
        v6_samples: 16,
        ..Default::default()
    };

    assert_eq!(address_count(&options), 6_068);
    let sampled = sample_addresses(&options);
    assert_eq!(sampled.len(), 6_068);

    let unique: BTreeSet<IpAddr> = sampled.iter().copied().collect();
    assert_eq!(
        unique.len(),
        sampled.len(),
        "v6 sampling produced duplicate addresses"
    );
}

#[test]
fn t2_all_ips_rejected_with_remedy() {
    let options = opts(&[("all-ips", OptionValue::Bool(true))]);
    let message = expect_invalid_plan(&options);
    assert!(
        message.contains("7,623,680"),
        "total address count missing from: {message}"
    );
    assert!(
        message.contains("250,000"),
        "250000 packet cap missing from: {message}"
    );
    assert!(
        message.contains("1,524,736"),
        "charged packet count missing from: {message}"
    );
    assert!(
        message.contains("--sample-per-subnet 2 --scan-timeout 300"),
        "remedy missing from: {message}"
    );
}

#[test]
fn t2_floor_and_options_errors() {
    let options = opts(&[("scan-timeout", OptionValue::Number(120.0))]);
    let message = expect_invalid_plan(&options);
    assert!(
        message.contains("150"),
        "150s scan timeout floor missing from: {message}"
    );

    let options = opts(&[("speed", OptionValue::Bool(true))]);
    let message = expect_invalid_plan(&options);
    assert!(
        message.contains("250"),
        "250s speed test minimum missing from: {message}"
    );
    assert!(
        message.contains("--scan-timeout 250"),
        "speed test remedy missing from: {message}"
    );

    let invalid: Vec<ModuleOptions> = vec![
        opts(&[("concurrency", OptionValue::Number(513.0))]),
        opts(&[
            ("mode", OptionValue::Text("http".to_string())),
            ("concurrency", OptionValue::Number(201.0)),
        ]),
        opts(&[("speed-count", OptionValue::Number(11.0))]),
        opts(&[("speed-max-bytes", OptionValue::Number(513.0))]),
        opts(&[("attempts", OptionValue::Number(3.0))]),
        opts(&[("sample-per-subnet", OptionValue::Number(257.0))]),
        opts(&[("v6-samples", OptionValue::Number(0.0))]),
    ];
    for options in &invalid {
        expect_options_invalid(options);
    }

    let options = opts(&[("cfcolo", OptionValue::List(vec!["FRA".to_string()]))]);
    expect_options_invalid(&options);
}

#[test]
fn t2_endpoint_bound() {
    let over = opts(&[
        ("mode", OptionValue::Text("http".to_string())),
        ("sample-per-subnet", OptionValue::Number(11.0)),
        ("scan-timeout", OptionValue::Number(1000.0)),
    ]);
    let message = expect_invalid_plan(&over);
    assert!(
        message.contains("65,516"),
        "65516 endpoint count missing from: {message}"
    );
    assert!(
        message.contains("64,512"),
        "64512 endpoint bound missing from: {message}"
    );

    let fits = opts(&[
        ("mode", OptionValue::Text("http".to_string())),
        ("sample-per-subnet", OptionValue::Number(10.0)),
        ("scan-timeout", OptionValue::Number(900.0)),
    ]);
    match build_plan(&fits) {
        Ok(plan) => assert_eq!(plan.plan_endpoints, 59_560),
        Err(_) => panic!("expected 59560 endpoints to fit the plan bound"),
    }
}

#[test]
fn t6_colo_extraction() {
    assert_eq!(
        extract_colo("abc-123-FRA", Some("cloudflare")),
        Some("FRA".to_string())
    );
    assert_eq!(extract_colo("abc-123-FRA", Some("nginx")), None);
    assert_eq!(extract_colo("abc-123-FRA", None), None);
    assert_eq!(
        extract_colo("123-FRA", Some("cloudflare")),
        Some("FRA".to_string())
    );
}

#[test]
fn t8_attempt_math() {
    let record = AttemptRecord {
        tries_made: 4,
        tries_succeeded: 3,
        try_rtts_us: vec![1000, 2000, 3000],
    };
    assert_eq!(loss_pct(&record), 25.0);
    assert_eq!(mean_rtt_us(&record), 2000);
}
