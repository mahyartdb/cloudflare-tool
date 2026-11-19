use std::collections::HashSet;

use cftool_core::error::ScanError;
use cftool_core::options::{ModuleOptions, OptionValue};
use cftool_core::target::TargetPlan;

use cftool_warp::{
    API_VERSION, WarpError, build_plan, decode_key, default_plan_for_test, derive_wire_index,
    lcg_walk24, parse_wgcf, registration_hint, registration_rejected,
};

fn opts(pairs: &[(&str, OptionValue)]) -> ModuleOptions {
    let mut o = ModuleOptions::default();
    for (k, v) in pairs {
        o.set(*k, v.clone());
    }
    o
}

#[test]
fn t1_lcg_full_period() {
    let bytes = lcg_walk24(0x1234);
    assert_eq!(bytes.len(), 256, "lcg_walk24 must emit one byte per index");
    let unique: HashSet<u8> = bytes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        256,
        "lcg_walk24 must be a full-period permutation"
    );
    for b in 0u8..=255 {
        assert!(unique.contains(&b), "missing byte value {b}");
    }
}

#[test]
fn t2_custom_cidr_rules() {
    for s in [
        "104.16.0.0/13",
        "188.114.96.0/21",
        "188.114.96.0/19",
        "162.159.192.0/16",
        "2606:4700:d0::/48",
    ] {
        let o = opts(&[("cidr", OptionValue::List(vec![s.to_string()]))]);
        match build_plan(&o) {
            Err(ScanError::AllowlistViolation(msg)) => {
                if s.contains(':') {
                    assert!(
                        msg.contains("IPv6") || msg.contains("v1"),
                        "IPv6 rejection message must explain that custom v6 input is not supported: {msg}"
                    );
                }
            }
            Err(other) => panic!("expected AllowlistViolation for {s}, got {other:?}"),
            Ok(_) => panic!("expected rejection for custom cidr {s}"),
        }
    }

    #[cfg(feature = "mock")]
    {
        for s in ["188.114.96.0/22", "162.159.192.0/24"] {
            let o = opts(&[("cidr", OptionValue::List(vec![s.to_string()]))]);
            assert!(
                build_plan(&o).is_ok(),
                "cidr {s} is inside the WARP pools and at least /20"
            );
        }
    }
}

#[test]
fn t2_order_range_before_budget() {
    let o = opts(&[
        ("cidr", OptionValue::List(vec!["104.16.0.0/13".to_string()])),
        ("scan-timeout", OptionValue::Number(1.0)),
    ]);
    match build_plan(&o) {
        Err(ScanError::AllowlistViolation(_)) => {}
        Err(other) => panic!("range validation must precede budget validation, got {other:?}"),
        Ok(_) => panic!("expected an error"),
    }
}

#[test]
fn t3_default_plan_invariants() {
    let p: TargetPlan = default_plan_for_test();
    assert_eq!(p.plan_endpoints, 3584);
    assert_eq!(p.charged_packet_count, 25088);
    assert!(!p.stop_on_first_answer);
}

#[test]
fn t3_full_default_rejected() {
    let o = opts(&[
        ("port-mode", OptionValue::Text("full".to_string())),
        ("noise", OptionValue::Text("off".to_string())),
    ]);
    match build_plan(&o) {
        Err(ScanError::InvalidPlan(_)) => {}
        Err(other) => panic!("full default must be rejected as InvalidPlan, got {other:?}"),
        Ok(_) => panic!("full default breaches the packet ceiling and the timeout floor"),
    }
}

#[test]
fn t3_result_lane_bound() {
    let o = opts(&[
        ("port-mode", OptionValue::Text("full".to_string())),
        ("noise", OptionValue::Text("off".to_string())),
        ("sample-per-subnet", OptionValue::Number(100.0)),
        ("scan-timeout", OptionValue::Number(300.0)),
    ]);
    match build_plan(&o) {
        Err(ScanError::InvalidPlan(msg)) => {
            assert!(
                msg.contains("75600"),
                "message must name the 75600 endpoints: {msg}"
            );
            assert!(
                msg.contains("64512"),
                "message must name the 64512 limit: {msg}"
            );
        }
        Err(other) => panic!("expected InvalidPlan for the oversized endpoint set, got {other:?}"),
        Ok(_) => panic!("75600 endpoints exceed the 64512 limit"),
    }
}

#[test]
fn t6_registration_status_mapping() {
    match registration_rejected(404, API_VERSION) {
        ScanError::RegistrationRejected { status, .. } => assert_eq!(status, 404),
        other => panic!("expected RegistrationRejected, got {other:?}"),
    }
    assert!(registration_hint(404).contains("version"));
    assert!(registration_hint(403).contains("fingerprint"));
    let h429 = registration_hint(429);
    assert!(
        h429.contains("rate") || h429.contains("later"),
        "hint was: {h429}"
    );
}

const WGCF_OK: &str = "[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
Reserved = 0,0,0
";

#[test]
fn t9_wgcf_parse() {
    let id = parse_wgcf(WGCF_OK).expect("a valid wgcf config must parse");
    assert_eq!(decode_key(&id.private_key), Some([0u8; 32]));
    assert_eq!(decode_key(&id.peer_public_key), Some([0u8; 32]));
    assert_eq!(id.endpoint, "162.159.192.1:2408");
    assert_eq!(id.reserved, [0u8, 0, 0]);

    let bad_key = "[Interface]
PrivateKey = not-base64!
Address = 172.16.0.2/32

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 162.159.192.1:2408
Reserved = 0,0,0
";
    match parse_wgcf(bad_key) {
        Err(WarpError::Import { field, .. }) => {
            assert!(
                field.to_lowercase().contains("private"),
                "field must name the private key, got {field}"
            );
        }
        other => panic!("expected an Import error for the malformed private key, got {other:?}"),
    }

    let no_endpoint = "[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Reserved = 0,0,0
";
    match parse_wgcf(no_endpoint) {
        Err(WarpError::Import { field, .. }) => {
            assert!(
                field.to_lowercase().contains("endpoint"),
                "field must name the endpoint, got {field}"
            );
        }
        other => panic!("expected an Import error for the missing endpoint, got {other:?}"),
    }
}

#[test]
fn t9_key_helpers() {
    assert_eq!(derive_wire_index(1), 257);
    assert_eq!(
        decode_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        Some([0u8; 32])
    );
    assert_eq!(decode_key("!!!"), None);
}
