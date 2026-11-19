use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use cftool_core::config::{Config, ConfigError, validate_config};
use cftool_core::mock::{
    ScriptLoadError, ScriptPlan, ScriptTarget, ScriptVerdict, ScriptedProbeSource,
};
use cftool_core::options::{
    ModuleOptions, OptionDefault, OptionKind, OptionSpec, OptionValue, OptionsSpec,
};
use cftool_core::output::{write_csv, write_json};
use cftool_core::probe::{AliveKind, DeadReason, ProbeSource, ProbeVerdict};
use cftool_core::result::{
    CellValue, ColumnSpec, FindingRow, ModuleFinding, ModuleId, ScanSummary, ScanTotals,
};
use cftool_core::target::{ProbeBudget, ProbeTarget};

struct DummyFinding;

impl ModuleFinding for DummyFinding {
    fn sort_rank(&self) -> Option<u64> {
        Some(1)
    }

    fn to_row(&self) -> FindingRow {
        FindingRow {
            columns: vec![
                ("addr".to_string(), CellValue::Text("1.2.3.4".to_string())),
                ("rtt_ms".to_string(), CellValue::Number(12.5)),
                ("note".to_string(), CellValue::Null),
            ],
        }
    }

    fn is_filtered(&self) -> bool {
        false
    }
}

fn sample_summary(started_at: OffsetDateTime, wall_time: Duration) -> ScanSummary {
    ScanSummary {
        module_id: ModuleId::new("warp"),
        started_at,
        wall_time,
        totals: ScanTotals {
            probed: 3,
            alive: 1,
            filtered: 1,
            cancelled: false,
        },
        findings: vec![Box::new(DummyFinding)],
    }
}

fn epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(0).expect("epoch is representable")
}

fn sorted_keys(map: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

const NO_OPTIONS: &[OptionSpec] = &[];

fn empty_options() -> ModuleOptions {
    ModuleOptions::with_static_defaults(&OptionsSpec {
        entries: NO_OPTIONS,
    })
}

fn budget(cancel: &CancellationToken, per_attempt_timeout: Duration) -> ProbeBudget {
    ProbeBudget {
        per_attempt_timeout,
        max_attempts: 1,
        overhead: Duration::from_millis(0),
        cancel: cancel.clone(),
    }
}

#[test]
fn json_summary_has_contract_keys() {
    let summary = sample_summary(epoch(), Duration::from_millis(1500));
    let value = serde_json::to_value(&summary).expect("summary must serialize");

    let object = value
        .as_object()
        .expect("summary must serialize to a JSON object");
    assert_eq!(
        sorted_keys(object),
        ["findings", "module", "started_at", "totals", "wall_time"]
    );

    assert_eq!(value["module"], serde_json::json!("warp"));
    assert_eq!(
        value["wall_time"].as_u64(),
        Some(1500),
        "wall_time must be integer milliseconds"
    );

    let totals = value["totals"]
        .as_object()
        .expect("totals must be a JSON object");
    assert_eq!(
        sorted_keys(totals),
        ["alive", "cancelled", "filtered", "probed"]
    );

    let findings = value["findings"]
        .as_array()
        .expect("findings must be a JSON array");
    assert_eq!(findings.len(), 1);
    let finding = findings[0]
        .as_object()
        .expect("a finding must be a JSON object");
    assert_eq!(sorted_keys(finding), ["addr", "note", "rtt_ms"]);
}

#[test]
fn started_at_is_rfc3339() {
    let summary = sample_summary(epoch(), Duration::from_millis(1));
    let value = serde_json::to_value(&summary).expect("summary must serialize");

    assert_eq!(
        value["started_at"],
        serde_json::json!("1970-01-01T00:00:00Z")
    );
}

#[test]
fn csv_float_rendering() {
    const COLUMNS: [ColumnSpec; 3] = [
        ColumnSpec {
            key: "a",
            header: "Alpha",
        },
        ColumnSpec {
            key: "b",
            header: "Beta",
        },
        ColumnSpec {
            key: "c",
            header: "Gamma",
        },
    ];
    let rows = [FindingRow {
        columns: vec![
            ("a".to_string(), CellValue::Number(12.0)),
            ("b".to_string(), CellValue::Number(12.5)),
            ("c".to_string(), CellValue::Number(12.125)),
        ],
    }];

    let mut out = Vec::new();
    write_csv(&COLUMNS, &rows, &mut out).expect("csv must be written");

    let text = String::from_utf8(out).expect("csv must be utf-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "expected a header line and one data line");
    assert_eq!(lines[0], "Alpha,Beta,Gamma");
    assert_eq!(lines[1], "12,12.5,12.125");
}

#[test]
fn csv_null_and_missing_render_empty_and_lf_only() {
    const COLUMNS: [ColumnSpec; 3] = [
        ColumnSpec {
            key: "a",
            header: "A",
        },
        ColumnSpec {
            key: "b",
            header: "B",
        },
        ColumnSpec {
            key: "c",
            header: "C",
        },
    ];
    // Column "c" is intentionally absent from the row.
    let rows = [FindingRow {
        columns: vec![
            ("a".to_string(), CellValue::Null),
            ("b".to_string(), CellValue::Text("x".to_string())),
        ],
    }];

    let mut out = Vec::new();
    write_csv(&COLUMNS, &rows, &mut out).expect("csv must be written");

    let text = String::from_utf8(out).expect("csv must be utf-8");
    assert!(!text.contains('\r'), "csv must use LF only");
    assert!(text.ends_with('\n'), "csv must end with LF");

    let segments: Vec<&str> = text.split('\n').collect();
    assert_eq!(
        segments.len(),
        3,
        "header and data line must each be LF terminated"
    );
    assert_eq!(segments[2], "", "no content may follow the final LF");
    assert_eq!(segments[0], "A,B,C");
    assert_eq!(
        segments[1], ",x,",
        "null and missing cells must render empty"
    );
}

#[test]
fn json_null_is_json_null() {
    let summary = sample_summary(epoch(), Duration::from_millis(1));
    let mut out = Vec::new();
    write_json(&summary, &mut out).expect("json must be written");

    let value: serde_json::Value = serde_json::from_slice(&out).expect("json output must parse");
    let note = &value["findings"][0]["note"];
    assert!(
        note.is_null(),
        "CellValue::Null must serialize as JSON null, got {note}"
    );
}

#[test]
fn option_static_defaults_vs_module_resolved() {
    const ENTRIES: &[OptionSpec] = &[
        OptionSpec {
            key: "concurrency",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(64.0),
            },
            default: OptionDefault::Static(OptionValue::Number(5.0)),
            help: "static default",
        },
        OptionSpec {
            key: "cidr",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "resolved by the module",
        },
    ];
    let spec = OptionsSpec { entries: ENTRIES };

    let mut options = ModuleOptions::with_static_defaults(&spec);
    assert!(
        options.get("concurrency").is_some(),
        "static default must be seeded"
    );
    assert!(
        options.get("cidr").is_none(),
        "module-resolved option must not be seeded"
    );

    options.set("cidr", OptionValue::Text("1.2.3.0/24".to_string()));
    let cidr = options.get("cidr").expect("set value must be readable");
    match cidr {
        OptionValue::Text(text) => assert_eq!(text, "1.2.3.0/24"),
        _ => panic!("cidr must be text"),
    }
}

#[tokio::test]
async fn scripted_probe_verdict_mapping() {
    let ip: IpAddr = "1.2.3.4".parse().expect("valid address");
    let source = ScriptedProbeSource::new(vec![
        ScriptTarget {
            ip,
            port: 1,
            verdict: ScriptVerdict::Alive,
            rtt_ms: Some(5),
        },
        ScriptTarget {
            ip,
            port: 2,
            verdict: ScriptVerdict::Cookie,
            rtt_ms: None,
        },
        ScriptTarget {
            ip,
            port: 3,
            verdict: ScriptVerdict::Dead,
            rtt_ms: None,
        },
    ]);
    let options = empty_options();
    let probe = source.probe(&options);
    let cancel = CancellationToken::new();

    let first = probe
        .probe(
            ProbeTarget { addr: ip, port: 1 },
            budget(&cancel, Duration::from_secs(1)),
        )
        .await;
    match &first.verdict {
        ProbeVerdict::Alive { rtt, detail } => {
            assert_eq!(*rtt, Some(Duration::from_millis(5)));
            assert!(
                matches!(&detail.kind, AliveKind::Type2Response),
                "alive script target must report Type2Response"
            );
        }
        _ => panic!("port 1 must be Alive"),
    }
    assert_eq!(first.attempts.tries_made, 1);
    assert_eq!(first.attempts.tries_succeeded, 1);

    let second = probe
        .probe(
            ProbeTarget { addr: ip, port: 2 },
            budget(&cancel, Duration::from_secs(1)),
        )
        .await;
    match &second.verdict {
        ProbeVerdict::Alive { rtt, detail } => {
            assert!(rtt.is_none(), "cookie verdict carries no rtt");
            assert!(
                matches!(&detail.kind, AliveKind::Cookie),
                "cookie script target must report Cookie"
            );
        }
        _ => panic!("port 2 must be Alive"),
    }
    assert_eq!(second.attempts.tries_made, 1);
    assert_eq!(second.attempts.tries_succeeded, 1);

    let third = probe
        .probe(
            ProbeTarget { addr: ip, port: 3 },
            budget(&cancel, Duration::from_secs(1)),
        )
        .await;
    assert!(
        matches!(
            &third.verdict,
            ProbeVerdict::Dead {
                reason: DeadReason::Timeout
            }
        ),
        "port 3 must be Dead/Timeout"
    );
    assert_eq!(third.attempts.tries_made, 1);
    assert_eq!(third.attempts.tries_succeeded, 0);
}

#[tokio::test]
async fn scripted_probe_cancellation_overrides() {
    let ip: IpAddr = "1.2.3.4".parse().expect("valid address");
    let source = ScriptedProbeSource::new(vec![ScriptTarget {
        ip,
        port: 1,
        verdict: ScriptVerdict::Alive,
        rtt_ms: Some(1000),
    }]);
    let options = empty_options();
    let probe = source.probe(&options);
    let cancel = CancellationToken::new();

    let future = probe.probe(
        ProbeTarget { addr: ip, port: 1 },
        budget(&cancel, Duration::from_secs(2)),
    );
    // Cancel before the first poll so the outcome does not depend on timing.
    cancel.cancel();
    let outcome = future.await;

    assert!(
        matches!(
            &outcome.verdict,
            ProbeVerdict::Dead {
                reason: DeadReason::Cancelled
            }
        ),
        "a cancelled probe must report Dead/Cancelled"
    );
    assert_eq!(
        outcome.attempts.tries_succeeded, 0,
        "a cancelled probe must not record a succeeded try"
    );
}

#[test]
fn config_engine_unknown_key_is_error() {
    let mut engine = BTreeMap::new();
    engine.insert("bogus".to_string(), serde_json::Value::Bool(true));
    let config = Config {
        engine,
        modules: BTreeMap::new(),
        gui: BTreeMap::new(),
    };

    match validate_config(&config, &BTreeSet::new(), &BTreeMap::new()) {
        Err(ConfigError::UnknownKey { key, section }) => {
            assert_eq!(key, "bogus");
            assert_eq!(section, "engine");
        }
        _ => panic!("unknown engine key must be ConfigError::UnknownKey"),
    }
}

#[test]
fn config_stale_module_section_is_warning() {
    let mut modules: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
    modules.insert("gone".to_string(), BTreeMap::new());
    let config = Config {
        engine: BTreeMap::new(),
        modules,
        gui: BTreeMap::new(),
    };

    match validate_config(&config, &BTreeSet::new(), &BTreeMap::new()) {
        Ok(warnings) => {
            assert_eq!(warnings.len(), 1, "expected exactly one warning");
            assert!(
                warnings[0].contains("gone"),
                "warning must name the stale module, got: {}",
                warnings[0]
            );
        }
        Err(_) => panic!("a stale module section must be a warning, not an error"),
    }
}

#[test]
fn config_registered_module_unknown_key_is_error() {
    let mut warp = BTreeMap::new();
    warp.insert("bogus".to_string(), serde_json::Value::Bool(true));
    let mut modules: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
    modules.insert("warp".to_string(), warp);
    let config = Config {
        engine: BTreeMap::new(),
        modules,
        gui: BTreeMap::new(),
    };

    let mut registered = BTreeSet::new();
    registered.insert("warp".to_string());
    let mut module_keys: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    module_keys.insert(
        "warp".to_string(),
        ["cidr".to_string()].into_iter().collect(),
    );

    match validate_config(&config, &registered, &module_keys) {
        Err(ConfigError::UnknownKey { key, section }) => {
            assert_eq!(key, "bogus");
            assert_eq!(section, "modules.warp");
        }
        _ => panic!("unknown key in a registered module section must be ConfigError::UnknownKey"),
    }
}

#[test]
fn script_alive_requires_rtt_ms() {
    let ip: IpAddr = "1.2.3.4".parse().expect("valid address");
    let plan = ScriptPlan {
        targets: vec![ScriptTarget {
            ip,
            port: 443,
            verdict: ScriptVerdict::Alive,
            rtt_ms: None,
        }],
    };

    match plan.validate() {
        Err(ScriptLoadError::Invalid(message)) => {
            assert!(
                !message.trim().is_empty(),
                "Invalid must explain the missing rtt_ms"
            );
        }
        _ => panic!("Alive target without rtt_ms must be rejected as ScriptLoadError::Invalid"),
    }
}

#[cfg(feature = "mock")]
#[test]
fn apply_script_rewrites_targets_and_denominator() {
    use cftool_core::mock::apply_script;
    use cftool_core::target::{GenerationRecipe, TargetPlan};

    let mut plan = TargetPlan {
        recipe: GenerationRecipe {
            start: Some("1.2.3.0".parse().expect("valid address")),
            count: 10,
        },
        targets: Vec::new(),
        plan_endpoints: 10,
        stop_on_first_answer: true,
        attempts_per_probe: 3,
        per_attempt_timeout: Duration::from_millis(1200),
        probe_overhead: Duration::from_millis(50),
        per_probe_timeout: Duration::from_secs(5),
        charged_packet_count: 3,
    };
    let script = ScriptPlan {
        targets: vec![
            ScriptTarget {
                ip: "1.1.1.1".parse().expect("valid address"),
                port: 1,
                verdict: ScriptVerdict::Alive,
                rtt_ms: Some(5),
            },
            ScriptTarget {
                ip: "1.1.1.1".parse().expect("valid address"),
                port: 2,
                verdict: ScriptVerdict::Alive,
                rtt_ms: Some(7),
            },
            ScriptTarget {
                ip: "2.2.2.2".parse().expect("valid address"),
                port: 3,
                verdict: ScriptVerdict::Dead,
                rtt_ms: None,
            },
        ],
    };

    apply_script(&mut plan, &script);

    assert_eq!(
        plan.plan_endpoints, 3,
        "endpoint denominator must follow the script"
    );
    assert_eq!(
        plan.targets.len(),
        2,
        "script targets must be grouped by address"
    );
    let mut ports: Vec<Vec<u16>> = plan
        .targets
        .iter()
        .map(|target| target.ports.clone())
        .collect();
    ports.sort();
    assert_eq!(ports, vec![vec![1u16, 2], vec![3]]);
}
