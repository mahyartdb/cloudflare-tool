//! GUI-side acceptance: module registry (G1) and export byte parity (G8).

use cftool_core::module::ModuleRegistry;
use cftool_core::result::{
    CellValue, ColumnSpec, FindingRow, ModuleFinding, ModuleId, ScanSummary, ScanTotals,
};
use std::time::Duration;
use time::OffsetDateTime;

#[derive(Clone)]
struct FixtureFinding;

impl ModuleFinding for FixtureFinding {
    fn sort_rank(&self) -> Option<u64> {
        Some(1)
    }
    fn to_row(&self) -> FindingRow {
        FindingRow {
            columns: vec![
                (
                    "endpoint".to_string(),
                    CellValue::Text("1.1.1.1:443".to_string()),
                ),
                ("rtt_ms".to_string(), CellValue::Number(12.125)),
                ("status".to_string(), CellValue::Text("ok".to_string())),
            ],
        }
    }
    fn is_filtered(&self) -> bool {
        false
    }
}

fn fixture() -> ScanSummary {
    ScanSummary {
        module_id: ModuleId("cdn".to_string()),
        started_at: OffsetDateTime::from_unix_timestamp(0).expect("epoch"),
        wall_time: Duration::from_millis(1500),
        totals: ScanTotals {
            probed: 3,
            alive: 2,
            filtered: 0,
            cancelled: false,
        },
        findings: vec![Box::new(FixtureFinding)],
    }
}

#[test]
fn g1_registry_exposes_both_modules() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(cftool_warp::WarpModule::new()))
        .expect("warp");
    registry
        .register(Box::new(cftool_cdn::CdnModule::new()))
        .expect("cdn");
    assert_eq!(registry.iter().count(), 2);
    assert!(registry.get(&ModuleId("warp".to_string())).is_some());
    assert!(registry.get(&ModuleId("cdn".to_string())).is_some());
    for module in registry.iter() {
        let meta = module.meta();
        assert!(!meta.name.is_empty());
        assert!(!module.columns().is_empty());
        assert!(!module.options_spec().entries.is_empty());
    }
}

#[test]
fn g8_json_export_is_byte_identical() {
    let summary = fixture();
    let mut gui = Vec::new();
    cftool_cli::export_json(&summary, &mut gui).expect("gui export");
    let mut cli = Vec::new();
    cftool_cli::export_json(&summary, &mut cli).expect("cli export");
    assert_eq!(gui, cli);
    let text = String::from_utf8(gui).expect("utf8");
    assert!(text.contains("\"wall_time\":1500"));
    assert!(text.contains("\"module\":\"cdn\""));
}

#[test]
fn g8_csv_export_uses_declared_columns_and_lf() {
    let columns = [
        ColumnSpec {
            key: "endpoint",
            header: "Endpoint",
        },
        ColumnSpec {
            key: "rtt_ms",
            header: "RTT (ms)",
        },
    ];
    let rows = [FixtureFinding.to_row()];
    let mut gui = Vec::new();
    cftool_cli::export_csv(&columns, &rows, &mut gui).expect("gui export");
    let text = String::from_utf8(gui).expect("utf8");
    assert_eq!(text.lines().count(), 2);
    assert!(text.starts_with("Endpoint,RTT (ms)\n"));
    assert!(!text.contains('\r'));
    assert!(text.contains("12.125"));
}
