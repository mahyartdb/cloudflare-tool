//! CDN edge-IP scanner module for cftool.

mod finding;
mod options;
mod plan;
mod probe;

use std::sync::Arc;

use cftool_core::error::ScanError;
use cftool_core::module::{ModuleMeta, RangePolicy, ScannerModule};
use cftool_core::options::{ModuleOptions, OptionsSpec, SubcommandSpec};
use cftool_core::probe::{BoxFuture, Probe};
use cftool_core::result::{ColumnSpec, ModuleFinding, ModuleId};
use cftool_core::target::TargetPlan;
use tokio_util::sync::CancellationToken;

pub use finding::{CdnFinding, apply_speed, ewma, loss_pct, mean_rtt_us};
pub use options::{COLUMNS, CdnMode, CdnOptions, OPTIONS_SPEC, mode_name, per_probe_timeout};
pub use plan::{
    address_count, build_plan, default_plan_for_test, published_v4_nets, sample_addresses,
    subnets24,
};
pub use probe::{CdnProbe, extract_colo};

#[derive(Debug, Default)]
pub struct CdnModule;

impl CdnModule {
    pub fn new() -> Self {
        Self
    }
}

impl ScannerModule for CdnModule {
    fn meta(&self) -> &ModuleMeta {
        static META: std::sync::OnceLock<ModuleMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ModuleMeta {
            id: ModuleId("cdn".to_string()),
            name: "CDN edge IP scanner",
            version: "0.1.0",
            description: "Measures Cloudflare published edge ranges (CFST methodology)",
            cli_name: None,
            range_policy: RangePolicy::PublishedCdn,
            actions: &[],
            dialogs: &[],
        })
    }

    fn subcommands(&self) -> &[SubcommandSpec] {
        &[]
    }

    fn run_command(
        &self,
        _id: &'static str,
        _args: &ModuleOptions,
        _cancel: &CancellationToken,
    ) -> BoxFuture<'_, Result<(), ScanError>> {
        Box::pin(async {
            Err(ScanError::OptionsInvalid {
                key: "command".into(),
                reason: "cdn-scan declares no commands".into(),
            })
        })
    }

    fn options_spec(&self) -> &OptionsSpec {
        &OPTIONS_SPEC
    }

    fn columns(&self) -> &[ColumnSpec] {
        COLUMNS
    }

    fn plan(&self, opts: &ModuleOptions) -> Result<TargetPlan, ScanError> {
        build_plan(opts)
    }

    fn probe(&self, opts: &ModuleOptions) -> Arc<dyn Probe> {
        let options = CdnOptions::try_from_options(opts).unwrap_or_default();
        Arc::new(CdnProbe::new(options.mode))
    }

    fn finalize<'a>(
        &'a self,
        outcomes: &'a [cftool_core::probe::ProbeOutcome],
        opts: &'a ModuleOptions,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>> {
        finding::finalize(outcomes, opts, cancel)
    }
}
