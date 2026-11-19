//! WARP endpoint scanner module for cftool.

mod finding;
mod identity;
mod options;
mod plan;
mod probe;
mod registration;

use std::sync::Arc;

use cftool_core::error::ScanError;
use cftool_core::module::{ModuleMeta, ScannerModule};
use cftool_core::options::{ActionKind, ActionSpec, ModuleOptions, OptionsSpec, SubcommandSpec};
use cftool_core::probe::{BoxFuture, Probe};
use cftool_core::result::{ColumnSpec, ModuleFinding};
use cftool_core::target::TargetPlan;
use tokio_util::sync::CancellationToken;

pub use finding::WarpFinding;
pub use identity::{Identity, WarpError, delete_identity, parse_wgcf};
pub use options::{
    COLUMNS, IDENTITY_DIALOG, IDENTITY_SUBCOMMANDS, NoisePreset, OPTIONS_SPEC, PORTS_FULL,
    PORTS_STANDARD, PoolMode, PortMode, WarpOptions,
};
pub use plan::{Lcg, build_plan, default_plan_for_test, lcg_walk24, ports_for};
pub use probe::{WarpProbe, classify_response, decode_key, derive_wire_index};
pub use registration::{
    API_VERSION, BUILD_NUMBER, CLIENT_VERSION, USER_AGENT, make_client, register,
    registration_hint, registration_rejected,
};

static DIALOGS: &[cftool_core::options::DialogSpec] = &[IDENTITY_DIALOG];

static ACTIONS: &[ActionSpec] = &[ActionSpec {
    id: "identity",
    label: "Identity…",
    kind: ActionKind::OpenDialog { dialog: "identity" },
}];

#[derive(Debug, Default)]
pub struct WarpModule;

impl WarpModule {
    pub fn new() -> Self {
        Self
    }
}

impl ScannerModule for WarpModule {
    fn meta(&self) -> &ModuleMeta {
        static META: std::sync::OnceLock<ModuleMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ModuleMeta {
            id: cftool_core::result::ModuleId("warp".to_string()),
            name: "WARP endpoint scanner",
            version: "0.1.0",
            description: "Probes Cloudflare WARP endpoint pools with WireGuard handshakes",
            cli_name: None,
            range_policy: cftool_core::module::RangePolicy::WarpEndpointPools,
            actions: ACTIONS,
            dialogs: DIALOGS,
        })
    }

    fn subcommands(&self) -> &[SubcommandSpec] {
        IDENTITY_SUBCOMMANDS
    }

    fn run_command(
        &self,
        id: &'static str,
        args: &ModuleOptions,
        cancel: &CancellationToken,
    ) -> BoxFuture<'_, Result<(), ScanError>> {
        let owned_args = args.clone();
        let owned_cancel = cancel.clone();
        Box::pin(async move {
            let args = &owned_args;
            let cancel = &owned_cancel;
            match id {
                "identity register" => {
                    let force = matches!(
                        args.get("force"),
                        Some(cftool_core::options::OptionValue::Bool(true))
                    );
                    let _ = (force, cancel);
                    #[cfg(feature = "mock")]
                    {
                        let _ = registration::register_mock().await?;
                    }
                    #[cfg(not(feature = "mock"))]
                    {
                        let _ = registration::register(force, cancel).await?;
                    }
                    Ok(())
                }
                "identity import" => {
                    let path = match args.get("file") {
                        Some(cftool_core::options::OptionValue::Text(path)) => path.clone(),
                        _ => {
                            return Err(ScanError::OptionsInvalid {
                                key: "file".into(),
                                reason: "an identity import needs a file path".into(),
                            });
                        }
                    };
                    identity::import_wgcf_file(path)
                        .map_err(|e| ScanError::InvalidPlan(e.to_string()))?;
                    Ok(())
                }
                "identity show" => {
                    identity::load_identity()?;
                    Ok(())
                }
                other => Err(ScanError::OptionsInvalid {
                    key: "command".into(),
                    reason: format!("unknown command `{other}`"),
                }),
            }
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
        let identity = {
            #[cfg(feature = "mock")]
            {
                identity::scripted_identity()
            }
            #[cfg(not(feature = "mock"))]
            {
                identity::load_identity().expect("plan() validates the identity before probe()")
            }
        };
        let options = WarpOptions::try_from_options(opts).unwrap_or_default();
        Arc::new(WarpProbe::new(
            identity,
            options.noise,
            std::time::Duration::from_millis(options.timeout_per_probe_ms),
        ))
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
