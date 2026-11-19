//! Module contract and registry.
//!
//! Every scan module owns one scanner end to end: its metadata, CLI wiring,
//! options, probe plan, and the step that turns probe outcomes into findings.
//! [`ModuleRegistry`] holds the instantiated modules in registration order and
//! indexes them by [`ModuleId`].

use std::fmt;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::error::ScanError;
use crate::options::{ActionSpec, DialogSpec, ModuleOptions, OptionsSpec, SubcommandSpec};
use crate::probe::{BoxFuture, Probe, ProbeOutcome};
use crate::result::{ColumnSpec, ModuleFinding, ModuleId};
use crate::target::TargetPlan;

/// Address-range set a module scans against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangePolicy {
    /// Cloudflare's published edge ranges: 15 IPv4 and 7 IPv6 CIDRs.
    PublishedCdn,
    /// The compiled-in WARP superset: 14 IPv4 /24s and 2 IPv6 /48s.
    WarpEndpointPools,
}

/// Static description of a scan module.
///
/// All of it is fixed at link time, so both frontends can build their CLI and
/// GUI surfaces from a module's metadata without running it.
#[derive(Clone, Debug)]
pub struct ModuleMeta {
    /// Stable module identifier; the key the registry indexes on.
    pub id: ModuleId,
    /// Human-readable name.
    pub name: &'static str,
    /// Module version, independent of the crate version.
    pub version: &'static str,
    /// One-line description for help output and the GUI.
    pub description: &'static str,
    /// CLI subcommand name; `None` means the CLI derives `<id>-scan`.
    pub cli_name: Option<&'static str>,
    /// Range set the module's plan targets.
    pub range_policy: RangePolicy,
    /// Actions the module exposes.
    pub actions: &'static [ActionSpec],
    /// Dialogs the module exposes.
    pub dialogs: &'static [DialogSpec],
}

/// A scan module: one scanner behind a single, frontend-agnostic interface.
pub trait ScannerModule: Send + Sync + 'static {
    /// Static metadata for registration and presentation.
    fn meta(&self) -> &ModuleMeta;

    /// CLI subcommands this module registers.
    fn subcommands(&self) -> &[SubcommandSpec];

    /// Run the named subcommand with parsed options, honouring `cancel`.
    fn run_command(
        &self,
        id: &'static str,
        args: &ModuleOptions,
        cancel: &CancellationToken,
    ) -> BoxFuture<'_, Result<(), ScanError>>;

    /// Declarative description of the module's options.
    fn options_spec(&self) -> &OptionsSpec;

    /// Result table columns, in output order.
    fn columns(&self) -> &[ColumnSpec];

    /// Resolve options into the concrete probe plan to execute.
    fn plan(&self, opts: &ModuleOptions) -> Result<TargetPlan, ScanError>;

    /// Build the probe that executes a planned scan.
    fn probe(&self, opts: &ModuleOptions) -> Arc<dyn Probe>;

    /// Turn raw probe outcomes into findings, honouring `cancel`.
    fn finalize<'a>(
        &'a self,
        outcomes: &'a [ProbeOutcome],
        opts: &'a ModuleOptions,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>>;
}

/// Ordered collection of scan modules, indexed by id.
///
/// Registration order is preserved and drives CLI subcommand ordering.
pub struct ModuleRegistry {
    modules: Vec<Box<dyn ScannerModule>>,
}

impl ModuleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Add a module, rejecting an id that is already registered.
    pub fn register(&mut self, module: Box<dyn ScannerModule>) -> Result<(), ScanError> {
        let meta = module.meta();
        if self.modules.iter().any(|m| m.meta().id == meta.id) {
            let id = &meta.id;
            return Err(ScanError::InvalidPlan(format!(
                "duplicate module id `{id}`"
            )));
        }
        self.modules.push(module);
        Ok(())
    }

    /// Look up a registered module by id.
    pub fn get(&self, id: &ModuleId) -> Option<&dyn ScannerModule> {
        self.modules
            .iter()
            .find(|m| &m.meta().id == id)
            .map(|m| &**m)
    }

    /// Iterate over the registered modules in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn ScannerModule> {
        self.modules.iter().map(|m| &**m)
    }

    /// Iterate over the registered module ids in registration order.
    pub fn ids(&self) -> impl Iterator<Item = &ModuleId> {
        self.modules.iter().map(|m| &m.meta().id)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ModuleRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ids = f.debug_list();
        for module in &self.modules {
            ids.entry(&module.meta().id);
        }
        ids.finish()
    }
}
