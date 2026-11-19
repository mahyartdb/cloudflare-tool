//! Deterministic probe scripting for tests, the CLI `--mock` mode, and GUI
//! test wiring.
//!
//! Script types are always compiled so every consumer shares one wire format;
//! only `load_script` and `apply_script` sit behind the `mock` feature.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::options::ModuleOptions;
use crate::probe::{
    AliveDetail, AliveKind, AttemptRecord, BoxFuture, DeadReason, Probe, ProbeOutcome, ProbeSource,
    ProbeVerdict,
};
use crate::target::{ProbeBudget, ProbeTarget};
#[cfg(feature = "mock")]
use crate::target::{ScanTarget, TargetPlan};

/// Verdict a scripted target reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptVerdict {
    Alive,
    Cookie,
    Dead,
}

/// One target in a mock script.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScriptTarget {
    pub ip: IpAddr,
    pub port: u16,
    pub verdict: ScriptVerdict,
    /// RTT in milliseconds. Required for `alive`, omitted for `cookie`, and
    /// optional for `dead`.
    pub rtt_ms: Option<u64>,
}

/// A parsed mock script.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ScriptPlan {
    pub targets: Vec<ScriptTarget>,
}

impl ScriptPlan {
    /// Rejects scripts that can never produce their declared verdict.
    ///
    /// Only `alive` requires an RTT. Cookie and dead targets may carry one,
    /// which is accepted leniently.
    pub fn validate(&self) -> Result<(), ScriptLoadError> {
        for target in &self.targets {
            if target.verdict == ScriptVerdict::Alive && target.rtt_ms.is_none() {
                return Err(ScriptLoadError::Invalid(format!(
                    "target {}:{} has verdict alive but no rtt_ms",
                    target.ip, target.port
                )));
            }
        }
        Ok(())
    }
}

/// Failure to read or parse a mock script.
#[derive(Debug, thiserror::Error)]
pub enum ScriptLoadError {
    #[error("cannot read script `{path}`: {cause}")]
    Io {
        path: std::path::PathBuf,
        cause: std::io::Error,
    },
    #[error("invalid script JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid script: {0}")]
    Invalid(String),
}

/// Probe source that replays a fixed script, ignoring runtime options.
#[derive(Clone, Debug)]
pub struct ScriptedProbeSource {
    targets: Arc<Vec<ScriptTarget>>,
}

impl ScriptedProbeSource {
    pub fn new(targets: Vec<ScriptTarget>) -> Self {
        Self {
            targets: Arc::new(targets),
        }
    }
}

impl ProbeSource for ScriptedProbeSource {
    fn probe(&self, _opts: &ModuleOptions) -> Arc<dyn Probe> {
        Arc::new(ScriptedProbe {
            targets: Arc::clone(&self.targets),
        })
    }
}

struct ScriptedProbe {
    targets: Arc<Vec<ScriptTarget>>,
}

impl Probe for ScriptedProbe {
    /// Replays the scripted verdict for `target` after its RTT delay.
    ///
    /// The sleep is cancellation-aware and bounded by the probe budget, so a
    /// cancelled probe never outlives the real probe path's deadline.
    fn probe<'a>(
        &'a self,
        target: ProbeTarget,
        budget: ProbeBudget,
    ) -> BoxFuture<'a, ProbeOutcome> {
        Box::pin(async move {
            let started_at = time::OffsetDateTime::now_utc();
            let scripted = self
                .targets
                .iter()
                .find(|candidate| candidate.ip == target.addr && candidate.port == target.port);

            let Some(scripted) = scripted else {
                return ProbeOutcome {
                    target,
                    verdict: ProbeVerdict::Dead {
                        reason: DeadReason::Timeout,
                    },
                    attempts: AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 0,
                        try_rtts_us: Vec::new(),
                    },
                    started_at,
                };
            };

            let verdict = scripted.verdict;
            let rtt_ms = scripted.rtt_ms;
            let budget_cap = budget.overhead
                + budget
                    .per_attempt_timeout
                    .saturating_mul(budget.max_attempts as u32);
            let delay = Duration::from_millis(rtt_ms.unwrap_or(0)).min(budget_cap);

            // Cancellation-aware; the delay above is already capped by the budget.
            let cancelled = tokio::select! {
                _ = tokio::time::sleep(delay) => false,
                _ = budget.cancel.cancelled() => true,
            };

            if cancelled {
                return ProbeOutcome {
                    target,
                    verdict: ProbeVerdict::Dead {
                        reason: DeadReason::Cancelled,
                    },
                    attempts: AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 0,
                        try_rtts_us: Vec::new(),
                    },
                    started_at,
                };
            }

            let (verdict, attempts) = match verdict {
                ScriptVerdict::Alive => (
                    ProbeVerdict::Alive {
                        rtt: Some(delay),
                        detail: AliveDetail {
                            kind: AliveKind::Type2Response,
                            facts: BTreeMap::new(),
                        },
                    },
                    AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 1,
                        try_rtts_us: vec![(rtt_ms.unwrap_or(0) * 1000) as u32],
                    },
                ),
                ScriptVerdict::Cookie => (
                    ProbeVerdict::Alive {
                        rtt: None,
                        detail: AliveDetail {
                            kind: AliveKind::Cookie,
                            facts: BTreeMap::new(),
                        },
                    },
                    AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 1,
                        try_rtts_us: Vec::new(),
                    },
                ),
                ScriptVerdict::Dead => (
                    ProbeVerdict::Dead {
                        reason: DeadReason::Timeout,
                    },
                    AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 0,
                        try_rtts_us: Vec::new(),
                    },
                ),
            };

            ProbeOutcome {
                target,
                verdict,
                attempts,
                started_at,
            }
        })
    }
}

/// Reads and validates a mock script from `path`.
#[cfg(feature = "mock")]
pub fn load_script(path: impl AsRef<std::path::Path>) -> Result<ScriptPlan, ScriptLoadError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|cause| ScriptLoadError::Io {
        path: path.to_path_buf(),
        cause,
    })?;
    let plan: ScriptPlan = serde_json::from_str(&raw)?;
    plan.validate()?;
    Ok(plan)
}

/// Replaces a scan plan's targets with the scripted ones.
///
/// Called by the CLI `--mock` path and GUI test wiring. Replacement happens
/// after plan validation; ports are sorted and deduplicated per IP so the
/// resulting plan is deterministic.
#[cfg(feature = "mock")]
pub fn apply_script(plan: &mut TargetPlan, script: &ScriptPlan) {
    let mut by_ip: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for target in &script.targets {
        by_ip.entry(target.ip).or_default().push(target.port);
    }

    plan.targets = by_ip
        .into_iter()
        .map(|(addr, mut ports)| {
            ports.sort_unstable();
            ports.dedup();
            ScanTarget { addr, ports }
        })
        .collect();
    plan.plan_endpoints = script.targets.len();
}
