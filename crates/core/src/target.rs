//! Target selection, generation recipes, and probe budgeting.

use std::net::IpAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProbeTarget {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScanTarget {
    pub addr: IpAddr,
    pub ports: Vec<u16>,
}

/// Forward-compatible on-demand address representation; every v1 plan is resolved.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GenerationRecipe {
    pub start: Option<IpAddr>,
    pub count: usize,
}

impl GenerationRecipe {
    /// A recipe whose addresses live in `TargetPlan.targets`.
    pub fn resolved() -> Self {
        Self::default()
    }

    pub fn address_count(&self) -> usize {
        self.count
    }
}

/// Derived probe timings for one plan.
///
/// `per_probe_timeout == probe_overhead + attempts_per_probe * per_attempt_timeout`.
/// `plan_endpoints` counts endpoints (addresses × ports) even for recipe-only plans.
#[derive(Clone, Debug)]
pub struct TargetPlan {
    pub recipe: GenerationRecipe,
    pub targets: Vec<ScanTarget>,
    pub plan_endpoints: usize,
    pub stop_on_first_answer: bool,
    pub attempts_per_probe: u8,
    pub per_attempt_timeout: Duration,
    pub probe_overhead: Duration,
    pub per_probe_timeout: Duration,
    pub charged_packet_count: u64,
}

#[derive(Clone, Debug)]
pub struct ProbeBudget {
    pub per_attempt_timeout: Duration,
    pub max_attempts: u8,
    pub overhead: Duration,
    pub cancel: CancellationToken,
}
