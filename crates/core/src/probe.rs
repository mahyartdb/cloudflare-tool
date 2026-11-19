//! Probe seam: the runner sees modules only through [`Probe`], and
//! [`ProbeSource`] is the one place tests swap implementations.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::options::ModuleOptions;
use crate::result::CellValue;
use crate::target::{ProbeBudget, ProbeTarget};

/// A boxed, `Send` future returned by [`Probe::probe`].
///
/// `Send` is load-bearing: the runner spawns probe futures on the Tokio
/// runtime behind an `Arc<dyn Probe>`, so every future must cross threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One module's probe, erased behind `Arc<dyn Probe>` so the runner never
/// names a concrete module.
pub trait Probe: Send + Sync + 'static {
    /// Probe `target` within `budget`.
    ///
    /// The returned boxed future is `Send` so the runner can spawn it from
    /// behind an `Arc<dyn Probe>` on any Tokio worker.
    fn probe<'a>(&'a self, target: ProbeTarget, budget: ProbeBudget)
    -> BoxFuture<'a, ProbeOutcome>;
}

/// Counters a module accumulated across the tries of one probe.
#[derive(Clone, Debug, Default)]
pub struct AttemptRecord {
    pub tries_made: u8,
    pub tries_succeeded: u8,
    pub try_rtts_us: Vec<u32>,
}

/// The verdict for one target once its tries are over.
#[derive(Clone, Debug)]
pub enum ProbeVerdict {
    Alive {
        rtt: Option<Duration>,
        detail: AliveDetail,
    },
    Dead {
        reason: DeadReason,
    },
}

/// Why a target was declared dead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadReason {
    Timeout,
    Unreachable,
    ParseFailure,
    Cancelled,
    Internal,
}

/// Which kind of evidence made a target alive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliveKind {
    /// Warp completed a full handshake.
    Type2Response,
    /// Cloudflare rate-limiting reply: alive, but no RTT is knowable.
    Cookie,
    /// Transport-level success only (cdn); no protocol evidence.
    Connected,
}

/// Detail a module attaches to an alive verdict at probe time.
///
/// `facts` carries module-observed probe-time facts (cdn status/colo) into
/// finalize. Post-phase findings are result columns and never live here.
#[derive(Clone, Debug)]
pub struct AliveDetail {
    pub kind: AliveKind,
    pub facts: BTreeMap<String, CellValue>,
}

impl Default for AliveDetail {
    /// `Connected` claims the least, so it is the neutral default.
    fn default() -> Self {
        Self {
            kind: AliveKind::Connected,
            facts: BTreeMap::new(),
        }
    }
}

/// What one probe produced for one target.
///
/// Liveness comes from `verdict` alone, never from `attempts`: a dead verdict
/// wins even when tries succeeded, and a `Cancelled` dead verdict overrides
/// earlier successes.
#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub target: ProbeTarget,
    pub verdict: ProbeVerdict,
    pub attempts: AttemptRecord,
    pub started_at: OffsetDateTime,
}

impl ProbeOutcome {
    /// Liveness comes from the verdict alone; a `Cancelled` dead verdict
    /// overrides earlier successes.
    pub fn is_alive(&self) -> bool {
        matches!(self.verdict, ProbeVerdict::Alive { .. })
    }

    /// Share of tries that failed, in `0.0..=1.0`; zero tries means zero loss.
    pub fn loss(&self) -> f64 {
        if self.attempts.tries_made == 0 {
            0.0
        } else {
            f64::from(self.attempts.tries_made - self.attempts.tries_succeeded)
                / f64::from(self.attempts.tries_made)
        }
    }

    /// Mean per-try RTT in microseconds, or `None` when no try reported one.
    pub fn mean_rtt_us(&self) -> Option<f64> {
        if self.attempts.try_rtts_us.is_empty() {
            return None;
        }
        let total: u64 = self
            .attempts
            .try_rtts_us
            .iter()
            .map(|&us| u64::from(us))
            .sum();
        Some(total as f64 / self.attempts.try_rtts_us.len() as f64)
    }
}

/// The single injection seam for probes.
///
/// The production implementation wraps the module and hands back its
/// `Probe`; tests substitute `ScriptedProbeSource`, and nothing else in the
/// runner changes.
pub trait ProbeSource: Send + Sync + 'static {
    fn probe(&self, opts: &ModuleOptions) -> Arc<dyn Probe>;
}
