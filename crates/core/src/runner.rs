use std::any::Any;
use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::ScanError;
use crate::events::{
    EventSink, LogLevel, ProgressSnapshot, RESULT_LANE_CAPACITY, ScanEvent, ScanPhase,
};
use crate::module::ScannerModule;
use crate::options::ModuleOptions;
use crate::probe::{AttemptRecord, DeadReason, ProbeOutcome, ProbeSource, ProbeVerdict};
use crate::result::{FindingRow, ModuleFinding, ScanSummary, ScanTotals};
use crate::target::{ProbeBudget, ProbeTarget, TargetPlan};

/// Upper bound on configured probe concurrency, checked before any socket work.
pub const HARD_CONCURRENCY_CEILING: usize = 4096;

/// Minimum interval between progress snapshots published to the watch channel.
pub const PROGRESS_COALESCE: Duration = Duration::from_millis(50);

static SCAN_PERMIT: OnceLock<Semaphore> = OnceLock::new();

fn permit() -> &'static Semaphore {
    SCAN_PERMIT.get_or_init(|| Semaphore::new(1))
}

type PanicPayload = Box<dyn Any + Send + 'static>;
type ProbeTaskResult = Result<ProbeOutcome, PanicPayload>;

#[derive(Clone, Debug)]
pub struct ProbeRunnerConfig {
    pub concurrency: usize,
    pub total_budget: Duration,
}

/// Executes a probe plan and finalizes the collected outcomes through a module.
///
/// The architecture fixes `run(plan, source, events, cancel)`, but core must call
/// the module's async `finalize` after probing. The module is therefore injected
/// through the constructor instead of being passed to `run`.
pub struct ProbeRunner {
    config: ProbeRunnerConfig,
    opts: ModuleOptions,
    module: Arc<dyn ScannerModule>,
}

impl ProbeRunner {
    pub fn new(
        config: ProbeRunnerConfig,
        opts: ModuleOptions,
        module: Arc<dyn ScannerModule>,
    ) -> Result<Self, ScanError> {
        if config.concurrency > HARD_CONCURRENCY_CEILING {
            return Err(ScanError::InvalidPlan(format!(
                "concurrency {} exceeds hard ceiling {}",
                config.concurrency, HARD_CONCURRENCY_CEILING
            )));
        }
        if config.concurrency == 0 {
            return Err(ScanError::InvalidPlan(
                "concurrency must be at least 1".to_string(),
            ));
        }
        Ok(Self {
            config,
            opts,
            module,
        })
    }

    /// Runs the scan.
    ///
    /// Cancellation by the caller and exhaustion of the total budget are terminal
    /// successes: dispatch stops, in-flight probes are drained for at most 500 ms,
    /// every outcome collected so far is finalized, and `Done` is emitted with
    /// `cancelled: true`. `Failed` is reserved for lane overflow, a closed receiver,
    /// finalization failure, and a zero budget that expires before `Started` is sent.
    pub async fn run(
        &self,
        plan: TargetPlan,
        source: Arc<dyn ProbeSource>,
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        let _permit = permit().try_acquire().map_err(|_| ScanError::Busy)?;

        let started_at = OffsetDateTime::now_utc();
        let started = Instant::now();
        let deadline = started + self.config.total_budget;

        if self.config.total_budget.is_zero() {
            send(
                &events,
                ScanEvent::Failed(ScanError::BudgetExhausted),
                &cancel,
            )?;
            return Err(ScanError::BudgetExhausted);
        }

        send(&events, ScanEvent::Phase(ScanPhase::Plan), &cancel)?;
        send(
            &events,
            ScanEvent::Started {
                plan_endpoints: plan.plan_endpoints,
                concurrency: self.config.concurrency,
            },
            &cancel,
        )?;
        send(&events, ScanEvent::Phase(ScanPhase::Run), &cancel)?;

        let probe = source.probe(&self.opts);

        let mut expanded = Vec::new();
        for target in &plan.targets {
            for &port in &target.ports {
                expanded.push(ProbeTarget {
                    addr: target.addr,
                    port,
                });
            }
        }

        let slots = Arc::new(Semaphore::new(self.config.concurrency));
        let mut tasks: JoinSet<(ProbeTarget, ProbeTaskResult)> = JoinSet::new();
        let mut pending = expanded.into_iter();
        let mut next_target = pending.next();
        let mut state = RunState::new();
        let mut stop_requested = false;
        let mut budget_expired = false;

        'run: loop {
            if !stop_requested && cancel.is_cancelled() {
                stop_requested = true;
            }
            if stop_requested {
                break 'run;
            }

            while let Some(target) = next_target.take() {
                if cancel.is_cancelled() {
                    stop_requested = true;
                    break;
                }
                if Instant::now() >= deadline {
                    budget_expired = true;
                    cancel.cancel();
                    stop_requested = true;
                    break;
                }
                if plan.stop_on_first_answer && state.answered.contains(&target.addr) {
                    next_target = pending.next();
                    continue;
                }

                let slot = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        next_target = Some(target);
                        break;
                    }
                };

                let probe = Arc::clone(&probe);
                let budget = ProbeBudget {
                    per_attempt_timeout: plan.per_attempt_timeout,
                    max_attempts: plan.attempts_per_probe,
                    overhead: plan.probe_overhead,
                    cancel: cancel.clone(),
                };
                let tracked = target;

                tasks.spawn(async move {
                    let _slot = slot;
                    let result = CatchUnwind::new(probe.probe(target, budget)).await;
                    (tracked, result)
                });

                next_target = pending.next();
            }

            if stop_requested {
                break 'run;
            }

            if tasks.is_empty() {
                if next_target.is_none() {
                    break 'run;
                }
                continue;
            }

            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    stop_requested = true;
                    break 'run;
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    budget_expired = true;
                    cancel.cancel();
                    stop_requested = true;
                    break 'run;
                }
                joined = tasks.join_next() => {
                    match joined {
                        Some(Ok((target, task_result))) => {
                            match task_result {
                                Ok(outcome) => self.admit_outcome(
                                    outcome,
                                    plan.stop_on_first_answer,
                                    &mut state,
                                    &events,
                                    &cancel,
                                )?,
                                Err(_) => self.admit_panic(
                                    target,
                                    started_at,
                                    &mut state,
                                    &events,
                                    &cancel,
                                )?,
                            }
                        }
                        Some(Err(_)) => {
                            send(
                                &events,
                                ScanEvent::Log {
                                    level: LogLevel::Warn,
                                    message: "probe task failed outside the probe future".to_string(),
                                },
                                &cancel,
                            )?;
                        }
                        None => {}
                    }
                }
            }
        }

        if stop_requested {
            cancel.cancel();
        }

        let drain_started = Instant::now();
        while !tasks.is_empty() {
            let elapsed = drain_started.elapsed();
            if elapsed >= Duration::from_millis(500) {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }

            let remaining = Duration::from_millis(500) - elapsed;
            match tokio::time::timeout(remaining, tasks.join_next()).await {
                Ok(Some(Ok((target, task_result)))) => match task_result {
                    Ok(outcome) => self.admit_outcome(
                        outcome,
                        plan.stop_on_first_answer,
                        &mut state,
                        &events,
                        &cancel,
                    )?,
                    Err(_) => self.admit_panic(target, started_at, &mut state, &events, &cancel)?,
                },
                Ok(Some(Err(_))) => {
                    send(
                        &events,
                        ScanEvent::Log {
                            level: LogLevel::Warn,
                            message: "probe task failed outside the probe future".to_string(),
                        },
                        &cancel,
                    )?;
                }
                Ok(None) => break,
                Err(_) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    break;
                }
            }
        }

        events.progress.send_replace(ProgressSnapshot {
            completed: state.probed,
            alive: state.alive,
        });

        if budget_expired {
            send(
                &events,
                ScanEvent::Log {
                    level: LogLevel::Warn,
                    message: format!(
                        "scan budget ceiling {:?} exhausted; finalizing partial results",
                        self.config.total_budget
                    ),
                },
                &cancel,
            )?;
        }

        send(&events, ScanEvent::Phase(ScanPhase::Finalize), &cancel)?;

        let finalized = match self
            .module
            .finalize(&state.outcomes, &self.opts, &cancel)
            .await
        {
            Ok(findings) => findings,
            Err(err) => {
                send(&events, ScanEvent::Failed(err.clone()), &cancel)?;
                return Err(err);
            }
        };

        let module_id = self.module.meta().id.clone();

        let mut rows: Vec<RowFinding> = finalized
            .into_iter()
            .map(|finding| RowFinding {
                rank: finding.sort_rank(),
                row: finding.to_row(),
                filtered: finding.is_filtered(),
            })
            .collect();

        rows.sort_by_key(|finding| (finding.rank.is_none(), finding.rank.unwrap_or(0)));

        let filtered = rows.iter().filter(|finding| finding.filtered).count();
        let cancelled = cancel.is_cancelled() || budget_expired;
        let wall_time = started.elapsed();

        let event_findings: Vec<Box<dyn ModuleFinding>> = rows
            .iter()
            .cloned()
            .map(|finding| Box::new(finding) as Box<dyn ModuleFinding>)
            .collect();

        let event_summary = ScanSummary {
            module_id: module_id.clone(),
            started_at,
            wall_time,
            totals: ScanTotals {
                probed: state.probed,
                alive: state.alive,
                filtered,
                cancelled,
            },
            findings: event_findings,
        };

        send(&events, ScanEvent::Done(event_summary), &cancel)?;

        Ok(ScanSummary {
            module_id,
            started_at,
            wall_time,
            totals: ScanTotals {
                probed: state.probed,
                alive: state.alive,
                filtered,
                cancelled,
            },
            findings: rows
                .into_iter()
                .map(|finding| Box::new(finding) as Box<dyn ModuleFinding>)
                .collect(),
        })
    }

    fn admit_outcome(
        &self,
        outcome: ProbeOutcome,
        stop_on_first_answer: bool,
        state: &mut RunState,
        events: &EventSink,
        cancel: &CancellationToken,
    ) -> Result<(), ScanError> {
        state.probed += 1;
        if outcome.is_alive() {
            state.alive += 1;
            if stop_on_first_answer {
                state.answered.insert(outcome.target.addr);
            }
        }

        state.outcomes.push(outcome.clone());
        send(events, ScanEvent::Result(outcome), cancel)?;

        if state.last_publish.elapsed() >= PROGRESS_COALESCE {
            events.progress.send_replace(ProgressSnapshot {
                completed: state.probed,
                alive: state.alive,
            });
            state.last_publish = Instant::now();
        }

        Ok(())
    }

    fn admit_panic(
        &self,
        target: ProbeTarget,
        started_at: OffsetDateTime,
        state: &mut RunState,
        events: &EventSink,
        cancel: &CancellationToken,
    ) -> Result<(), ScanError> {
        state.probed += 1;
        let outcome = ProbeOutcome {
            target,
            verdict: ProbeVerdict::Dead {
                reason: DeadReason::Internal,
            },
            attempts: AttemptRecord {
                tries_made: 1,
                tries_succeeded: 0,
                try_rtts_us: Vec::new(),
            },
            started_at,
        };

        state.outcomes.push(outcome.clone());
        send(events, ScanEvent::Result(outcome), cancel)
    }
}

struct RunState {
    probed: usize,
    alive: usize,
    answered: HashSet<IpAddr>,
    outcomes: Vec<ProbeOutcome>,
    last_publish: Instant,
}

impl RunState {
    fn new() -> Self {
        Self {
            probed: 0,
            alive: 0,
            answered: HashSet::new(),
            outcomes: Vec::new(),
            last_publish: Instant::now(),
        }
    }
}

#[derive(Clone)]
struct RowFinding {
    rank: Option<u64>,
    row: FindingRow,
    filtered: bool,
}

impl ModuleFinding for RowFinding {
    fn sort_rank(&self) -> Option<u64> {
        self.rank
    }

    fn is_filtered(&self) -> bool {
        self.filtered
    }

    fn to_row(&self) -> FindingRow {
        self.row.clone()
    }
}

fn send(events: &EventSink, event: ScanEvent, cancel: &CancellationToken) -> Result<(), ScanError> {
    match events.results.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            cancel.cancel();
            let error = ScanError::ResultLaneOverflow {
                capacity: RESULT_LANE_CAPACITY,
            };
            let _ = events.results.try_send(ScanEvent::Failed(error.clone()));
            Err(error)
        }
        Err(TrySendError::Closed(_)) => Err(ScanError::Cancelled),
    }
}

struct CatchUnwind<F> {
    inner: Pin<Box<F>>,
}

impl<F> CatchUnwind<F> {
    fn new(inner: F) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<F> Unpin for CatchUnwind<F> {}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, PanicPayload>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        })) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}
