#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cftool_core::error::ScanError;
use cftool_core::events::{EventSink, ProgressSnapshot, ScanEvent};
use cftool_core::module::{ModuleMeta, RangePolicy, ScannerModule};
use cftool_core::options::{ModuleOptions, OptionsSpec, SubcommandSpec};
use cftool_core::probe::{
    AliveDetail, AliveKind, AttemptRecord, BoxFuture, DeadReason, Probe, ProbeOutcome, ProbeSource,
    ProbeVerdict,
};
use cftool_core::result::{CellValue, ColumnSpec, FindingRow, ModuleFinding, ModuleId};
use cftool_core::target::{GenerationRecipe, ProbeBudget, ProbeTarget, ScanTarget, TargetPlan};
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

pub static OPTIONS: OptionsSpec = OptionsSpec { entries: &[] };

pub static COLUMNS: &[ColumnSpec] = &[
    ColumnSpec {
        key: "endpoint",
        header: "Endpoint",
    },
    ColumnSpec {
        key: "rtt",
        header: "RTT",
    },
    ColumnSpec {
        key: "kind",
        header: "Kind",
    },
    ColumnSpec {
        key: "speed",
        header: "Speed",
    },
];

#[derive(Clone)]
pub struct TestFinding {
    pub rank: Option<u64>,
    pub row: FindingRow,
    pub filtered: bool,
}

impl ModuleFinding for TestFinding {
    fn sort_rank(&self) -> Option<u64> {
        self.rank
    }

    fn to_row(&self) -> FindingRow {
        self.row.clone()
    }

    fn is_filtered(&self) -> bool {
        self.filtered
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Reply {
    Alive { rtt_ms: u64 },
    Cookie,
    Dead,
    Panic,
    Slow { rtt_ms: u64 },
}

pub struct ScriptedSource {
    pub replies: Arc<Mutex<VecDeque<Reply>>>,
    pub probed: Arc<Mutex<Vec<ProbeTarget>>>,
}

impl ScriptedSource {
    pub fn new(replies: Vec<Reply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Arc::new(Mutex::new(replies.into())),
            probed: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

impl ProbeSource for ScriptedSource {
    fn probe(&self, _options: &ModuleOptions) -> Arc<dyn Probe> {
        Arc::new(ScriptedProbe {
            replies: Arc::clone(&self.replies),
            probed: Arc::clone(&self.probed),
        })
    }
}

struct ScriptedProbe {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    probed: Arc<Mutex<Vec<ProbeTarget>>>,
}

impl Probe for ScriptedProbe {
    fn probe<'a>(
        &'a self,
        target: ProbeTarget,
        budget: ProbeBudget,
    ) -> BoxFuture<'a, ProbeOutcome> {
        Box::pin(async move {
            let addr = target.addr;
            let port = target.port;
            self.probed
                .lock()
                .expect("probed mutex poisoned")
                .push(target);
            let reply = self
                .replies
                .lock()
                .expect("replies mutex poisoned")
                .pop_front()
                .unwrap_or(Reply::Dead);
            let started_at = OffsetDateTime::now_utc();
            let target = ProbeTarget { addr, port };

            match reply {
                Reply::Alive { rtt_ms } | Reply::Slow { rtt_ms } => {
                    let cancelled = tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(rtt_ms)) => false,
                        _ = budget.cancel.cancelled() => true,
                    };
                    if cancelled {
                        ProbeOutcome {
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
                        }
                    } else {
                        let rtt = Duration::from_millis(rtt_ms);
                        ProbeOutcome {
                            target,
                            verdict: ProbeVerdict::Alive {
                                rtt: Some(rtt),
                                detail: AliveDetail {
                                    kind: AliveKind::Type2Response,
                                    facts: BTreeMap::new(),
                                },
                            },
                            attempts: AttemptRecord {
                                tries_made: 1,
                                tries_succeeded: 1,
                                try_rtts_us: vec![(rtt_ms * 1000) as u32],
                            },
                            started_at,
                        }
                    }
                }
                Reply::Cookie => ProbeOutcome {
                    target,
                    verdict: ProbeVerdict::Alive {
                        rtt: None,
                        detail: AliveDetail {
                            kind: AliveKind::Cookie,
                            facts: BTreeMap::new(),
                        },
                    },
                    attempts: AttemptRecord {
                        tries_made: 1,
                        tries_succeeded: 1,
                        try_rtts_us: Vec::new(),
                    },
                    started_at,
                },
                Reply::Dead => ProbeOutcome {
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
                },
                Reply::Panic => panic!("scripted probe panic"),
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizeBehavior {
    Normal,
    Block,
}

pub struct TestModule {
    pub meta: ModuleMeta,
    pub behavior: FinalizeBehavior,
    pub entered: Arc<tokio::sync::Notify>,
    pub release: Arc<tokio::sync::Notify>,
}

impl TestModule {
    pub fn new(behavior: FinalizeBehavior) -> Arc<Self> {
        Arc::new(Self {
            meta: ModuleMeta {
                id: ModuleId::new("test"),
                name: "test",
                version: "0.1.0",
                description: "scripted test module",
                cli_name: None,
                range_policy: RangePolicy::WarpEndpointPools,
                actions: &[],
                dialogs: &[],
            },
            behavior,
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        })
    }
}

impl ScannerModule for TestModule {
    fn meta(&self) -> &ModuleMeta {
        &self.meta
    }

    fn subcommands(&self) -> &[SubcommandSpec] {
        &[]
    }

    fn run_command(
        &self,
        _subcommand: &'static str,
        _options: &ModuleOptions,
        _cancel: &CancellationToken,
    ) -> BoxFuture<'_, Result<(), ScanError>> {
        Box::pin(async { Ok(()) })
    }

    fn options_spec(&self) -> &OptionsSpec {
        &OPTIONS
    }

    fn columns(&self) -> &[ColumnSpec] {
        COLUMNS
    }

    fn plan(&self, _options: &ModuleOptions) -> Result<TargetPlan, ScanError> {
        Ok(make_plan(&[443], true, 1, 1))
    }

    fn probe(&self, _options: &ModuleOptions) -> Arc<dyn Probe> {
        Arc::new(DummyProbe)
    }

    fn finalize<'a>(
        &'a self,
        outcomes: &'a [ProbeOutcome],
        _options: &'a ModuleOptions,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>> {
        Box::pin(async move {
            if matches!(self.behavior, FinalizeBehavior::Block) {
                self.entered.notify_one();
                self.release.notified().await;
            }

            let findings: Vec<Box<dyn ModuleFinding>> = outcomes
                .iter()
                .filter_map(|outcome| {
                    let ProbeVerdict::Alive { rtt, detail: _ } = &outcome.verdict else {
                        return None;
                    };
                    let port = outcome.target.port;
                    let rtt_cell = match rtt {
                        Some(duration) => CellValue::Number(duration.as_secs_f64() * 1000.0),
                        None => CellValue::Null,
                    };
                    let speed_cell = if cancel.is_cancelled() {
                        CellValue::Null
                    } else {
                        CellValue::Text("ok".to_string())
                    };
                    Some(Box::new(TestFinding {
                        rank: Some(port as u64),
                        row: FindingRow {
                            columns: vec![
                                (
                                    "endpoint".to_string(),
                                    CellValue::Text(format!("{}:{}", outcome.target.addr, port)),
                                ),
                                ("rtt".to_string(), rtt_cell),
                                ("kind".to_string(), CellValue::Text("alive".to_string())),
                                ("speed".to_string(), speed_cell),
                            ],
                        },
                        filtered: false,
                    }) as Box<dyn ModuleFinding>)
                })
                .collect();

            Ok(findings)
        })
    }
}

struct DummyProbe;

impl Probe for DummyProbe {
    fn probe<'a>(
        &'a self,
        target: ProbeTarget,
        _budget: ProbeBudget,
    ) -> BoxFuture<'a, ProbeOutcome> {
        Box::pin(async move {
            ProbeOutcome {
                target,
                verdict: ProbeVerdict::Alive {
                    rtt: Some(Duration::from_millis(1)),
                    detail: AliveDetail {
                        kind: AliveKind::Connected,
                        facts: BTreeMap::new(),
                    },
                },
                attempts: AttemptRecord {
                    tries_made: 1,
                    tries_succeeded: 1,
                    try_rtts_us: vec![1000],
                },
                started_at: OffsetDateTime::now_utc(),
            }
        })
    }
}

pub fn make_plan(ports: &[u16], stop: bool, endpoints: usize, packets: u64) -> TargetPlan {
    TargetPlan {
        recipe: GenerationRecipe::resolved(),
        targets: vec![ScanTarget {
            addr: "198.51.100.1".parse().expect("valid IPv4 address"),
            ports: ports.to_vec(),
        }],
        plan_endpoints: endpoints,
        stop_on_first_answer: stop,
        attempts_per_probe: 1,
        per_attempt_timeout: Duration::from_millis(1000),
        probe_overhead: Duration::ZERO,
        per_probe_timeout: Duration::from_millis(1000),
        charged_packet_count: packets,
    }
}

pub fn channels(
    cap: usize,
) -> (
    EventSink,
    mpsc::Receiver<ScanEvent>,
    watch::Receiver<ProgressSnapshot>,
) {
    let (progress, progress_rx) = watch::channel(ProgressSnapshot::default());
    let (results, results_rx) = mpsc::channel(cap);
    (EventSink { progress, results }, results_rx, progress_rx)
}
