//! Lanes between the scan core and its consumer: a latest-value progress
//! watch and an ordered result channel.

use tokio::sync::{mpsc, watch};

use crate::error::ScanError;
use crate::probe::ProbeOutcome;
use crate::result::ScanSummary;

/// Capacity of the ordered result lane.
pub const RESULT_LANE_CAPACITY: usize = 65_536;

/// Latest-value progress payload; the core coalesces updates at 50 ms.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgressSnapshot {
    pub completed: usize,
    pub alive: usize,
}

/// Lifecycle position of the scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanPhase {
    Plan,
    Run,
    Finalize,
}

/// Severity of a progress log line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// Ordered events of a scan.
///
/// Progress is on the watch lane only and never appears in `ScanEvent`.
#[derive(Debug)]
pub enum ScanEvent {
    Started {
        plan_endpoints: usize,
        concurrency: usize,
    },
    Result(ProbeOutcome),
    Phase(ScanPhase),
    Log {
        level: LogLevel,
        message: String,
    },
    Done(ScanSummary),
    Failed(ScanError),
}

/// The two lanes a scan writes to.
///
/// `progress` is the latest-value lane (50 ms coalescing in core, never
/// blocks). `results` is the ordered capacity-65,536 mpsc lane; every send
/// goes through `try_send`, and a full lane aborts with `ResultLaneOverflow`.
#[derive(Clone)]
pub struct EventSink {
    pub progress: watch::Sender<ProgressSnapshot>,
    pub results: mpsc::Sender<ScanEvent>,
}
