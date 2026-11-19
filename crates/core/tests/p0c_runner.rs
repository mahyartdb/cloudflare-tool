static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

mod support;
use support::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

use cftool_core::error::ScanError;
use cftool_core::events::{ScanEvent, ScanPhase};
use cftool_core::options::ModuleOptions;
use cftool_core::probe::{DeadReason, ProbeOutcome, ProbeVerdict};
use cftool_core::runner::{HARD_CONCURRENCY_CEILING, ProbeRunner, ProbeRunnerConfig};
use tokio_util::sync::CancellationToken;

fn runner_config(concurrency: usize, budget_secs: u64) -> ProbeRunnerConfig {
    ProbeRunnerConfig {
        concurrency,
        total_budget: Duration::from_secs(budget_secs),
    }
}

fn build_runner(config: ProbeRunnerConfig, behavior: FinalizeBehavior) -> ProbeRunner {
    ProbeRunner::new(config, ModuleOptions::default(), TestModule::new(behavior))
        .expect("ProbeRunner::new must accept the test configuration")
}

fn result_outcomes(events: &[ScanEvent]) -> Vec<&ProbeOutcome> {
    let mut outcomes = Vec::new();
    for event in events {
        if let ScanEvent::Result(outcome) = event {
            outcomes.push(outcome);
        }
    }
    outcomes
}

fn classify(outcome: &ProbeOutcome) -> (u16, &'static str) {
    let port = outcome.target.port;
    match &outcome.verdict {
        ProbeVerdict::Alive { .. } => (port, "alive"),
        ProbeVerdict::Dead { reason } => {
            if matches!(reason, DeadReason::Internal) {
                (port, "internal")
            } else if matches!(reason, DeadReason::Cancelled) {
                (port, "cancelled")
            } else {
                (port, "other")
            }
        }
    }
}

#[tokio::test]
async fn c3_events_ordered_done_last() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(3, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
    ]);
    let plan = make_plan(&[1, 2, 3], false, 3, 3);
    let (sink, mut rx, _progress_rx) = channels(65536);
    let cancel = CancellationToken::new();

    let summary = runner
        .run(plan, source, sink, cancel)
        .await
        .expect("run must succeed");
    assert_eq!(summary.totals.probed, 3);

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    assert_eq!(
        events.len(),
        8,
        "expected plan, started, run, 3 results, finalize, done; got {} events",
        events.len()
    );

    assert!(
        matches!(&events[0], ScanEvent::Phase(ScanPhase::Plan)),
        "event 0 must be Phase(Plan)"
    );
    match &events[1] {
        ScanEvent::Started {
            plan_endpoints,
            concurrency,
        } => {
            assert_eq!(
                *plan_endpoints, 3,
                "Started must report 3 planned endpoints"
            );
            assert_eq!(
                *concurrency, 3,
                "Started must report the effective concurrency"
            );
        }
        _ => panic!("event 1 must be Started"),
    }
    assert!(
        matches!(&events[2], ScanEvent::Phase(ScanPhase::Run)),
        "event 2 must be Phase(Run)"
    );

    for (index, event) in events[3..6].iter().enumerate() {
        assert!(
            matches!(event, ScanEvent::Result(_)),
            "event {} must be a Result",
            index + 3
        );
    }
    assert_eq!(
        result_outcomes(&events).len(),
        3,
        "exactly 3 result events must be emitted"
    );

    assert!(
        matches!(&events[6], ScanEvent::Phase(ScanPhase::Finalize)),
        "event 6 must be Phase(Finalize)"
    );
    assert!(
        matches!(&events[7], ScanEvent::Done(_)),
        "Done must be the last event"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, ScanEvent::Failed(_))),
        "a successful run must not emit Failed"
    );
}

#[tokio::test]
async fn c3_progress_final_snapshot_matches_totals() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(4, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
    ]);
    let plan = make_plan(&[1, 2, 3, 4], false, 4, 4);
    let (sink, _rx, progress_rx) = channels(65536);
    let cancel = CancellationToken::new();

    let summary = runner
        .run(plan, source, sink, cancel)
        .await
        .expect("run must succeed");

    let (completed, alive) = {
        let snapshot = progress_rx.borrow();
        (snapshot.completed, snapshot.alive)
    };

    assert_eq!(
        completed, summary.totals.probed,
        "final progress must match the probed total"
    );
    assert_eq!(completed, 4, "all 4 endpoints must be completed");
    assert_eq!(
        alive, summary.totals.alive,
        "final progress must match the alive total"
    );
    assert_eq!(alive, 4, "all 4 endpoints must be alive");
}

#[tokio::test]
async fn c3_full_result_lane_aborts_with_overflow() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(4, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
    ]);
    let plan = make_plan(&[1, 2, 3, 4], false, 4, 4);
    let (sink, _rx, _progress_rx) = channels(1);
    let cancel = CancellationToken::new();

    match runner.run(plan, source, sink, cancel).await {
        Err(ScanError::ResultLaneOverflow { capacity }) => {
            assert_eq!(
                capacity, 65536,
                "overflow must report the hard result-lane capacity"
            );
        }
        Ok(_) => panic!("a full result lane must abort the run"),
        Err(_) => panic!("expected ScanError::ResultLaneOverflow"),
    }
}

#[tokio::test]
async fn c3_receiver_drop_is_cancelled() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(1, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![Reply::Alive { rtt_ms: 1 }]);
    let plan = make_plan(&[1], false, 1, 1);
    let (sink, rx, _progress_rx) = channels(65536);
    drop(rx);
    let cancel = CancellationToken::new();

    match runner.run(plan, source, sink, cancel).await {
        Err(ScanError::Cancelled) => {}
        Ok(_) => panic!("run must fail when the result receiver is dropped"),
        Err(_) => panic!("expected ScanError::Cancelled"),
    }
}

#[tokio::test]
async fn c4_cancel_stops_within_500ms() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(8, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
        Reply::Slow { rtt_ms: 5000 },
    ]);
    let plan = make_plan(&[1, 2, 3, 4, 5, 6, 7, 8], false, 8, 60_000);
    let (sink, _rx, _progress_rx) = channels(65536);
    let cancel = CancellationToken::new();

    let task_cancel = cancel.clone();
    let task_source = Arc::clone(&source);
    let handle =
        tokio::spawn(async move { runner.run(plan, task_source, sink, task_cancel).await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    cancel.cancel();

    let joined = tokio::time::timeout(Duration::from_millis(500), handle)
        .await
        .expect("run did not stop within 500ms after cancellation");
    let elapsed = started.elapsed();
    let summary = joined
        .expect("runner task panicked")
        .expect("a cancelled run must still return a summary");

    assert!(
        elapsed < Duration::from_millis(500),
        "cancellation took {elapsed:?}"
    );
    assert!(
        summary.totals.cancelled,
        "summary must report that the run was cancelled"
    );
    let probed = source.probed.lock().expect("probed lock").len();
    assert_eq!(probed, 8, "all 8 dispatched targets must be recorded");
}

#[tokio::test]
async fn c5_second_concurrent_run_is_busy() {
    let _guard = TEST_LOCK.lock().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        let module = TestModule::new(FinalizeBehavior::Block);
        let entered = Arc::clone(&module.entered);
        let release = Arc::clone(&module.release);
        let runner = Arc::new(
            ProbeRunner::new(runner_config(1, 60), ModuleOptions::default(), module)
                .expect("ProbeRunner::new must accept the test configuration"),
        );

        let (sink, _rx, _progress_rx) = channels(65536);
        let source = ScriptedSource::new(vec![Reply::Alive { rtt_ms: 1 }]);
        let plan = make_plan(&[1], false, 1, 1);
        let cancel = CancellationToken::new();

        let task_runner = Arc::clone(&runner);
        let first = tokio::spawn(async move { task_runner.run(plan, source, sink, cancel).await });

        entered.notified().await;

        let (second_sink, _second_rx, _second_progress_rx) = channels(65536);
        let second_source = ScriptedSource::new(vec![Reply::Alive { rtt_ms: 1 }]);
        let second_plan = make_plan(&[2], false, 1, 1);
        let second_cancel = CancellationToken::new();

        match runner
            .run(second_plan, second_source, second_sink, second_cancel)
            .await
        {
            Err(ScanError::Busy) => {}
            Ok(_) => panic!("a second run while the first holds the permit must fail busy"),
            Err(_) => panic!("expected ScanError::Busy for the concurrent run"),
        }

        release.notify_one();

        let summary = first
            .await
            .expect("first run task panicked")
            .expect("first run must succeed once released");
        assert_eq!(summary.totals.probed, 1);
    })
    .await
    .expect("busy-run test timed out");
}

#[tokio::test]
async fn c6_panicking_probe_is_dead_internal_and_scan_continues() {
    let _guard = TEST_LOCK.lock().await;
    let runner = build_runner(runner_config(1, 60), FinalizeBehavior::Normal);
    let source = ScriptedSource::new(vec![Reply::Panic, Reply::Alive { rtt_ms: 1 }]);
    let plan = make_plan(&[1, 2], false, 1, 60_000);
    let (sink, mut rx, _progress_rx) = channels(65536);
    let cancel = CancellationToken::new();

    let summary = runner
        .run(plan, source, sink, cancel)
        .await
        .expect("a panicking probe must not fail the scan");
    assert_eq!(summary.totals.probed, 2);
    assert_eq!(summary.totals.alive, 1);

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    let mut by_port = std::collections::HashMap::new();
    for outcome in result_outcomes(&events) {
        by_port.insert(classify(outcome).0, classify(outcome).1);
    }

    assert_eq!(
        by_port.get(&1),
        Some(&"internal"),
        "port 1 must be Dead {{ reason: Internal }}"
    );
    assert_eq!(
        by_port.get(&2),
        Some(&"alive"),
        "port 2 must be Alive after the panicking probe"
    );
}

#[test]
fn c7_concurrency_backstop() {
    let result = ProbeRunner::new(
        ProbeRunnerConfig {
            concurrency: 5000,
            total_budget: Duration::from_secs(60),
        },
        ModuleOptions::default(),
        TestModule::new(FinalizeBehavior::Normal),
    );

    let message = match result {
        Err(ScanError::InvalidPlan(message)) => message,
        Ok(_) => panic!("concurrency 5000 exceeds the hard ceiling and must be rejected"),
        Err(_) => panic!("expected ScanError::InvalidPlan for concurrency 5000"),
    }
    .to_string();

    assert!(
        message.contains("5000"),
        "plan error must name the requested concurrency: {message}"
    );
    assert!(
        message.contains(&HARD_CONCURRENCY_CEILING.to_string()),
        "plan error must name the hard ceiling: {message}"
    );
    assert_eq!(HARD_CONCURRENCY_CEILING, 4096);
}
