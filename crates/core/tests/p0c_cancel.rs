static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

mod support;

use support::*;

use std::time::Duration;

use cftool_core::result::CellValue;
use cftool_core::runner::{ProbeRunner, ProbeRunnerConfig};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn c8_stop_on_first_answer_skips_tail_ports() {
    let _guard = TEST_LOCK.lock().await;
    let source = ScriptedSource::new(vec![Reply::Dead, Reply::Alive { rtt_ms: 1 }, Reply::Dead]);
    let plan = make_plan(&[1, 2, 3], true, 3, 3);
    let config = ProbeRunnerConfig {
        concurrency: 1,
        total_budget: Duration::from_secs(60),
    };
    let (events, _scan_events, _progress) = channels(65536);
    let cancel = CancellationToken::new();
    let runner = ProbeRunner::new(
        config,
        Default::default(),
        TestModule::new(FinalizeBehavior::Normal),
    )
    .expect("runner construction should succeed");

    let summary = runner
        .run(plan, source.clone(), events, cancel)
        .await
        .expect("run should succeed");

    assert_eq!(summary.totals.probed, 2);
    assert_eq!(summary.totals.alive, 1);

    let probed = source.probed.lock().unwrap();
    let ports: Vec<u16> = probed.iter().map(|target| target.port).collect();
    assert_eq!(ports, vec![1, 2]);
}

#[tokio::test]
async fn c8_flag_unset_probes_all_ports() {
    let _guard = TEST_LOCK.lock().await;
    let source = ScriptedSource::new(vec![Reply::Dead, Reply::Alive { rtt_ms: 1 }, Reply::Dead]);
    let plan = make_plan(&[1, 2, 3], false, 3, 3);
    let config = ProbeRunnerConfig {
        concurrency: 1,
        total_budget: Duration::from_secs(60),
    };
    let (events, _scan_events, _progress) = channels(65536);
    let cancel = CancellationToken::new();
    let runner = ProbeRunner::new(
        config,
        Default::default(),
        TestModule::new(FinalizeBehavior::Normal),
    )
    .expect("runner construction should succeed");

    let summary = runner
        .run(plan, source.clone(), events, cancel)
        .await
        .expect("run should succeed");

    assert_eq!(summary.totals.probed, 3);
    assert_eq!(summary.totals.alive, 1);

    let probed = source.probed.lock().unwrap();
    let ports: Vec<u16> = probed.iter().map(|target| target.port).collect();
    assert_eq!(ports, vec![1, 2, 3]);
}

#[tokio::test]
async fn c9_cancel_during_finalize_keeps_every_alive_finding() {
    let _guard = TEST_LOCK.lock().await;
    let source = ScriptedSource::new(vec![
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
        Reply::Alive { rtt_ms: 1 },
    ]);
    let plan = make_plan(&[1, 2, 3], false, 3, 3);
    let config = ProbeRunnerConfig {
        concurrency: 3,
        total_budget: Duration::from_secs(60),
    };
    let module = TestModule::new(FinalizeBehavior::Block);
    let entered = module.entered.clone();
    let release = module.release.clone();
    let (events, _scan_events, _progress) = channels(65536);
    let cancel = CancellationToken::new();
    let run_cancel = cancel.clone();

    let handle = tokio::spawn(async move {
        let runner = ProbeRunner::new(config, Default::default(), module)
            .expect("runner construction should succeed");
        runner.run(plan, source, events, run_cancel).await
    });

    entered.notified().await;
    cancel.cancel();
    release.notify_one();

    let summary = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run did not finish within 5s after finalize was released")
        .expect("run task panicked")
        .expect("run returned an error after cancel");

    assert!(summary.totals.cancelled);
    assert_eq!(summary.findings.len(), 3);
    assert_eq!(summary.totals.probed, 3);
    assert_eq!(summary.totals.alive, 3);

    for finding in summary.findings {
        let row = finding.to_row();
        assert!(
            row.columns
                .iter()
                .any(|(key, value)| key.as_str() == "speed" && matches!(value, CellValue::Null)),
            "expected speed=Null on every finding after cancel, got {:?}",
            row.columns
        );
    }
}
