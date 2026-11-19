//! CDN findings: filter marking (T3), ranking, and the T7 speed policy.

use cftool_core::error::ScanError;
use cftool_core::options::ModuleOptions;
use cftool_core::probe::{AttemptRecord, BoxFuture, ProbeOutcome, ProbeVerdict};
use cftool_core::result::{CellValue, FindingRow, ModuleFinding};
use tokio_util::sync::CancellationToken;

use crate::options::{COLUMNS, CdnOptions};

#[derive(Clone, Debug)]
pub struct CdnFinding {
    pub ip: String,
    pub rtt_us: u32,
    pub loss_pct: f64,
    pub attempts: u8,
    pub port: u16,
    pub colo: Option<String>,
    pub speed_mb_per_s: Option<f64>,
    pub truncated: bool,
    pub status: &'static str,
    pub filtered: bool,
    pub rank: Option<u64>,
}

impl ModuleFinding for CdnFinding {
    fn sort_rank(&self) -> Option<u64> {
        self.rank
    }

    fn is_filtered(&self) -> bool {
        self.filtered
    }

    fn to_row(&self) -> FindingRow {
        let mut columns = Vec::with_capacity(COLUMNS.len());
        for name in COLUMNS.iter() {
            let key: &str = name.key;
            let value = match key {
                "ip" => CellValue::Text(self.ip.clone()),
                "rtt_ms" => CellValue::Number(f64::from(self.rtt_us) / 1000.0),
                "loss_pct" => CellValue::Number(self.loss_pct),
                "attempts" => CellValue::Number(f64::from(self.attempts)),
                "port" => CellValue::Number(f64::from(self.port)),
                "colo" => match &self.colo {
                    Some(colo) => CellValue::Text(colo.clone()),
                    None => CellValue::Null,
                },
                "speed_mb_per_s" => match self.speed_mb_per_s {
                    Some(speed) => CellValue::Number(speed),
                    None => CellValue::Null,
                },
                "truncated" => CellValue::Bool(self.truncated),
                "status" => CellValue::Text(self.status.to_string()),
                other => unreachable!("unknown finding column: {other}"),
            };
            columns.push((key.to_string(), value));
        }
        FindingRow { columns }
    }
}

pub fn mean_rtt_us(attempts: &AttemptRecord) -> u32 {
    if attempts.try_rtts_us.is_empty() {
        return 0;
    }
    let total: u64 = attempts.try_rtts_us.iter().map(|&rtt| u64::from(rtt)).sum();
    let mean = total / attempts.try_rtts_us.len() as u64;
    mean.min(u64::from(u32::MAX)) as u32
}

pub fn loss_pct(attempts: &AttemptRecord) -> f64 {
    if attempts.tries_made == 0 {
        return 0.0;
    }
    let made = f64::from(attempts.tries_made);
    let succeeded = f64::from(attempts.tries_succeeded);
    (made - succeeded) / made * 100.0
}

pub fn ewma(windows: &[f64]) -> Option<f64> {
    let mut iter = windows.iter().copied();
    let mut state = iter.next()?;
    for window in iter {
        state = 0.25 * window + 0.75 * state;
    }
    Some(state)
}

/// Build one finding per alive outcome, mark filtered rows, and return them in
/// rank order. Cancellation does not truncate the pass in v1.
///
/// The live HTTP download is driven by the CLI/integration layer, which feeds
/// measured rates to [`apply_speed`]; that helper is the tested policy seam.
pub fn finalize<'a>(
    outcomes: &'a [ProbeOutcome],
    opts: &'a ModuleOptions,
    cancel: &'a CancellationToken,
) -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>> {
    Box::pin(async move {
        let options = CdnOptions::try_from_options(opts)?;
        let findings = collect(outcomes, &options);
        let _ = cancel;
        Ok(findings
            .into_iter()
            .map(|finding| Box::new(finding) as Box<dyn ModuleFinding>)
            .collect())
    })
}

/// Assign measured window rates (MB/s) to the first rankable findings.
///
/// `findings` is expected in rank order. Rates below 0.01 MB/s mark the
/// candidate origin-suspect and unranked. At most ten candidates are measured,
/// and the pass stops once `speed_count` candidates meet `speed_min` when
/// `speed_min > 0`.
pub fn apply_speed(findings: &mut [CdnFinding], o: &CdnOptions, feed: &[f64]) {
    let limit = o.speed_count.min(10);
    if limit == 0 {
        return;
    }
    let floor = o.speed_min;
    let mut rates = feed.iter().copied();
    let mut measured = 0usize;
    let mut met = 0usize;
    for finding in findings.iter_mut() {
        if measured >= limit {
            break;
        }
        if finding.filtered || finding.status != "ok" {
            continue;
        }
        let Some(rate) = rates.next() else {
            break;
        };
        measured += 1;
        if rate < 0.01 {
            finding.speed_mb_per_s = None;
            finding.status = "origin-suspect";
            finding.rank = None;
            continue;
        }
        finding.speed_mb_per_s = Some(rate);
        finding.rank = rank_for(finding);
        if floor > 0.0 && rate >= floor {
            met += 1;
            if met >= o.speed_count {
                break;
            }
        }
    }
}

fn collect(outcomes: &[ProbeOutcome], options: &CdnOptions) -> Vec<CdnFinding> {
    let mut findings: Vec<CdnFinding> = outcomes.iter().filter_map(finding_for).collect();
    mark_filtered(&mut findings, options);
    assign_ranks(&mut findings);
    findings.sort_by_key(|finding| (finding.rank.is_none(), finding.rank.unwrap_or(0)));
    findings
}

fn finding_for(outcome: &ProbeOutcome) -> Option<CdnFinding> {
    let detail = match &outcome.verdict {
        ProbeVerdict::Alive { detail, .. } => detail,
        _ => return None,
    };
    let colo = match detail.facts.get("colo") {
        Some(CellValue::Text(colo)) if !colo.is_empty() => Some(colo.clone()),
        _ => None,
    };
    let attempts = &outcome.attempts;
    Some(CdnFinding {
        ip: outcome.target.addr.to_string(),
        rtt_us: mean_rtt_us(attempts),
        loss_pct: loss_pct(attempts),
        attempts: attempts.tries_made,
        port: outcome.target.port,
        colo,
        speed_mb_per_s: None,
        truncated: false,
        status: "ok",
        filtered: false,
        rank: None,
    })
}

fn mark_filtered(findings: &mut [CdnFinding], o: &CdnOptions) {
    let max_rtt_ms = o.max_rtt_ms as f64;
    let min_rtt_ms = o.min_rtt_ms as f64;
    let max_loss_pct = o.max_loss_pct;
    for finding in findings.iter_mut() {
        let rtt_ms = f64::from(finding.rtt_us) / 1000.0;
        let colo_match = match finding.colo.as_deref() {
            Some(colo) => o
                .cfcolo
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(colo)),
            None => false,
        };
        finding.filtered = rtt_ms > max_rtt_ms
            || (min_rtt_ms > 0.0 && rtt_ms < min_rtt_ms)
            || finding.loss_pct > max_loss_pct
            || (!o.cfcolo.is_empty() && !colo_match);
    }
}

fn assign_ranks(findings: &mut [CdnFinding]) {
    for finding in findings.iter_mut() {
        finding.rank = rank_for(finding);
    }
}

fn rank_for(finding: &CdnFinding) -> Option<u64> {
    if finding.status != "ok" {
        return None;
    }
    match finding.speed_mb_per_s {
        Some(speed) => {
            let scaled = (speed.max(0.0) * 1000.0) as u64;
            let base = 1_000_000_000u64.saturating_sub(scaled.min(999_000_000));
            Some(base.saturating_add(u64::from(finding.rtt_us)))
        }
        None => Some(2_000_000_000u64.saturating_add(u64::from(finding.rtt_us))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use cftool_core::probe::{AliveDetail, AliveKind, DeadReason, ProbeOutcome};
    use cftool_core::target::ProbeTarget;

    fn alive(
        addr: &str,
        port: u16,
        rtts: &[u32],
        tries_made: u8,
        tries_succeeded: u8,
        colo: Option<&str>,
    ) -> ProbeOutcome {
        let mut facts = BTreeMap::new();
        if let Some(colo) = colo {
            facts.insert("colo".to_string(), CellValue::Text(colo.to_string()));
        }
        ProbeOutcome {
            target: ProbeTarget {
                addr: addr.parse().unwrap(),
                port,
            },
            verdict: ProbeVerdict::Alive {
                rtt: None,
                detail: AliveDetail {
                    kind: AliveKind::Connected,
                    facts,
                },
            },
            attempts: AttemptRecord {
                tries_made,
                tries_succeeded,
                try_rtts_us: rtts.to_vec(),
            },
            started_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn dead(addr: &str, port: u16) -> ProbeOutcome {
        ProbeOutcome {
            target: ProbeTarget {
                addr: addr.parse().unwrap(),
                port,
            },
            verdict: ProbeVerdict::Dead {
                reason: DeadReason::Timeout,
            },
            attempts: AttemptRecord {
                tries_made: 3,
                tries_succeeded: 0,
                try_rtts_us: Vec::new(),
            },
            started_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn clean(ip: &str, rtt_us: u32) -> CdnFinding {
        CdnFinding {
            ip: ip.to_string(),
            rtt_us,
            loss_pct: 0.0,
            attempts: 3,
            port: 443,
            colo: None,
            speed_mb_per_s: None,
            truncated: false,
            status: "ok",
            filtered: false,
            rank: None,
        }
    }

    #[test]
    fn t3_filter_marks() {
        let o = CdnOptions {
            max_rtt_ms: 500,
            min_rtt_ms: 0,
            max_loss_pct: 20.0,
            cfcolo: Vec::new(),
            ..Default::default()
        };

        let outcomes = vec![
            alive("1.1.1.1", 443, &[900_000, 900_000], 2, 2, Some("HKG")),
            alive("2.2.2.2", 443, &[50_000], 4, 2, Some("NRT")),
            alive("3.3.3.3", 443, &[40_000], 2, 2, Some("SIN")),
            dead("4.4.4.4", 443),
        ];

        let findings = collect(&outcomes, &o);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.ip != "4.4.4.4"));

        let slow = findings.iter().find(|f| f.ip == "1.1.1.1").unwrap();
        assert_eq!(slow.rtt_us, 900_000);
        assert!(slow.filtered);
        assert_eq!(slow.status, "ok");

        let lossy = findings.iter().find(|f| f.ip == "2.2.2.2").unwrap();
        assert!((lossy.loss_pct - 50.0).abs() < 1e-9);
        assert!(lossy.filtered);

        let clean = findings.iter().find(|f| f.ip == "3.3.3.3").unwrap();
        assert!(!clean.filtered);
    }

    #[test]
    fn t7_ewma() {
        let value = ewma(&[1.0, 2.0, 3.0]).unwrap();
        assert!((value - 1.6875).abs() < 1e-12);
        assert_eq!(ewma(&[2.5]), Some(2.5));
        assert_eq!(ewma(&[]), None);
    }

    #[test]
    fn t7_speed_floor_stops() {
        let o = CdnOptions {
            speed_count: 3,
            speed_min: 1.0,
            ..Default::default()
        };

        let mut findings: Vec<CdnFinding> = (0..5)
            .map(|i| clean(&format!("10.0.0.{i}"), 10_000 + i as u32))
            .collect();
        assign_ranks(&mut findings);
        findings.sort_by_key(|f| (f.rank.is_none(), f.rank.unwrap_or(0)));

        apply_speed(&mut findings, &o, &[2.0, 2.0, 2.0, 2.0]);

        let measured = findings
            .iter()
            .filter(|f| f.speed_mb_per_s.is_some())
            .count();
        assert_eq!(measured, 3);
        assert_eq!(findings[0].speed_mb_per_s, Some(2.0));
        assert_eq!(findings[1].speed_mb_per_s, Some(2.0));
        assert_eq!(findings[2].speed_mb_per_s, Some(2.0));
        assert!(findings[3].speed_mb_per_s.is_none());
        assert!(findings[4].speed_mb_per_s.is_none());
    }
}
