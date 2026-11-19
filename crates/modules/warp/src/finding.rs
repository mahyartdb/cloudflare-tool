use cftool_core::error::ScanError;
use cftool_core::options::ModuleOptions;
use cftool_core::probe::{AliveKind, BoxFuture, ProbeOutcome, ProbeVerdict};
use cftool_core::result::{CellValue, FindingRow, ModuleFinding};
use tokio_util::sync::CancellationToken;

use crate::options::{COLUMNS, NoisePreset, WarpOptions};

#[derive(Clone, Debug)]
pub struct WarpFinding {
    pub endpoint: String,
    pub rtt_us: Option<u32>,
    pub status: &'static str,
    pub colo: Option<String>,
    pub exit_country: Option<String>,
    pub noise_preset: NoisePreset,
    pub rank: Option<u64>,
    pub filtered: bool,
}

impl ModuleFinding for WarpFinding {
    fn sort_rank(&self) -> Option<u64> {
        self.rank
    }

    fn to_row(&self) -> FindingRow {
        let values = [
            CellValue::Text(self.endpoint.clone()),
            match self.rtt_us {
                Some(rtt_us) => CellValue::Number(rtt_us as f64 / 1000.0),
                None => CellValue::Null,
            },
            CellValue::Text(self.status.to_string()),
            self.colo.clone().map_or(CellValue::Null, CellValue::Text),
            self.exit_country
                .clone()
                .map_or(CellValue::Null, CellValue::Text),
            CellValue::Text(noise_name(&self.noise_preset).to_string()),
        ];

        FindingRow {
            columns: COLUMNS
                .iter()
                .copied()
                .zip(values)
                .map(|(key, value)| (key.key.to_string(), value))
                .collect(),
        }
    }

    fn is_filtered(&self) -> bool {
        self.filtered
    }
}

fn noise_name(preset: &NoisePreset) -> &'static str {
    match preset {
        NoisePreset::Off => "off",
        NoisePreset::Light => "light",
        NoisePreset::Heavy => "heavy",
    }
}

pub fn finalize<'a>(
    outcomes: &'a [ProbeOutcome],
    opts: &'a ModuleOptions,
    cancel: &'a CancellationToken,
) -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>> {
    Box::pin(async move {
        let options = WarpOptions::try_from_options(opts)?;
        let _ = cancel;

        let findings = finalize_findings(outcomes, &options);
        Ok(findings
            .into_iter()
            .map(|finding| Box::new(finding) as Box<dyn ModuleFinding>)
            .collect())
    })
}

fn finalize_findings(outcomes: &[ProbeOutcome], options: &WarpOptions) -> Vec<WarpFinding> {
    let mut findings = collect_findings(outcomes, options);
    apply_limits(&mut findings, options);
    order_findings(findings)
}

fn collect_findings(outcomes: &[ProbeOutcome], options: &WarpOptions) -> Vec<WarpFinding> {
    let mut findings = Vec::new();

    for outcome in outcomes {
        let ProbeVerdict::Alive { rtt, detail } = &outcome.verdict else {
            continue;
        };

        let rtt_us = rtt.as_ref().map(|rtt| rtt.as_micros() as u32);
        let (status, rtt_us, rank) = if matches!(&detail.kind, AliveKind::Type2Response) {
            ("alive", rtt_us, rtt_us.map(u64::from))
        } else if matches!(&detail.kind, AliveKind::Cookie) {
            ("cookie", None, None)
        } else {
            continue;
        };

        findings.push(WarpFinding {
            endpoint: format!("{}:{}", outcome.target.addr, outcome.target.port),
            rtt_us,
            status,
            colo: None,
            exit_country: None,
            noise_preset: options.noise,
            rank,
            filtered: false,
        });
    }

    findings
}

fn apply_limits(findings: &mut [WarpFinding], options: &WarpOptions) {
    let max_rtt_us = options.max_rtt_ms.saturating_mul(1000);

    for finding in findings.iter_mut() {
        if let (Some(_), Some(rtt_us)) = (finding.rank, finding.rtt_us)
            && u64::from(rtt_us) > max_rtt_us
        {
            finding.filtered = true;
        }
    }

    let mut ranked: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| finding.rank.map(|_| index))
        .collect();
    ranked.sort_by_key(|&index| (findings[index].rank.unwrap(), index));

    for &index in ranked.iter().skip(options.results) {
        findings[index].filtered = true;
    }
}

fn order_findings(findings: Vec<WarpFinding>) -> Vec<WarpFinding> {
    let mut ranked: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| finding.rank.map(|_| index))
        .collect();
    ranked.sort_by_key(|&index| (findings[index].rank.unwrap(), index));

    let mut ordered = Vec::with_capacity(findings.len());
    for &index in &ranked {
        ordered.push(findings[index].clone());
    }
    for finding in findings.iter().filter(|finding| finding.rank.is_none()) {
        ordered.push(finding.clone());
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use cftool_core::probe::{AliveDetail, AttemptRecord};
    use cftool_core::result::ModuleFinding;
    use cftool_core::target::ProbeTarget;
    use std::time::Duration;

    fn synth(addr: &str, rtt_ms: Option<u64>, kind: AliveKind) -> ProbeOutcome {
        ProbeOutcome {
            target: ProbeTarget {
                addr: addr.parse().expect("test address"),
                port: 443,
            },
            verdict: ProbeVerdict::Alive {
                rtt: rtt_ms.map(Duration::from_millis),
                detail: AliveDetail {
                    kind,
                    ..Default::default()
                },
            },
            attempts: AttemptRecord {
                tries_made: 1,
                tries_succeeded: 1,
                try_rtts_us: Vec::new(),
            },
            started_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn t8_rank_order() {
        let outcomes = vec![
            synth("198.51.100.1", Some(20), AliveKind::Type2Response),
            synth("198.51.100.2", Some(5), AliveKind::Type2Response),
            synth("198.51.100.3", Some(40), AliveKind::Type2Response),
            synth("198.51.100.4", None, AliveKind::Cookie),
        ];

        let options = WarpOptions {
            max_rtt_ms: 10_000,
            results: 10,
            ..Default::default()
        };

        let findings = finalize_findings(&outcomes, &options);
        let rtts: Vec<Option<u32>> = findings.iter().map(|finding| finding.rtt_us).collect();

        assert_eq!(rtts, vec![Some(5_000), Some(20_000), Some(40_000), None]);
        assert_eq!(findings.last().unwrap().status, "cookie");
        assert_eq!(findings.last().unwrap().sort_rank(), None);
    }

    #[test]
    fn t8_filters_mark_not_drop() {
        let outcomes = vec![
            synth("198.51.100.1", Some(20), AliveKind::Type2Response),
            synth("198.51.100.2", Some(5), AliveKind::Type2Response),
            synth("198.51.100.3", Some(40), AliveKind::Type2Response),
            synth("198.51.100.4", None, AliveKind::Cookie),
        ];

        let options = WarpOptions {
            max_rtt_ms: 30,
            results: 1,
            ..Default::default()
        };

        let findings = finalize_findings(&outcomes, &options);

        assert_eq!(findings.len(), outcomes.len());
        assert!(
            !findings
                .iter()
                .find(|finding| finding.rtt_us == Some(5_000))
                .expect("5ms finding")
                .is_filtered()
        );
        assert!(
            findings
                .iter()
                .find(|finding| finding.rtt_us == Some(20_000))
                .expect("20ms finding")
                .is_filtered()
        );
        assert!(
            findings
                .iter()
                .find(|finding| finding.rtt_us == Some(40_000))
                .expect("40ms finding")
                .is_filtered()
        );

        let cookie = findings
            .iter()
            .find(|finding| finding.status == "cookie")
            .expect("cookie finding");
        assert!(!cookie.is_filtered());
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.is_filtered())
                .count(),
            2
        );
    }
}
