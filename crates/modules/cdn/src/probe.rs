//! CDN latency probe: a warm-up connect plus fixed measurement tries.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use cftool_core::probe::{
    AliveDetail, AliveKind, AttemptRecord, BoxFuture, DeadReason, Probe, ProbeOutcome, ProbeVerdict,
};
use cftool_core::result::CellValue;
use cftool_core::target::{ProbeBudget, ProbeTarget};
use reqwest::redirect::Policy;
use time::OffsetDateTime;
use tokio::net::TcpSocket;

use crate::options::CdnMode;

const SPEED_URL: &str = "https://speed.cloudflare.com/";
const WARMUP_TIMEOUT: Duration = Duration::from_secs(1);

pub struct CdnProbe {
    pub mode: CdnMode,
}

impl CdnProbe {
    pub fn new(mode: CdnMode) -> Self {
        Self { mode }
    }
}

/// Colo extraction requires BOTH `server: cloudflare` and a `cf-ray` suffix.
pub fn extract_colo(cf_ray: &str, server: Option<&str>) -> Option<String> {
    if !server?.eq_ignore_ascii_case("cloudflare") {
        return None;
    }
    let (_, colo) = cf_ray.rsplit_once('-')?;
    if colo.is_empty() {
        return None;
    }
    Some(colo.to_ascii_uppercase())
}

fn pinned_client(addr: SocketAddr) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .resolve("speed.cloudflare.com", addr)
        .redirect(Policy::none())
        .build()
}

fn tcp_socket(addr: IpAddr) -> std::io::Result<TcpSocket> {
    match addr {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
}

impl Probe for CdnProbe {
    fn probe<'a>(
        &'a self,
        target: ProbeTarget,
        budget: ProbeBudget,
    ) -> BoxFuture<'a, ProbeOutcome> {
        Box::pin(async move {
            let started_at = OffsetDateTime::now_utc();
            let http = matches!(self.mode, CdnMode::Http);
            let addr = SocketAddr::new(target.addr, target.port);

            let finish = |verdict: ProbeVerdict, attempts: AttemptRecord| ProbeOutcome {
                target,
                verdict,
                attempts,
                started_at,
            };
            let cancelled = |made: u8, ok: u8, rtts: Vec<u32>| {
                finish(
                    ProbeVerdict::Dead {
                        reason: DeadReason::Cancelled,
                    },
                    AttemptRecord {
                        tries_made: made,
                        tries_succeeded: ok,
                        try_rtts_us: rtts,
                    },
                )
            };

            if budget.cancel.is_cancelled() {
                return cancelled(1, 0, Vec::new());
            }

            // Warm-up is excluded from the attempt record and its failure ignored.
            if http {
                if let Ok(client) = pinned_client(addr) {
                    let warmup = client.head(SPEED_URL).header("Connection", "close").send();
                    tokio::select! {
                        _ = budget.cancel.cancelled() => return cancelled(0, 0, Vec::new()),
                        _ = tokio::time::timeout(WARMUP_TIMEOUT, warmup) => {}
                    }
                }
            } else if let Ok(socket) = tcp_socket(target.addr) {
                tokio::select! {
                    _ = budget.cancel.cancelled() => return cancelled(0, 0, Vec::new()),
                    _ = tokio::time::timeout(WARMUP_TIMEOUT, socket.connect(addr)) => {}
                }
            }

            let tries = budget.max_attempts;
            let mut made: u8 = 0;
            let mut successes: u8 = 0;
            let mut rtts: Vec<u32> = Vec::new();
            let mut saw_connect_error = false;
            let mut status: Option<u16> = None;
            let mut colo: Option<String> = None;

            for _ in 0..tries {
                if budget.cancel.is_cancelled() {
                    return cancelled(made, successes, rtts);
                }
                made += 1;
                let begin = Instant::now();

                if http {
                    let Ok(client) = pinned_client(addr) else {
                        saw_connect_error = true;
                        continue;
                    };
                    let request = client.head(SPEED_URL).header("Connection", "close").send();
                    let result = tokio::select! {
                        _ = budget.cancel.cancelled() => return cancelled(made, successes, rtts),
                        result = tokio::time::timeout(budget.per_attempt_timeout, request) => result,
                    };
                    if let Ok(Ok(response)) = result {
                        let code = response.status().as_u16();
                        let ray = response
                            .headers()
                            .get("cf-ray")
                            .and_then(|v| v.to_str().ok());
                        let server = response
                            .headers()
                            .get("server")
                            .and_then(|v| v.to_str().ok());
                        if matches!(code, 200 | 301 | 302)
                            && let Some(found_colo) = ray.and_then(|r| extract_colo(r, server))
                        {
                            successes += 1;
                            rtts.push(begin.elapsed().as_micros() as u32);
                            status = Some(code);
                            colo = Some(found_colo);
                        }
                    } else if result.is_err() {
                        saw_connect_error = true;
                    }
                } else {
                    let Ok(socket) = tcp_socket(target.addr) else {
                        saw_connect_error = true;
                        continue;
                    };
                    let result = tokio::select! {
                        _ = budget.cancel.cancelled() => return cancelled(made, successes, rtts),
                        result = tokio::time::timeout(budget.per_attempt_timeout, socket.connect(addr)) => result,
                    };
                    match result {
                        Ok(Ok(_)) => {
                            successes += 1;
                            rtts.push(begin.elapsed().as_micros() as u32);
                        }
                        Ok(Err(_)) => saw_connect_error = true,
                        Err(_) => {}
                    }
                }
            }

            let attempts = AttemptRecord {
                tries_made: tries,
                tries_succeeded: successes,
                try_rtts_us: rtts,
            };

            if successes == 0 {
                let reason = if saw_connect_error {
                    DeadReason::Unreachable
                } else {
                    DeadReason::Timeout
                };
                return finish(ProbeVerdict::Dead { reason }, attempts);
            }

            let mut facts = std::collections::BTreeMap::new();
            if http {
                if let Some(code) = status {
                    facts.insert("status".to_string(), CellValue::Number(f64::from(code)));
                }
                if let Some(found) = colo {
                    facts.insert("colo".to_string(), CellValue::Text(found));
                }
            }

            finish(
                ProbeVerdict::Alive {
                    rtt: None,
                    detail: AliveDetail {
                        kind: AliveKind::Connected,
                        facts,
                    },
                },
                attempts,
            )
        })
    }
}
