use cftool_core::error::ScanError;
use cftool_core::options::{
    ModuleOptions, OptionDefault, OptionKind, OptionSpec, OptionValue, OptionsSpec,
};
use cftool_core::result::ColumnSpec;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CdnMode {
    #[default]
    Tcp,
    Http,
}

pub fn mode_name(m: CdnMode) -> &'static str {
    match m {
        CdnMode::Tcp => "tcp",
        CdnMode::Http => "http",
    }
}

#[derive(Clone, Debug)]
pub struct CdnOptions {
    pub mode: CdnMode,
    pub port: u16,
    pub attempts: u8,
    pub v6: bool,
    pub v6_samples: u16,
    pub all_ips: bool,
    pub sample_per_subnet: u16,
    pub concurrency: usize,
    pub timeout_per_probe_ms: u64,
    pub max_rtt_ms: u64,
    pub min_rtt_ms: u64,
    pub max_loss_pct: f64,
    pub cfcolo: Vec<String>,
    pub speed: bool,
    pub speed_count: usize,
    pub speed_time_s: u64,
    pub speed_min: f64,
    pub speed_max_bytes: u64,
    pub speed_url: String,
    pub scan_timeout_s: u64,
    pub scan_timeout_set: bool,
}

impl Default for CdnOptions {
    fn default() -> Self {
        Self {
            mode: CdnMode::Tcp,
            port: 443,
            attempts: 4,
            v6: false,
            v6_samples: 16,
            all_ips: false,
            sample_per_subnet: 1,
            concurrency: 200,
            timeout_per_probe_ms: 1000,
            max_rtt_ms: 200,
            min_rtt_ms: 0,
            max_loss_pct: 20.0,
            cfcolo: Vec::new(),
            speed: false,
            speed_count: 10,
            speed_time_s: 10,
            speed_min: 0.0,
            speed_max_bytes: 512_000_000,
            speed_url: "https://speed.cloudflare.com/__down?bytes=100000000".to_string(),
            scan_timeout_s: 180,
            scan_timeout_set: false,
        }
    }
}

impl CdnOptions {
    pub fn try_from_options(opts: &ModuleOptions) -> Result<Self, ScanError> {
        let d = CdnOptions::default();

        let mode = match get_text(opts, "mode")? {
            None => d.mode,
            Some(s) => match s.as_str() {
                "tcp" => CdnMode::Tcp,
                "http" => CdnMode::Http,
                other => {
                    return Err(options_invalid(
                        "mode",
                        format!("unknown mode '{other}', expected 'tcp' or 'http'"),
                    ));
                }
            },
        };

        let fixed_attempts: u8 = match mode {
            CdnMode::Tcp => 4,
            CdnMode::Http => 1,
        };
        let default_probe_ms: u64 = match mode {
            CdnMode::Tcp => 1000,
            CdnMode::Http => 2000,
        };

        let attempts = match get_number(opts, "attempts")? {
            None => fixed_attempts,
            Some(n) => {
                if whole("attempts", n)? != u64::from(fixed_attempts) {
                    return Err(options_invalid(
                        "attempts",
                        format!(
                            "{} mode fixes attempts at {fixed_attempts}",
                            mode_name(mode)
                        ),
                    ));
                }
                fixed_attempts
            }
        };

        let port = match get_number(opts, "port")? {
            None => d.port,
            Some(n) => bounded("port", n, 1, 65_535)? as u16,
        };

        let v6 = get_bool(opts, "v6")?.unwrap_or(d.v6);

        let v6_samples = match get_number(opts, "v6-samples")? {
            None => d.v6_samples,
            Some(n) => bounded("v6-samples", n, 1, u64::from(u16::MAX))? as u16,
        };

        let all_ips = get_bool(opts, "all-ips")?.unwrap_or(d.all_ips);

        let sample_per_subnet = match get_number(opts, "sample-per-subnet")? {
            None => d.sample_per_subnet,
            Some(n) => bounded("sample-per-subnet", n, 1, 256)? as u16,
        };

        let concurrency_hi = match mode {
            CdnMode::Tcp => 512,
            CdnMode::Http => 200,
        };
        let concurrency = match get_number(opts, "concurrency")? {
            None => d.concurrency,
            Some(n) => bounded("concurrency", n, 1, concurrency_hi)? as usize,
        };

        let timeout_per_probe_ms = match get_number(opts, "timeout-per-probe")? {
            None => default_probe_ms,
            Some(n) => bounded("timeout-per-probe", n, 200, u64::MAX)?,
        };

        let max_rtt_ms = match get_number(opts, "max-rtt")? {
            None => d.max_rtt_ms,
            Some(n) => whole("max-rtt", n)?,
        };

        let min_rtt_ms = match get_number(opts, "min-rtt")? {
            None => d.min_rtt_ms,
            Some(n) => whole("min-rtt", n)?,
        };

        let max_loss_pct = match get_number(opts, "max-loss")? {
            None => d.max_loss_pct,
            Some(n) => {
                if !(0.0..=100.0).contains(&n) {
                    return Err(options_invalid(
                        "max-loss",
                        format!("{n} is outside 0..=100"),
                    ));
                }
                n
            }
        };

        let cfcolo = get_list(opts, "cfcolo")?.unwrap_or_default();
        if !cfcolo.is_empty() && mode != CdnMode::Http {
            return Err(options_invalid(
                "cfcolo",
                "colo pinning requires mode 'http'",
            ));
        }

        let speed = get_bool(opts, "speed")?.unwrap_or(d.speed);

        let speed_count = match get_number(opts, "speed-count")? {
            None => d.speed_count,
            Some(n) => bounded("speed-count", n, 1, 10)? as usize,
        };

        let speed_time_s = match get_number(opts, "speed-time")? {
            None => d.speed_time_s,
            Some(n) => bounded("speed-time", n, 1, u64::MAX)?,
        };

        let speed_min = match get_number(opts, "speed-min")? {
            None => d.speed_min,
            Some(n) => {
                if !n.is_finite() || n < 0.0 {
                    return Err(options_invalid("speed-min", format!("{n} is negative")));
                }
                n
            }
        };

        let speed_max_bytes = match get_number(opts, "speed-max-bytes")? {
            None => d.speed_max_bytes,
            Some(n) => {
                if !(1.0..=512.0).contains(&n) {
                    return Err(options_invalid(
                        "speed-max-bytes",
                        format!("{n} MB is outside 1..=512"),
                    ));
                }
                (n * 1_000_000.0).round() as u64
            }
        };

        let speed_url = match get_text(opts, "speed-url")? {
            None => d.speed_url,
            Some(s) => {
                if !s.starts_with("https://") {
                    return Err(options_invalid("speed-url", "must be an https:// URL"));
                }
                s
            }
        };

        let scan_timeout_set = opts.get("scan-timeout").is_some();
        let scan_timeout_s = match get_number(opts, "scan-timeout")? {
            None => d.scan_timeout_s,
            Some(n) => whole("scan-timeout", n)?,
        };

        Ok(Self {
            mode,
            port,
            attempts,
            v6,
            v6_samples,
            all_ips,
            sample_per_subnet,
            concurrency,
            timeout_per_probe_ms,
            max_rtt_ms,
            min_rtt_ms,
            max_loss_pct,
            cfcolo,
            speed,
            speed_count,
            speed_time_s,
            speed_min,
            speed_max_bytes,
            speed_url,
            scan_timeout_s,
            scan_timeout_set,
        })
    }
}

fn options_invalid(key: &str, reason: impl Into<String>) -> ScanError {
    ScanError::OptionsInvalid {
        key: key.to_string(),
        reason: reason.into(),
    }
}

fn get_number(opts: &ModuleOptions, key: &str) -> Result<Option<f64>, ScanError> {
    match opts.get(key) {
        None => Ok(None),
        Some(OptionValue::Number(n)) => Ok(Some(*n)),
        Some(_) => Err(options_invalid(key, "expected a number")),
    }
}

fn get_bool(opts: &ModuleOptions, key: &str) -> Result<Option<bool>, ScanError> {
    match opts.get(key) {
        None => Ok(None),
        Some(OptionValue::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(options_invalid(key, "expected true or false")),
    }
}

fn get_text(opts: &ModuleOptions, key: &str) -> Result<Option<String>, ScanError> {
    match opts.get(key) {
        None => Ok(None),
        Some(OptionValue::Text(s)) => Ok(Some(s.clone())),
        Some(_) => Err(options_invalid(key, "expected text")),
    }
}

fn get_list(opts: &ModuleOptions, key: &str) -> Result<Option<Vec<String>>, ScanError> {
    match opts.get(key) {
        None => Ok(None),
        Some(OptionValue::List(v)) => Ok(Some(v.clone())),
        Some(_) => Err(options_invalid(key, "expected a list of strings")),
    }
}

fn whole(key: &str, n: f64) -> Result<u64, ScanError> {
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 {
        return Err(options_invalid(
            key,
            format!("expected a non-negative whole number, got {n}"),
        ));
    }
    Ok(n as u64)
}

fn bounded(key: &str, n: f64, lo: u64, hi: u64) -> Result<u64, ScanError> {
    let v = whole(key, n)?;
    if v < lo || v > hi {
        return Err(options_invalid(key, format!("{v} is outside {lo}..={hi}")));
    }
    Ok(v)
}

pub static OPTIONS_SPEC: OptionsSpec = OptionsSpec {
    entries: &[
        OptionSpec {
            key: "mode",
            kind: OptionKind::Enum {
                variants: &["tcp", "http"],
            },
            default: OptionDefault::ModuleResolved,
            help: "Scan mode: tcp probes the Cloudflare edge directly, http resolves and pins colos.",
        },
        OptionSpec {
            key: "port",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(65_535.0),
            },
            default: OptionDefault::Static(OptionValue::Number(443.0)),
            help: "TCP port probed on each edge IP.",
        },
        OptionSpec {
            key: "attempts",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(4.0),
            },
            default: OptionDefault::Static(OptionValue::Number(4.0)),
            help: "Probes per IP, fixed at 4 for tcp and 1 for http.",
        },
        OptionSpec {
            key: "v6",
            kind: OptionKind::Bool,
            default: OptionDefault::Static(OptionValue::Bool(false)),
            help: "Include IPv6 addresses in the scan.",
        },
        OptionSpec {
            key: "v6-samples",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(65_535.0),
            },
            default: OptionDefault::Static(OptionValue::Number(16.0)),
            help: "Number of IPv6 addresses to sample.",
        },
        OptionSpec {
            key: "all-ips",
            kind: OptionKind::Bool,
            default: OptionDefault::Static(OptionValue::Bool(false)),
            help: "Scan every resolved IP instead of a sample.",
        },
        OptionSpec {
            key: "sample-per-subnet",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(256.0),
            },
            default: OptionDefault::Static(OptionValue::Number(1.0)),
            help: "Addresses sampled per IPv6 /64 subnet.",
        },
        OptionSpec {
            key: "concurrency",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(512.0),
            },
            default: OptionDefault::Static(OptionValue::Number(200.0)),
            help: "Maximum probes in flight, up to 512 for tcp and 200 for http.",
        },
        OptionSpec {
            key: "timeout-per-probe",
            kind: OptionKind::Number {
                min: 200.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(1000.0)),
            help: "Per-probe timeout in milliseconds.",
        },
        OptionSpec {
            key: "max-rtt",
            kind: OptionKind::Number {
                min: 0.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(200.0)),
            help: "Reject IPs whose best RTT exceeds this many milliseconds.",
        },
        OptionSpec {
            key: "min-rtt",
            kind: OptionKind::Number {
                min: 0.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(0.0)),
            help: "Reject IPs faster than this many milliseconds.",
        },
        OptionSpec {
            key: "max-loss",
            kind: OptionKind::Number {
                min: 0.0,
                max: Some(100.0),
            },
            default: OptionDefault::Static(OptionValue::Number(20.0)),
            help: "Reject IPs whose packet loss exceeds this percentage.",
        },
        OptionSpec {
            key: "cfcolo",
            kind: OptionKind::List,
            default: OptionDefault::ModuleResolved,
            help: "Preferred Cloudflare colos for http mode, such as FRA or AMS.",
        },
        OptionSpec {
            key: "speed",
            kind: OptionKind::Bool,
            default: OptionDefault::Static(OptionValue::Bool(false)),
            help: "Run a download speed test on the surviving IPs.",
        },
        OptionSpec {
            key: "speed-count",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(10.0),
            },
            default: OptionDefault::Static(OptionValue::Number(10.0)),
            help: "Number of IPs included in the speed test.",
        },
        OptionSpec {
            key: "speed-time",
            kind: OptionKind::Number {
                min: 1.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(10.0)),
            help: "Seconds each speed test may run.",
        },
        OptionSpec {
            key: "speed-min",
            kind: OptionKind::Number {
                min: 0.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(0.0)),
            help: "Minimum MB/s an IP must reach to stay in the results.",
        },
        OptionSpec {
            key: "speed-max-bytes",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(512.0),
            },
            default: OptionDefault::Static(OptionValue::Number(512.0)),
            help: "Download cap per speed test in megabytes.",
        },
        OptionSpec {
            key: "speed-url",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "HTTPS URL used for the speed test download.",
        },
        OptionSpec {
            key: "scan-timeout",
            kind: OptionKind::Number {
                min: 0.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(180.0)),
            help: "Overall scan budget in seconds.",
        },
    ],
};

pub static COLUMNS: &[ColumnSpec] = &[
    ColumnSpec {
        key: "ip",
        header: "IP",
    },
    ColumnSpec {
        key: "rtt_ms",
        header: "RTT (ms)",
    },
    ColumnSpec {
        key: "loss_pct",
        header: "Loss (%)",
    },
    ColumnSpec {
        key: "attempts",
        header: "Attempts",
    },
    ColumnSpec {
        key: "port",
        header: "Port",
    },
    ColumnSpec {
        key: "colo",
        header: "Colo",
    },
    ColumnSpec {
        key: "speed_mb_per_s",
        header: "Speed (MB/s)",
    },
    ColumnSpec {
        key: "truncated",
        header: "Truncated",
    },
    ColumnSpec {
        key: "status",
        header: "Status",
    },
];

pub fn per_probe_timeout(o: &CdnOptions) -> u64 {
    1000 + u64::from(o.attempts) * o.timeout_per_probe_ms
}
