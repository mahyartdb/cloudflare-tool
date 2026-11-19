//! WARP scan options: typed access, the declarative spec, and report metadata.

use cftool_core::error::ScanError;
use cftool_core::options::{
    DialogSpec, ModuleOptions, OptionDefault, OptionKind, OptionSpec, OptionValue, OptionsSpec,
    SubcommandSpec,
};
use cftool_core::result::ColumnSpec;

/// Port a pinned scan probes.
pub const PINNED_PORT: u16 = 2408;

/// Ports probed in standard mode.
pub const PORTS_STANDARD: [u16; 4] = [500, 1701, 2408, 4500];

/// Ports probed in full mode.
pub const PORTS_FULL: [u16; 54] = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
    968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506,
    3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

/// Address pool a scan draws endpoints from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PoolMode {
    /// Built-in Cloudflare endpoints.
    #[default]
    Default,
    /// Classic WARP endpoint set.
    Classic,
    /// Ranges supplied via `cidr`.
    Custom,
}

/// Which UDP ports a scan probes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PortMode {
    /// Only [`PINNED_PORT`].
    #[default]
    Pinned,
    /// [`PORTS_STANDARD`].
    Standard,
    /// [`PORTS_FULL`].
    Full,
}

/// Amount of masking noise sent before each probe.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NoisePreset {
    /// No masking noise.
    Off,
    /// Up to 5 datagrams of 5 ms.
    #[default]
    Light,
    /// Up to 50 datagrams of 150 ms.
    Heavy,
}

/// Datagrams of masking noise sent per probe.
///
/// Light sends at most 5 datagrams of 5 ms each, heavy at most 50 of 150 ms. The warm-up
/// datagram is always sent and charged separately, so a preset only adds to its cost.
pub fn noise_datagrams(preset: NoisePreset) -> u8 {
    match preset {
        NoisePreset::Off => 0,
        NoisePreset::Light => 5,
        NoisePreset::Heavy => 50,
    }
}

/// Milliseconds of delay the masking noise adds to a probe.
pub fn noise_overhead_ms(preset: NoisePreset) -> u64 {
    match preset {
        NoisePreset::Off => 0,
        NoisePreset::Light => 25,
        NoisePreset::Heavy => 7_500,
    }
}

/// WARP scan options after validation.
#[derive(Clone, Debug, Default)]
pub struct WarpOptions {
    /// Address pool to scan.
    pub pool: PoolMode,
    /// Explicit CIDR ranges; a non-empty list forces [`PoolMode::Custom`].
    pub cidr: Vec<String>,
    /// Addresses sampled per /24 subnet.
    pub sample_per_subnet: u16,
    /// IPv6 endpoints sampled when `enable_v6` is set.
    pub v6_samples: u16,
    /// Whether to probe IPv6 endpoints.
    pub enable_v6: bool,
    /// Which ports to probe.
    pub port_mode: PortMode,
    /// Per-probe timeout in milliseconds.
    pub timeout_per_probe_ms: u64,
    /// Maximum probes in flight.
    pub concurrency: usize,
    /// Endpoints slower than this are dropped.
    pub max_rtt_ms: u64,
    /// Number of endpoints kept.
    pub results: usize,
    /// Masking noise preset.
    pub noise: NoisePreset,
    /// Overall scan budget in seconds.
    pub scan_timeout_secs: u64,
}

impl WarpOptions {
    /// Reads the option set, applying module defaults and rejecting wrongly typed or
    /// out-of-range values.
    pub fn try_from_options(opts: &ModuleOptions) -> Result<Self, ScanError> {
        let mut pool = match get_text(opts, "pool", "default")?.as_str() {
            "default" => PoolMode::Default,
            "classic" => PoolMode::Classic,
            "custom" => PoolMode::Custom,
            other => {
                return Err(invalid(
                    "pool",
                    format!("unknown pool {other:?}; expected default, classic or custom"),
                ));
            }
        };
        let cidr = get_list(opts, "cidr")?;
        if !cidr.is_empty() {
            pool = PoolMode::Custom;
        } else if pool == PoolMode::Custom {
            return Err(invalid(
                "cidr",
                "pool custom requires at least one CIDR: set cidr or choose default/classic",
            ));
        }

        let sample_per_subnet = get_whole(opts, "sample-per-subnet", 256, 1, Some(256))? as u16;
        let v6_samples = get_whole(opts, "v6-samples", 256, 1, Some(65_535))? as u16;
        let enable_v6 = get_bool(opts, "enable-v6", false)?;
        let port_mode = match get_text(opts, "port-mode", "pinned")?.as_str() {
            "pinned" => PortMode::Pinned,
            "standard" => PortMode::Standard,
            "full" => PortMode::Full,
            other => {
                return Err(invalid(
                    "port-mode",
                    format!("unknown port mode {other:?}; expected pinned, standard or full"),
                ));
            }
        };
        let timeout_per_probe_ms = get_whole(opts, "timeout-per-probe", 1_500, 200, Some(5_000))?;
        let concurrency = get_whole(opts, "concurrency", 512, 1, Some(4_096))? as usize;
        let max_rtt_ms = get_whole(opts, "max-rtt", 400, 1, None)?;
        let results = get_whole(opts, "results", 8, 1, None)? as usize;
        let noise = match get_text(opts, "noise", "light")?.as_str() {
            "off" => NoisePreset::Off,
            "light" => NoisePreset::Light,
            "heavy" => NoisePreset::Heavy,
            other => {
                return Err(invalid(
                    "noise",
                    format!("unknown noise preset {other:?}; expected off, light or heavy"),
                ));
            }
        };
        let scan_timeout_secs = get_whole(opts, "scan-timeout", 90, 1, None)?;

        Ok(Self {
            pool,
            cidr,
            sample_per_subnet,
            v6_samples,
            enable_v6,
            port_mode,
            timeout_per_probe_ms,
            concurrency,
            max_rtt_ms,
            results,
            noise,
            scan_timeout_secs,
        })
    }
}

fn invalid(key: &'static str, reason: impl Into<String>) -> ScanError {
    ScanError::OptionsInvalid {
        key: key.to_string(),
        reason: reason.into(),
    }
}

fn get_bool(opts: &ModuleOptions, key: &'static str, default: bool) -> Result<bool, ScanError> {
    match opts.get(key) {
        None => Ok(default),
        Some(OptionValue::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid(key, "expected true or false")),
    }
}

fn get_number(opts: &ModuleOptions, key: &'static str, default: f64) -> Result<f64, ScanError> {
    match opts.get(key) {
        None => Ok(default),
        Some(OptionValue::Number(value)) => Ok(*value),
        Some(_) => Err(invalid(key, "expected a number")),
    }
}

fn get_text(
    opts: &ModuleOptions,
    key: &'static str,
    default: &'static str,
) -> Result<String, ScanError> {
    match opts.get(key) {
        None => Ok(default.to_string()),
        Some(OptionValue::Text(value)) => Ok(value.to_string()),
        Some(_) => Err(invalid(key, "expected text")),
    }
}

fn get_list(opts: &ModuleOptions, key: &'static str) -> Result<Vec<String>, ScanError> {
    match opts.get(key) {
        None => Ok(Vec::new()),
        Some(OptionValue::List(value)) => Ok(value.clone()),
        Some(_) => Err(invalid(key, "expected a list of strings")),
    }
}

fn whole_number(key: &'static str, value: f64) -> Result<u64, ScanError> {
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(invalid(
            key,
            format!("expected a whole number, got {value}"),
        ));
    }
    if value < 0.0 || value >= u64::MAX as f64 {
        return Err(invalid(
            key,
            format!("{value} is outside the supported range"),
        ));
    }
    Ok(value as u64)
}

fn get_whole(
    opts: &ModuleOptions,
    key: &'static str,
    default: u64,
    min: u64,
    max: Option<u64>,
) -> Result<u64, ScanError> {
    let value = whole_number(key, get_number(opts, key, default as f64)?)?;
    if value < min {
        return Err(invalid(key, format!("must be at least {min}, got {value}")));
    }
    if let Some(max) = max
        && value > max
    {
        return Err(invalid(key, format!("must be at most {max}, got {value}")));
    }
    Ok(value)
}

/// Options a WARP scan accepts.
pub static OPTIONS_SPEC: OptionsSpec = OptionsSpec {
    entries: &[
        OptionSpec {
            key: "pool",
            kind: OptionKind::Enum {
                variants: &["default", "classic", "custom"],
            },
            default: OptionDefault::ModuleResolved,
            help: "Pool to scan; a non-empty cidr selects custom.",
        },
        OptionSpec {
            key: "cidr",
            kind: OptionKind::List,
            default: OptionDefault::ModuleResolved,
            help: "Explicit CIDR ranges to scan instead of the built-in pool.",
        },
        OptionSpec {
            key: "sample-per-subnet",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(256.0),
            },
            default: OptionDefault::Static(OptionValue::Number(256.0)),
            help: "Addresses sampled per /24 subnet (1-256).",
        },
        OptionSpec {
            key: "v6-samples",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(65_535.0),
            },
            default: OptionDefault::Static(OptionValue::Number(256.0)),
            help: "IPv6 endpoints sampled (1-65535).",
        },
        OptionSpec {
            key: "enable-v6",
            kind: OptionKind::Bool,
            default: OptionDefault::Static(OptionValue::Bool(false)),
            help: "Also probe IPv6 endpoints.",
        },
        OptionSpec {
            key: "port-mode",
            kind: OptionKind::Enum {
                variants: &["pinned", "standard", "full"],
            },
            default: OptionDefault::ModuleResolved,
            help: "UDP ports probed per endpoint: pinned, standard, or full.",
        },
        OptionSpec {
            key: "timeout-per-probe",
            kind: OptionKind::Number {
                min: 200.0,
                max: Some(5_000.0),
            },
            default: OptionDefault::Static(OptionValue::Number(1_500.0)),
            help: "Per-probe timeout in milliseconds (200-5000).",
        },
        OptionSpec {
            key: "concurrency",
            kind: OptionKind::Number {
                min: 1.0,
                max: Some(4_096.0),
            },
            default: OptionDefault::Static(OptionValue::Number(512.0)),
            help: "Maximum probes in flight (1-4096).",
        },
        OptionSpec {
            key: "max-rtt",
            kind: OptionKind::Number {
                min: 1.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(400.0)),
            help: "Drop endpoints slower than this many milliseconds.",
        },
        OptionSpec {
            key: "results",
            kind: OptionKind::Number {
                min: 1.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(8.0)),
            help: "Number of endpoints to report.",
        },
        OptionSpec {
            key: "noise",
            kind: OptionKind::Enum {
                variants: &["off", "light", "heavy"],
            },
            default: OptionDefault::ModuleResolved,
            help: "Masking noise per probe: off, light, or heavy.",
        },
        OptionSpec {
            key: "scan-timeout",
            kind: OptionKind::Number {
                min: 1.0,
                max: None,
            },
            default: OptionDefault::Static(OptionValue::Number(90.0)),
            help: "Overall scan budget in seconds.",
        },
    ],
};

/// Columns a WARP scan reports.
pub static COLUMNS: &[ColumnSpec] = &[
    ColumnSpec {
        key: "endpoint",
        header: "Endpoint",
    },
    ColumnSpec {
        key: "rtt_ms",
        header: "RTT (ms)",
    },
    ColumnSpec {
        key: "status",
        header: "Status",
    },
    ColumnSpec {
        key: "colo",
        header: "Colo",
    },
    ColumnSpec {
        key: "exit_country",
        header: "Exit country",
    },
    ColumnSpec {
        key: "noise_preset",
        header: "Noise preset",
    },
];

/// `warp identity` subcommands.
pub static IDENTITY_SUBCOMMANDS: &[SubcommandSpec] = &[
    SubcommandSpec {
        name: "identity register",
        description: "Register a new WARP identity",
        args: &[OptionSpec {
            key: "force",
            kind: OptionKind::Bool,
            default: OptionDefault::Static(OptionValue::Bool(false)),
            help: "Re-register even if an identity exists",
        }],
    },
    SubcommandSpec {
        name: "identity import",
        description: "Import a WGCF config",
        args: &[OptionSpec {
            key: "file",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "Path to the WGCF config file",
        }],
    },
    SubcommandSpec {
        name: "identity show",
        description: "Show the stored identity (private key masked)",
        args: &[],
    },
];

/// The identity dialog; the GUI renders it from these field specs.
pub static IDENTITY_DIALOG: DialogSpec = DialogSpec {
    id: "identity",
    title: "WARP identity",
    fields: &[
        OptionSpec {
            key: "private_key",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "WARP private key.",
        },
        OptionSpec {
            key: "peer_public_key",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "Peer public key.",
        },
        OptionSpec {
            key: "endpoint",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "Endpoint host and port.",
        },
        OptionSpec {
            key: "reserved",
            kind: OptionKind::Text,
            default: OptionDefault::ModuleResolved,
            help: "Reserved bytes, comma separated.",
        },
    ],
    confirm_command: "identity import",
};
