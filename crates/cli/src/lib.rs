//! Library target of the `cftool` CLI.
//!
//! `main.rs` is a thin shell over these items: exports, configuration and exit
//! codes live here so they can be exercised without a terminal. This is the
//! parity target for the CLI contract in `04-cli.md`.

use std::path::{Path, PathBuf};

use cftool_core::error::ScanError;
use cftool_core::options::{OptionKind, OptionValue};
use cftool_core::output::{OutputError, write_csv, write_json};
use cftool_core::result::{ColumnSpec, FindingRow, ScanSummary};

/// Write `rows` as CSV using `columns`.
pub fn export_csv(
    columns: &[ColumnSpec],
    rows: &[FindingRow],
    out: &mut impl std::io::Write,
) -> Result<(), OutputError> {
    write_csv(columns, rows, out)
}

/// Write `summary` as JSON.
pub fn export_json(
    summary: &ScanSummary,
    out: &mut impl std::io::Write,
) -> Result<(), OutputError> {
    write_json(summary, out)
}

/// Process exit code for a scan that failed.
///
/// Exit 5 is normally derived from `totals.cancelled` in `main`; this mapping is
/// the fallback used when no summary was produced.
pub fn exit_code(error: &ScanError) -> i32 {
    match error {
        ScanError::OptionsInvalid { .. } => 1,
        ScanError::InvalidPlan(_)
        | ScanError::AllowlistViolation(_)
        | ScanError::IdentityMissing => 3,
        ScanError::Network { .. } | ScanError::Busy | ScanError::RegistrationRejected { .. } => 4,
        ScanError::Cancelled | ScanError::BudgetExhausted => 5,
        ScanError::ResultLaneOverflow { .. } | ScanError::Internal(_) => 6,
    }
}

/// On-disk configuration: engine and GUI settings plus per-module options.
///
/// `[modules.<id>]` is a nested table, so module options are a map of maps.
/// Values stay as JSON so a module can read its own keys without the CLI
/// knowing every option.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct CftoolConfig {
    /// `[engine]` settings such as `scan-timeout` and `concurrency`.
    pub engine: std::collections::BTreeMap<String, serde_json::Value>,
    /// `[modules.<id>]` option tables keyed by module id.
    pub modules:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, serde_json::Value>>,
    /// `[gui]` settings such as theme, window and the last module used.
    pub gui: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Path of the config file: `override_path` when given, else the per-user default.
pub fn config_path(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    dirs::config_dir()
        .unwrap_or_default()
        .join("cftool")
        .join("cftool.toml")
}

/// Load the config file, falling back to defaults when it does not exist.
///
/// A missing file is not an error; unreadable or malformed files name the path
/// so the user can fix or remove it.
pub fn load_config(path: Option<&Path>) -> Result<CftoolConfig, String> {
    let path = config_path(path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CftoolConfig::default());
        }
        Err(error) => {
            return Err(format!(
                "cannot read config `{}`: {error}; check the path and its permissions",
                path.display()
            ));
        }
    };
    toml::from_str(&text).map_err(|error| {
        format!(
            "cannot parse config `{}`: {error}; fix the TOML or delete the file to fall back to defaults",
            path.display()
        )
    })
}

/// Commented TOML template written by `cftool config init`.
pub fn config_template() -> &'static str {
    r#"# cftool configuration.
# Every section is optional; missing keys fall back to built-in defaults.

[engine]
# Seconds to wait for a single scan request.
scan-timeout = 30
# Maximum number of in-flight requests.
concurrency = 4

[modules.warp]
enabled = true
threads = 4

[modules.cdn]
enabled = true
provider = "cloudflare"

[gui]
theme = "dark"
# Initial window geometry.
window = "1280x800"
last_module = "warp"
"#
}

/// Parse a raw CLI value for an option of `kind`.
///
/// Values are validated against the kind up front so a bad flag fails before a
/// scan is planned.
pub fn parse_option(kind: &OptionKind, text: &str) -> Result<OptionValue, ScanError> {
    match kind {
        OptionKind::Bool => match text {
            "true" => Ok(OptionValue::Bool(true)),
            "false" => Ok(OptionValue::Bool(false)),
            _ => Err(ScanError::OptionsInvalid {
                key: "value".to_owned(),
                reason: format!("expected a bool (`true` or `false`), got `{text}`"),
            }),
        },
        OptionKind::Number { .. } => {
            text.trim()
                .parse::<f64>()
                .map(OptionValue::Number)
                .map_err(|_| ScanError::OptionsInvalid {
                    key: "value".to_owned(),
                    reason: format!("expected a number, got `{text}`"),
                })
        }
        OptionKind::Enum { variants } => {
            if variants.contains(&text) {
                Ok(OptionValue::Text(text.to_owned()))
            } else {
                Err(ScanError::OptionsInvalid {
                    key: "value".to_owned(),
                    reason: format!("expected one of {}, got `{text}`", variants.join(", ")),
                })
            }
        }
        OptionKind::Text => Ok(OptionValue::Text(text.to_owned())),
        OptionKind::List => Ok(OptionValue::List(
            text.split(',').map(|item| item.trim().to_owned()).collect(),
        )),
    }
}
