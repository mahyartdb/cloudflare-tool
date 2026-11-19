//! cftool-core configuration.
//!
//! Configuration is grouped into three tables: `[engine]`, `[modules.<id>]`, and
//! `[gui]`. Validation is strict wherever the schema is known: an unknown key in
//! `[engine]`, in `[gui]`, or in a registered module is an error. A module id that
//! matches no registered module is only a warning, so a stale section cannot block
//! a run. `[gui]` has no CLI effect (the desktop shell writes it), and the identity
//! private key never lives in this config.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Keys accepted in `[engine]`.
pub const ENGINE_KEYS: &[&str] = &["concurrency", "output_dir", "scan_timeout"];

/// Keys accepted in `[gui]`.
pub const GUI_KEYS: &[&str] = &["theme", "window", "last_module"];

/// Raw values of the `[engine]`, `[modules.<id>]`, and `[gui]` tables.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub engine: BTreeMap<String, Value>,
    pub modules: BTreeMap<String, BTreeMap<String, Value>>,
    pub gui: BTreeMap<String, Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown key `{key}` in section `{section}`")]
    UnknownKey { key: String, section: String },
}

/// Validates `config` against the known schema and returns warnings for module
/// sections that were ignored.
///
/// `registered` holds the module ids the build knows about; `module_keys` holds
/// the keys each of those modules accepts. Unknown keys are reported for
/// `[engine]` first, then `[gui]`, then modules in id order.
pub fn validate_config(
    config: &Config,
    registered: &BTreeSet<String>,
    module_keys: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<String>, ConfigError> {
    for key in config.engine.keys() {
        if !ENGINE_KEYS.contains(&key.as_str()) {
            return Err(ConfigError::UnknownKey {
                key: key.clone(),
                section: "engine".to_owned(),
            });
        }
    }

    for key in config.gui.keys() {
        if !GUI_KEYS.contains(&key.as_str()) {
            return Err(ConfigError::UnknownKey {
                key: key.clone(),
                section: "gui".to_owned(),
            });
        }
    }

    let mut warnings = Vec::new();
    for (id, table) in &config.modules {
        if !registered.contains(id) {
            warnings.push(format!("ignoring stale module section `{id}`"));
            continue;
        }

        let known = module_keys.get(id);
        for key in table.keys() {
            if !known.is_some_and(|known| known.contains(key)) {
                return Err(ConfigError::UnknownKey {
                    key: key.clone(),
                    section: format!("modules.{id}"),
                });
            }
        }
    }

    Ok(warnings)
}
