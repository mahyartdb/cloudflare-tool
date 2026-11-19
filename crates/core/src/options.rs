//! Declarative option schema shared by every cftool frontend.
//!
//! A module describes its options once here; the CLI, TUI and GUI render that
//! description without knowing anything module-specific.
//!
//! Keys whose default is [`OptionDefault::ModuleResolved`] are absent from
//! [`ModuleOptions`] unless the user has set them: the value does not exist
//! until the module resolves it (config file, API response, prompt). A
//! frontend must not guess a missing key. It renders the option as unset and
//! asks the module to resolve it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A value a user can assign to an option.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OptionValue {
    Bool(bool),
    Number(f64),
    Text(String),
    List(Vec<String>),
}

/// One module instance's option values, keyed by [`OptionSpec::key`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModuleOptions {
    pub values: BTreeMap<String, OptionValue>,
}

impl ModuleOptions {
    pub fn get(&self, key: &str) -> Option<&OptionValue> {
        self.values.get(key)
    }

    pub fn set(&mut self, key: impl Into<String>, value: OptionValue) {
        self.values.insert(key.into(), value);
    }

    /// Build options seeded with every static default in `spec`.
    ///
    /// Static-default keys are always present; [`OptionDefault::ModuleResolved`]
    /// keys stay absent until the user sets them.
    pub fn with_static_defaults(spec: &OptionsSpec) -> Self {
        let mut options = Self::default();
        for entry in spec.entries {
            if let OptionDefault::Static(value) = &entry.default {
                options.set(entry.key, value.clone());
            }
        }
        options
    }
}

/// Where an option's initial value comes from.
#[derive(Clone, Debug, PartialEq)]
pub enum OptionDefault {
    /// Known up front; always present in [`ModuleOptions`].
    Static(OptionValue),
    /// Produced by the module at resolve time; absent until the user sets it.
    ModuleResolved,
}

/// The values an option accepts, used for validation and widget choice.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OptionKind {
    Bool,
    /// `max: None` means no upper bound.
    Number {
        min: f64,
        max: Option<f64>,
    },
    Enum {
        variants: &'static [&'static str],
    },
    Text,
    List,
}

// Not Copy: OptionDefault::Static owns an OptionValue.
#[derive(Clone, Debug)]
pub struct OptionSpec {
    pub key: &'static str,
    pub kind: OptionKind,
    pub default: OptionDefault,
    pub help: &'static str,
}

/// The full option set a module exposes.
#[derive(Clone, Copy, Debug)]
pub struct OptionsSpec {
    pub entries: &'static [OptionSpec],
}

/// A CLI subcommand a module contributes.
#[derive(Clone, Copy, Debug)]
pub struct SubcommandSpec {
    /// Command path, e.g. `"identity import"`.
    pub name: &'static str,
    pub description: &'static str,
    pub args: &'static [OptionSpec],
}

/// A dialog a module can open, and the command that confirms it.
#[derive(Clone, Copy, Debug)]
pub struct DialogSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub fields: &'static [OptionSpec],
    pub confirm_command: &'static str,
}

/// What an action does when invoked.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ActionKind {
    OpenDialog { dialog: &'static str },
}

/// A frontend-agnostic action (menu item, button, palette entry).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActionSpec {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: ActionKind,
}
