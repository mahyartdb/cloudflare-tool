//! Scan result model.
//!
//! Serialized scan output never carries dead counts — dead is core-internal
//! bookkeeping and stays out of the wire format. `wall_time` is emitted as an
//! integer number of milliseconds.

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use std::fmt;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Clone, Debug, PartialEq)]
pub enum CellValue {
    Text(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl Serialize for CellValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CellValue::Text(text) => serializer.serialize_str(text),
            CellValue::Number(number) => serializer.serialize_f64(*number),
            CellValue::Bool(value) => serializer.serialize_bool(*value),
            CellValue::Null => serializer.serialize_unit(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnSpec {
    pub key: &'static str,
    pub header: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct FindingRow {
    pub columns: Vec<(String, CellValue)>,
}

impl Serialize for FindingRow {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.columns.len()))?;
        for (key, value) in &self.columns {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

pub trait ModuleFinding: Send {
    fn sort_rank(&self) -> Option<u64>;
    fn to_row(&self) -> FindingRow;
    fn is_filtered(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ScanTotals {
    pub probed: usize,
    pub alive: usize,
    pub filtered: usize,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct ModuleId(pub String);

impl ModuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for ModuleId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for ModuleId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct GenerationId(pub u64);

pub struct ScanSummary {
    pub module_id: ModuleId,
    pub started_at: OffsetDateTime,
    pub wall_time: Duration,
    pub totals: ScanTotals,
    pub findings: Vec<Box<dyn ModuleFinding>>,
}

impl std::fmt::Debug for ScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanSummary")
            .field("module_id", &self.module_id)
            .field("started_at", &self.started_at)
            .field("wall_time", &self.wall_time)
            .field("totals", &self.totals)
            .field("findings", &self.findings.len())
            .finish()
    }
}

impl Serialize for ScanSummary {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let started_at = self
            .started_at
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;

        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("module", &self.module_id)?;
        map.serialize_entry("started_at", &started_at)?;
        map.serialize_entry("wall_time", &(self.wall_time.as_millis() as u64))?;
        map.serialize_entry("totals", &self.totals)?;
        map.serialize_entry("findings", &FindingsProjection(&self.findings[..]))?;
        map.end()
    }
}

struct FindingsProjection<'a>(&'a [Box<dyn ModuleFinding>]);

impl Serialize for FindingsProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for finding in self.0 {
            // Project through the trait object: never serialize dyn ModuleFinding.
            seq.serialize_element(&finding.to_row())?;
        }
        seq.end()
    }
}
