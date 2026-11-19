//! Shared result writer.
//!
//! The CLI and the GUI both call this module, so the bytes written for a scan
//! are identical whichever frontend produced them.

use crate::result::{CellValue, ColumnSpec, FindingRow, ScanSummary};

/// Failure while writing scan output.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// The underlying writer failed.
    #[error("output write failed: {0}")]
    Io(#[from] std::io::Error),
    /// The summary could not be serialized.
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Write `rows` as CSV with `columns` as both header and cell order.
///
/// Text is written verbatim and unquoted; numbers keep at most three decimals
/// with trailing zeros trimmed; booleans render as `true`/`false`; null or
/// absent values are empty. Lines always end with `\n`, never `\r\n`.
pub fn write_csv(
    columns: &[ColumnSpec],
    rows: &[FindingRow],
    out: &mut impl std::io::Write,
) -> Result<(), OutputError> {
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        out.write_all(column.header.as_bytes())?;
    }
    out.write_all(b"\n")?;

    for row in rows {
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                out.write_all(b",")?;
            }
            if let Some(value) = cell_for(row, column.key) {
                write_cell(value, out)?;
            }
        }
        out.write_all(b"\n")?;
    }

    Ok(())
}

/// Write `summary` as a single JSON document followed by a newline.
pub fn write_json(summary: &ScanSummary, out: &mut impl std::io::Write) -> Result<(), OutputError> {
    serde_json::to_writer(&mut *out, summary)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn cell_for<'a>(row: &'a FindingRow, key: &str) -> Option<&'a CellValue> {
    row.columns
        .iter()
        .find(|(column_key, _)| column_key.as_str() == key)
        .map(|(_, value)| value)
}

fn write_cell(value: &CellValue, out: &mut impl std::io::Write) -> Result<(), OutputError> {
    match value {
        CellValue::Text(text) => out.write_all(text.as_bytes())?,
        CellValue::Bool(flag) => {
            let rendered = if *flag { "true" } else { "false" };
            out.write_all(rendered.as_bytes())?;
        }
        CellValue::Number(number) => out.write_all(render_number(number).as_bytes())?,
        CellValue::Null => {}
    }
    Ok(())
}

fn render_number(number: impl std::fmt::Display) -> String {
    let mut rendered = format!("{number:.3}");
    if rendered.contains('.') {
        while rendered.ends_with('0') {
            rendered.pop();
        }
        if rendered.ends_with('.') {
            rendered.pop();
        }
    }
    rendered
}
