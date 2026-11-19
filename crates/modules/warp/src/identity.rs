//! Warp identity storage and WGCF import.
//!
//! The identity is the only credential the Warp flow needs: it contains the
//! WireGuard private key and the peer details used to reach Cloudflare. It is
//! never copied into general configuration, command output, or logs.
//! `identity show` masks the private key at the CLI boundary; this module
//! persists the real value only in the identity file.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use cftool_core::error::ScanError;

/// Failure while importing, reading, or storing a Warp identity.
#[derive(Debug, thiserror::Error)]
pub enum WarpError {
    #[error("identity file unreadable: {0}")]
    Io(String),
    #[error("invalid identity: {0}")]
    Invalid(String),
    #[error("WGCF import field `{field}`: {reason}")]
    Import { field: String, reason: String },
}

impl From<std::io::Error> for WarpError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

/// A Warp client identity.
///
/// `private_key` and `peer_public_key` are standard, padded base64 strings.
/// `endpoint` is `host:port`. `reserved` is the three decoded bytes of the
/// Cloudflare `client_id`, used by tier 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub private_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub reserved: [u8; 3],
}

/// Directory holding cftool's persistent state.
pub fn config_dir() -> Result<PathBuf, ScanError> {
    dirs::config_dir()
        .map(|p| p.join("cftool"))
        .ok_or_else(|| ScanError::Internal("no config directory".into()))
}

/// Path of the stored identity file.
pub fn identity_path() -> Result<PathBuf, ScanError> {
    Ok(config_dir()?.join("identity.json"))
}

/// Load the stored identity.
pub fn load_identity() -> Result<Identity, ScanError> {
    let path = identity_path()?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(ScanError::IdentityMissing),
        Err(e) => return Err(ScanError::Internal(format!("identity file: {e}"))),
    };
    serde_json::from_str(&text)
        .map_err(|e| ScanError::Internal(format!("invalid identity file: {e}")))
}

/// Store the identity as pretty JSON.
///
/// On Unix the file is written with mode `0600`; on Windows the user-profile
/// directory ACL is relied on.
pub fn store_identity(identity: &Identity) -> Result<(), ScanError> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).map_err(|e| ScanError::Internal(format!("config directory: {e}")))?;
    let path = dir.join("identity.json");
    let mut body = serde_json::to_string_pretty(identity)
        .map_err(|e| ScanError::Internal(format!("serialize identity: {e}")))?;
    body.push('\n');
    fs::write(&path, body).map_err(|e| ScanError::Internal(format!("identity file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| ScanError::Internal(format!("identity permissions: {e}")))?;
    }
    Ok(())
}

/// Remove the stored identity. A missing file is success.
pub fn delete_identity() -> Result<(), ScanError> {
    let path = identity_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ScanError::Internal(format!("identity file: {e}"))),
    }
}

/// Parse a WGCF-style WireGuard configuration.
///
/// Keys are matched case-insensitively. Section headers, blank lines, and
/// `#`/`;` comments are ignored. The resulting identity is not written.
pub fn parse_wgcf(text: &str) -> Result<Identity, WarpError> {
    let mut private_key = None;
    let mut public_key = None;
    let mut endpoint = None;
    let mut reserved = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || (line.starts_with('[') && line.ends_with(']'))
        {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = unquote(raw_key).to_ascii_lowercase();
        let value = unquote(raw_value).to_string();
        match key.as_str() {
            "privatekey" => private_key = Some(value),
            "publickey" => public_key = Some(value),
            "endpoint" => endpoint = Some(value),
            "reserved" => reserved = Some(value),
            _ => {}
        }
    }

    let private_key = private_key.ok_or_else(|| missing("PrivateKey"))?;
    if private_key.is_empty() {
        return Err(WarpError::Import {
            field: "PrivateKey".into(),
            reason: "must not be empty".into(),
        });
    }
    decode_b64_32(&private_key, "PrivateKey")?;

    let public_key = public_key.ok_or_else(|| missing("PublicKey"))?;
    if public_key.is_empty() {
        return Err(WarpError::Import {
            field: "PublicKey".into(),
            reason: "must not be empty".into(),
        });
    }
    decode_b64_32(&public_key, "PublicKey")?;

    let endpoint = endpoint.ok_or_else(|| missing("Endpoint"))?;
    if endpoint.is_empty() || !endpoint.contains(':') {
        return Err(WarpError::Import {
            field: "Endpoint".into(),
            reason: "expected host:port".into(),
        });
    }

    let reserved = reserved.ok_or_else(|| missing("Reserved"))?;
    let reserved = parse_reserved(&reserved)?;

    Ok(Identity {
        private_key,
        peer_public_key: public_key,
        endpoint,
        reserved,
    })
}

/// Parse a WGCF file, then store its identity only if parsing succeeds.
pub fn import_wgcf_file(path: impl AsRef<Path>) -> Result<Identity, WarpError> {
    let text = fs::read_to_string(path.as_ref())?;
    let identity = parse_wgcf(&text)?;
    store_identity(&identity).map_err(|e| WarpError::Invalid(e.to_string()))?;
    Ok(identity)
}

/// Deterministic identity for mocked tests.
#[cfg(feature = "mock")]
pub fn scripted_identity() -> Identity {
    Identity {
        private_key: STANDARD.encode([7u8; 32]),
        peer_public_key: STANDARD.encode([9u8; 32]),
        endpoint: "162.159.192.1:2408".to_string(),
        reserved: [0, 0, 0],
    }
}

/// Decode standard, padded base64 that must contain exactly 32 bytes.
pub fn decode_b64_32(value: &str, field: &str) -> Result<[u8; 32], WarpError> {
    let bytes = STANDARD.decode(value).map_err(|e| WarpError::Import {
        field: field.to_string(),
        reason: format!("not standard base64: {e}"),
    })?;
    let len = bytes.len();
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| WarpError::Import {
        field: field.to_string(),
        reason: format!("expected 32 bytes, got {len}"),
    })?;
    Ok(array)
}

fn missing(field: &str) -> WarpError {
    WarpError::Import {
        field: field.to_string(),
        reason: "missing".to_string(),
    }
}

fn unquote(raw: &str) -> &str {
    let value = raw.trim();
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].trim();
        }
    }
    value
}

fn parse_reserved(value: &str) -> Result<[u8; 3], WarpError> {
    let malformed = |reason: String| WarpError::Import {
        field: "Reserved".to_string(),
        reason,
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(malformed("must not be empty".to_string()));
    }

    if value.contains(',') {
        let mut parts = value.split(',').map(str::trim);
        let mut bytes = [0u8; 3];
        for slot in &mut bytes {
            let part = parts
                .next()
                .ok_or_else(|| malformed("expected three decimal bytes".to_string()))?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed(format!("`{part}` is not a decimal byte")));
            }
            *slot = part
                .parse::<u8>()
                .map_err(|_| malformed(format!("`{part}` is outside 0..=255")))?;
        }
        if parts.next().is_some() {
            return Err(malformed("expected three decimal bytes".to_string()));
        }
        return Ok(bytes);
    }

    if let Ok(bytes) = STANDARD.decode(value)
        && bytes.len() == 3
    {
        return Ok([bytes[0], bytes[1], bytes[2]]);
    }

    let raw = value.as_bytes();
    if raw.len() == 3 {
        return Ok([raw[0], raw[1], raw[2]]);
    }

    Err(malformed(
        "expected three comma-separated decimal bytes or three literal bytes".to_string(),
    ))
}
