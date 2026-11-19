//! WARP registration transport (spec `02-warp-scan.md`, §5).
//!
//! Ethical bounds: exactly one registration per explicit user action — this
//! module never retries or loops on its own, and the caller decides when to run
//! it. The keypair is freshly generated for this device and is a legitimate
//! WireGuard identity, not a shared or harvested value. Registering creates a
//! Cloudflare WARP account; the user must accept Cloudflare's Terms of Service
//! before [`register`] is called.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use boringtun::x25519::{PublicKey, StaticSecret};
use cftool_core::error::ScanError;
use rand_core_06::OsRng;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::identity::{Identity, load_identity, store_identity};

/// Build number advertised by the WARP client. One literal feeds every
/// versioned constant below so a bump cannot desync them.
macro_rules! build_constants {
    ($build:literal) => {
        pub const BUILD_NUMBER: &str = $build;

        /// Registration API version, e.g. `v0a5641`.
        pub const API_VERSION: &str = concat!("v0a", $build);

        /// User-Agent sent with registration requests.
        pub const USER_AGENT: &str = concat!("1.1.1.1/6.38.9-", $build, " (Android 16.0.0)");

        /// CF-Client-Version sent with registration requests.
        pub const CLIENT_VERSION: &str = concat!("a-6.38.9-", $build);
    };
}

build_constants!("5641");

#[derive(Serialize)]
struct RegisterBody {
    fcm_token: String,
    install_id: String,
    key: String,
    locale: String,
    model: String,
    tos: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
}

#[derive(Deserialize)]
struct Resp {
    config: RespConfig,
}

#[derive(Deserialize)]
struct RespConfig {
    peers: Vec<RespPeer>,
    client_id: String,
}

#[derive(Deserialize)]
struct RespPeer {
    public_key: String,
    endpoint: String,
}

/// Human-readable cause for a refused registration, keyed by HTTP status.
///
/// Pure: mapping only, no I/O, so tests can assert each string directly.
pub fn registration_hint(status: u16) -> &'static str {
    match status {
        404 => "Cloudflare may have changed the API version; check the build constant",
        403 => {
            "likely fingerprint/policy rejection (TLS profile); import a WGCF identity as a workaround"
        }
        429 => "rate limited; try again later (no automatic retry)",
        _ => "registration refused",
    }
}

/// Maps a non-2xx registration response to [`ScanError::RegistrationRejected`].
///
/// Pure; the human-readable cause is looked up separately through
/// [`registration_hint`] so callers can print one without rediscovering it.
pub fn registration_rejected(status: u16, api_version: &str) -> ScanError {
    ScanError::RegistrationRejected {
        status,
        api_version: api_version.to_string(),
    }
}

/// Builds the registration HTTP client: HTTP/1.1 only, TLS 1.2, presenting the
/// two AES-256-GCM ECDHE suites the WARP client uses.
pub fn make_client() -> Result<reqwest::Client, ScanError> {
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        ..rustls::crypto::ring::default_provider()
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ScanError::Internal(format!("build TLS config: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    reqwest::Client::builder()
        .http1_only()
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .tls_version_max(reqwest::tls::Version::TLS_1_2)
        .tls_backend_preconfigured(tls)
        .build()
        .map_err(|e| ScanError::Internal(format!("build HTTP client: {e}")))
}

/// Registers a fresh WARP identity, or returns the stored one when `force` is
/// false and it exists (no network in that case).
///
/// Cancellation is observed before the request and again once a response
/// arrives; a cancellation racing the request drops it. One request per call,
/// no retries: 404/403/429 map to [`ScanError::RegistrationRejected`] and the
/// caller decides what to tell the user.
pub async fn register(force: bool, cancel: &CancellationToken) -> Result<Identity, ScanError> {
    if cancel.is_cancelled() {
        return Err(ScanError::Cancelled);
    }

    if !force && let Ok(identity) = load_identity() {
        return Ok(identity);
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let key = STANDARD.encode(PublicKey::from(&secret).as_bytes());
    let tos = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| ScanError::Internal(format!("format registration timestamp: {e}")))?;

    let body = RegisterBody {
        fcm_token: String::new(),
        install_id: String::new(),
        key,
        locale: "en_US".into(),
        model: "cftool".into(),
        tos,
        serial_number: String::new(),
        os_version: "16.0.0".into(),
        key_type: "curve25519".into(),
        tunnel_type: "wireguard".into(),
    };

    let client = make_client()?;
    let url = format!("https://api.cloudflareclient.com/{}/reg", API_VERSION);

    let request = client
        .post(url.as_str())
        .header("User-Agent", USER_AGENT)
        .header("CF-Client-Version", CLIENT_VERSION)
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Connection", "Keep-Alive")
        .json(&body)
        .send();

    let resp = tokio::select! {
        _ = cancel.cancelled() => return Err(ScanError::Cancelled),
        res = request => res.map_err(|e| ScanError::Network {
            target: url.clone(),
            cause: e.to_string(),
        })?,
    };

    if cancel.is_cancelled() {
        return Err(ScanError::Cancelled);
    }

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(registration_rejected(status, API_VERSION));
    }

    let parsed: Resp = resp
        .json()
        .await
        .map_err(|e| ScanError::Internal(format!("parse registration response: {e}")))?;

    let peer =
        parsed.config.peers.first().ok_or_else(|| {
            ScanError::Internal("registration response contained no peers".into())
        })?;

    let client_id = STANDARD
        .decode(&parsed.config.client_id)
        .map_err(|e| ScanError::Internal(format!("decode registration client_id: {e}")))?;
    if client_id.is_empty() {
        return Err(ScanError::Internal(
            "registration response contained an empty client_id".into(),
        ));
    }

    let mut reserved = [0u8; 3];
    for (slot, byte) in reserved.iter_mut().zip(&client_id) {
        *slot = *byte;
    }

    let identity = Identity {
        private_key: STANDARD.encode(secret.to_bytes()),
        peer_public_key: peer.public_key.clone(),
        endpoint: peer.endpoint.clone(),
        reserved,
    };
    store_identity(&identity)?;

    Ok(identity)
}

/// Returns the identity scripted by the `mock` feature. No network, no clock,
/// no storage: scan and UI tests get deterministic peer data.
#[cfg(feature = "mock")]
pub async fn register_mock() -> Result<Identity, ScanError> {
    Ok(crate::identity::scripted_identity())
}
