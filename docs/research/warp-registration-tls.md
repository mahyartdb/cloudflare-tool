# WARP registration over TLS, from Rust

Scope: what it takes for `cftool` to get a 2xx from `POST https://api.cloudflareclient.com/v0a5641/reg`
on Windows. Evidence gathered 2026-11-16 from crates.io, docs.rs and upstream source. No live
registration was attempted; every "works today" claim below is marked accordingly.

## 1. The profile wgcf actually sends

[`cloudflare/api.go` @ master](https://github.com/ViRb3/wgcf/blob/master/cloudflare/api.go), commit `803310a` ("fix: update api to v0a5641 and pin tls fingerprint", 2026-09-18):

- TLS 1.2 pinned as both min and max; ClientHello hand-built with uTLS `HelloCustom` (uTLS 1.8.2).
- Cipher suites: exactly `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` and
  `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC02C, 0xC030).
- ALPN `http/1.1`; `ForceAttemptHTTP2: false`.
- Extensions, in order: SNI, extended_master_secret, renegotiation_info (empty),
  supported_groups {X25519, P-256, P-384}, ec_point_formats {0}, session_ticket, ALPN,
  status_request, signature_algorithms (9 entries), padding (`BoringPaddingStyle`).
- Session ID cleared on a fresh connection (Conscrypt behaviour), random 32 bytes only for
  ticket resumption. Compression: null only.
- HTTP side: `Connection: Keep-Alive`, `Accept` removed, `Content-Type: application/json; charset=UTF-8`.

The app hello is *reproducible in shape*; nothing proves the server demands byte equality — see §2.

## 2. Does a stock Rust TLS stack pass?

Chronology, all from primary sources:

- wgcf ≤ 2.2.32 used stock Go `crypto/tls` with only TLS 1.2 pinned and `okhttp/3.12.1` headers.  Its own comment: *"Match app's TLS config or API will reject us with code 403 error 1020"*
  ([v2.2.32 api.go](https://github.com/ViRb3/wgcf/blob/v2.2.32/cloudflare/api.go)). It worked for years.
- [badafans/warp-reg](https://github.com/badafans/warp-reg) (Apr 2023) is the same recipe in Go —
  stock `crypto/tls`, TLS 1.2 pinned, okhttp UA — and worked.
  ⇒ A hello that is *not* Conscrypt has passed this endpoint. The check is not an exact-match allowlist.
- 2026-09: wgcf 2.2.32 began returning **429** on macOS, Debian and Windows
  ([#626](https://github.com/ViRb3/wgcf/issues/626), 12 comments). The author: "looks like something
  in the TLS fingerprint changed again". 2.3.0 then changed four things at once — API version
  `v0a1922`→`v0a5641`, User-Agent, request headers, and TLS (stock Go → uTLS) — and reported 40/40
  success. **The cause was never isolated**; the version bump alone is a plausible explanation.
- warp-plus (Go) uses uTLS 1.7.3 with its own hello (TLS 1.2 pinned, GREASE, 9 suites, ALPN
  `http/1.1`, a 1200-byte SNI-curve padding trick) and falls back to stock Go TLS 1.3, then
  `HelloChrome_Auto` ([warp/tls.go](https://github.com/bepass-org/warp-plus/blob/master/warp/tls.go),
  [warp/api.go](https://github.com/bepass-org/warp-plus/blob/master/warp/api.go)). Hedged, not proof.
- Rust precedent: **no WARP-registration crate exists** — `wgcf-rs`, `cloudflare-warp`, `warp-plus`
  are 404 on crates.io; `warp-rs` is image resampling; `bypass` is thread-local variables.
  - [usque-rs](https://github.com/Diniboy1123/usque-rs) registers with `reqwest` + `rustls-tls`,
    API `v0a4471`, UA `WARP for Android`, last push 2026-03 — it predates the September change.
  - [Aether](https://github.com/CluvexStudio/Aether) (2.4k★, pushed 2026-11-03) sends its WARP API
    calls through a hand-built BoringSSL client with a Chrome fingerprint
    ([aether/src/https.rs](https://github.com/CluvexStudio/Aether/blob/main/aether/src/https.rs),
    [aether/src/tls.rs](https://github.com/CluvexStudio/Aether/blob/main/aether/src/tls.rs)), not
    `reqwest`. But the same client serves its DPI-resistant DoH, and no comment says the API rejects
    rustls — the motive is censorship resistance, not a documented 403.

**Verdict: UNVERIFIED.** Two readings survive: (i) Cloudflare allowlists known JA3 families
(Conscrypt/Chrome/OkHttp) and rustls's distinctive hello fails; (ii) the September failure was
version/header rate-limiting and a stock hello still passes. They are one HTTP request apart.

## 3. Crates that can shape a ClientHello

| Crate | Version (date) | Backend | TLS 1.2-only | Cipher-suite list | ALPN list | Ext. order / GREASE | Windows | State |
|---|---|---|---|---|---|---|---|---|
| `wreq` | 0.16.3 (2026-10-30) | BoringSSL via `btls` | `min/max_tls_version` | `cipher_list` (BoringSSL mini-language) | `alpn_protocols` | `extension_permutation`, `grease_enabled` | yes — CI builds `windows-latest` + NASM | active, 2.5M dl |
| `wreq-util` | 0.2.1 (2026-11-10) | — | profiles only | OkHttp 3.9/4/5 profiles | — | — | yes | active |
| `boring` + `tokio-boring` | 5.5.0 (2026-11-12) | BoringSSL | `set_min/max_proto_version` | `set_cipher_list`, `set_strict_cipher_list` | `set_alpn_protos` | `set_permute_extensions`, `set_grease_enabled` | yes (cmake+NASM) | active; **no HTTP client** |
| `rustls` | 0.23.46 (2026-11-12) | pure Rust | `builder_with_provider(..).with_protocol_versions(&[&version::TLS12])` | provider `cipher_suites` list | `alpn_protocols` | none | yes, pure Rust | active |
| `reqwest` | 0.13.5 (2026-09-08) | rustls | `tls_version_min` / `tls_version_max` (`min_tls_version` / `max_tls_version` are `#[deprecated]` on this version and fail a `-D warnings` gate), `tls_backend_preconfigured` | via injected rustls config | via that config | none | yes | active, already in this project |
| `ureq` | 3.5.2 (2026-11-12) | rustls | no API in `TlsConfig` | via `unversioned_rustls_crypto_provider` | no | none | yes | active, cannot pin 1.2 |
| `native-tls` / `hyper-tls` | 0.2.18 / 0.6.0 | SChannel on Windows | `min/max_protocol_version` | **no cipher API at all** | no | no | yes | stable/stale |
| `rquest`, `reqwest-impersonate` | all yanked / 0.0.0 | — | — | — | — | — | — | dead, superseded by `wreq` |
| `boring-tls` | **does not exist** (crates.io 404) | — | — | — | — | — | — | the name people cite for `boring` |

`wreq::tls::TlsOptions` (verified on docs.rs for 0.16.3) exposes exactly the knobs the profile needs:
`min_tls_version`, `max_tls_version`, `cipher_list`, `tls13_cipher_list`, `alpn_protocols`,
`curves_list`, `sigalgs_list`, `grease_enabled`, `session_ticket`, `psk_dhe_ke`,
`extension_permutation`, `permute_extensions`, `enable_ocsp_stapling`.

## 4. What the profile demands of a library

- **Version pin** — every candidate exposes it (`min/max_tls_version`, `set_min/max_proto_version`,
  native-tls `min/max_protocol_version`).
- **Cipher-suite list** — only the BoringSSL-backed crates take a real list. rustls takes a provider
  suite list too (both AES-256-GCM suites exist in `rustls-ring`'s TLS 1.2 table), so this is
  expressible without BoringSSL. `native-tls` cannot do it at all.
- **ALPN** — rustls/BoringSSL yes; `native-tls` only through its OpenSSL backend, never on Windows.
- **Extension order, GREASE, padding, session-ID bytes** — BoringSSL only, and even there not fully:
  `boring` offers permutation + GREASE toggles, and `wreq` adds an explicit
  `extension_permutation([ExtensionType])`. **A byte-exact Conscrypt hello is not available in Rust**;
  no crate lets you append an arbitrary padding extension. Closest achievable: wreq with the two
  suites, TLS 1.2 min=max, ALPN `http/1.1`, curves `X25519:P-256:P-384`, the wgcf sigalgs list,
  GREASE off, `session_ticket` + `psk_dhe_ke` on, fixed extension order.
- **Windows build** — rustls is pure Rust. BoringSSL needs CMake, NASM and MSVC; wreq's own CI does
  exactly that on `windows-latest`.

## 5. Recommendation

**Primary — stock reqwest + rustls, gated by a one-request spike.** The project already ships reqwest.
Configure `tls_version_min(TLS_1_2)` + `tls_version_max(TLS_1_2)` (on reqwest 0.13.5 the older `min_tls_version` / `max_tls_version` spellings are `#[deprecated]` and would fail a `-D warnings` build), `.http1_only()`, and inject a rustls
`ClientConfig` (via `tls_backend_preconfigured`) whose `alpn_protocols` is `[b"http/1.1"]` and whose
provider carries only the two AES-256-GCM suites. Send wgcf's headers verbatim. Exit criterion: 2xx on
one live registration — ~20 lines, and the only way to settle §2.

**Fallback — `wreq` 0.16.3 with a custom `TlsOptions`** reproducing §1, behind the same `register()`
seam so the swap is one file. Costs: a second TLS stack (BoringSSL), CMake+NASM in the Windows build,
MSRV 1.98/edition 2024, and binary size. Pay it only if the spike fails.

**Diagnostic only — shell out to `wgcf`.** Zero TLS work and a known-good hello, but it ships a Go
binary and an external process; acceptable to *compare* hellos during the spike, not as a dependency.

**Rejected:** `native-tls`/`hyper-tls` (no cipher control), `ureq` (no version pin), `rquest` and
`reqwest-impersonate` (dead), `boring` direct (correct but you write the HTTP/1.1 layer yourself —
that is the Aether-scale option, ~47 KB of module).

| Approach | Crates | TLS 1.2-only | Custom cipher list | Windows | Risk |
|---|---|---|---|---|---|
| Stock rustls + reqwest | `reqwest` 0.13.5, `rustls` 0.23.46 | yes | yes (provider) | yes, pure Rust | **high until the spike passes**; then low |
| BoringSSL via wreq | `wreq` 0.16.3, `wreq-util` 0.2.1 | yes | yes | yes, needs CMake+NASM | medium: capability certain, profile untested, build cost |
| BoringSSL direct | `boring` 5.5.0, `tokio-boring` 5.5.0 | yes | yes | yes | medium-high: you own the HTTP layer |
| native-tls / hyper-tls | `native-tls` 0.2.18, `hyper-tls` 0.6.0 | yes | **no** | yes (SChannel) | certain failure on the suite list |
| ureq | `ureq` 3.5.2 | no API | via provider | yes | certain failure on the pin |
| Impersonation crates | `rquest`, `reqwest-impersonate` | — | — | — | dead code |
| External helper | `wgcf` binary | n/a | n/a | yes | low effort, high ops cost |

## 6. Correction to the current spec

`02-warp-scan.md` §5 says a mismatched fingerprint yields HTTP 403 with error `1020`. That mapping is
**not verified for the 2026 endpoint**: the reproduced rejection was **429**, and Aether treats 403 as
an SNI/host mismatch and 429 as rate limiting. The spec therefore keeps ONE error variant,
`RegistrationRejected { status, api_version }`, whose `status` carries the meaning: **404** → the API
version moved; **403 + Cloudflare error 1020** → fingerprint/TLS policy rejection; **429** → rate
limited (report it and try much later — never in a loop). (This study originally proposed a separate
`RegistrationRateLimited` variant; the spec does not, because a second variant would need its own row
in all three exit-code tables — `01-architecture.md` §8, `04-cli.md` §6, `06-qa.md` §2.1 — and the
single variant with a status value expresses the same behaviour.)

## 7. Verified vs unverified

**Verified (primary sources, 2026-11-16):**
- wgcf master `api.go` contents, commit `803310a`, `go.mod` (uTLS 1.8.2); v2.2.32 `api.go` comment and
  stock `tls.Config`; issue #626 thread (429 reports, fix released as 2.3.0).
- warp-plus `go.mod` (uTLS 1.7.3), `warp/tls.go`, `warp/api.go`.
- crates.io API: `wreq` 0.16.3 (Apache-2.0, MSRV 1.98, edition 2024) and its 39-version history;
  `rquest` fully yanked; `reqwest-impersonate` only 0.0.0; `boring` 5.5.0; `native-tls` 0.2.18;
  `ureq` 3.5.2; `rustls` 0.23.46; `reqwest` 0.13.5; `boring-tls` 404; no WARP-client crates.
- docs.rs: `wreq` 0.16.3 `TlsOptionsBuilder` methods; `boring` 5.5.0 `SslContextBuilder` methods;
  `rustls` `builder_with_provider` / `with_protocol_versions` / `version::TLS12`; `native-tls`
  0.2.18 has `min/max_protocol_version` but no cipher API; `reqwest` `min/max_tls_version` +
  `tls_backend_preconfigured`.
- Source: `rustls-ring/src/tls12.rs` defines both AES-256-GCM suites; wreq CI builds on
  `windows-latest` with NASM; Aether and usque-rs stacks as cited above.

**Unverified / inferred:**
- Whether stock rustls is refused today — no request was made, and the September incident is
  confounded by a simultaneous API-version and header change.
- Whether a wreq-shaped hello is accepted. Plausible, never tested.
- "403/1020 means fingerprint" — only a historical code comment, not reproduced in 2026.
- Why Aether hand-rolls HTTPS for the API; no statement of a rejection was found.
- That `v0a5641` is still the live version (it is wgcf master's value today, not a live probe).
- That wgcf's hello is byte-identical to the real Android app — it is the author's reconstruction.
