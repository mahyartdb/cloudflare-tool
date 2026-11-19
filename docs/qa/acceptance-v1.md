# cftool v1 acceptance record

Date: 2026-11-19
Toolchain: rustc/cargo 1.97.1 (the declared `rust-version = "1.97"` floor)

## Workspace

| Crate | Role |
| --- | --- |
| `cftool-core` | Shared engine: plans, ranges, probe runner, events, results, output |
| `cftool-warp` | WARP endpoint scanner (registration, handshake probe, tier-1 findings) |
| `cftool-cdn` | CDN edge-IP scanner (sampling, pinning, filters, speed policy) |
| `cftool` | CLI frontend (binary + `[lib]` writer target for GUI parity) |
| `cftool-gui` | gpui-kit 0.9.1 generic module view |

Registered modules: `warp`, `cdn` (verified by `cftool modules`).

## Gates (observed)

| Gate | Command | Result |
| --- | --- | --- |
| Format | `cargo fmt --all` | clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Check | `cargo check --workspace --features mock` | clean |
| Test | `cargo test --workspace --features mock` | **61 passed, 0 failed** |

Test distribution: core 36 (P0-A 13, P0-B 12, P0-C 11), warp 12, cdn 10, gui 3.

Notes:
- `[profile.dev] debug = 0` and `[profile.test] debug = 0` are set because MSVC `link.exe` failed with `LNK1318: PDB LIMIT (12)` when linking the gpui-kit GUI binary with full debug info.
- A full workspace test after a clean `target/` was run successfully.

## Acceptance coverage

| IDs | Evidence |
| --- | --- |
| C1–C9 | `core/tests/p0b_ranges.rs` (C1/C2), `core/tests/p0c_runner.rs` + `p0c_cancel.rs` (C3–C9) |
| Warp T1, T2, T3, T6, T8, T9 | `warp/tests/warp_t.rs` + `warp/src/{probe,finding}.rs` unit tests |
| Cdn T1, T2, T3, T6 (extraction), T7, T8 | `cdn/tests/cdn_t.rs` + `cdn/src/finding.rs` unit tests |
| CLI T1–T10 | CLI dispatch + exit-code mapping (`exit_code`), writer via core; `cargo run ... modules`, `--help`, `config path`, mock scan smoke tests |
| GUI G1, G8 | `gui/tests/gui_t.rs` (registry + byte-identical CSV/JSON export) |
| Parity | GUI calls `cftool_cli::export_json/export_csv`; G8 asserts byte equality |

## End-to-end smoke (observed)

```
$ cargo run -q -p cftool --features mock -- \
    --json --mock <script> warp-scan
{"module":"warp","started_at":"2026-11-19T06:30:41.352558Z","wall_time":19,
 "totals":{"probed":3,"alive":2,"filtered":0,"cancelled":false},
 "findings":[alive endpoint with rtt 5.0, cookie endpoint with rtt null]}
```

The script target set replaced the plan, the dead target produced no row, and the cookie finding carried `rtt_ms: null`.

## Known gaps (not claimed as passed)

1. **Live ignored tests not run.** Warp T4/T5 and cdn T4 are `#[ignore]` live-network tests; they require registration/network access and were not executed. The registration transport and handshake path are implemented but only their pure seams (status mapping, receiver-index rule) are covered hermetically.
2. **P1 registration TLS spike not executed.** The reqwest/rustls profile (TLS 1.2, two AES-256-GCM suites, ALPN http/1.1) is implemented behind `register()`; whether a stock hello is accepted by the live API was not verified in this build.
3. **CDN live download phase.** `apply_speed` implements the tested EWMA/floor/budget policy; the real HTTP GET download is not wired into `finalize` in v1.
4. **GUI manual QA.** The generic view compiles and its registry/export tests pass; visual layout, interaction, dialog rendering and window-close timing were not manually exercised in a desktop session.
5. **Second Ctrl-C hard exit.** Handled via `tokio::signal::ctrl_c()` twice; the Windows `windows`-crate console control handler for exit 130 was not added (the spec permits but does not require all polish in v1 merge state).
6. **WARP tier 2** is post-v1 by spec and intentionally absent.

## Merge readiness

All automated gates are green and all spec'd unit/acceptance tests that are hermetic pass. The gaps above are live-network, manual-GUI, and explicitly post-v1 items; none of them block a code merge, but release sign-off should schedule the live spikes and manual GUI pass.
