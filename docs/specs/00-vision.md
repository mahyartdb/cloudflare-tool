# cftool — Vision & Product Spec

- Status: Draft v1 (spec phase)
- Date: 2026-11-16
- Supersedes: nothing

## 1. One-line definition

cftool is a modular Cloudflare network toolkit: pluggable scanner modules (WARP endpoint scanner, CDN edge-IP scanner, more later), one shared probe engine, two frontends (CLI and gpui-kit GUI) built on the same core.

## 2. Why this exists

Cloudflare's WARP endpoints and CDN edge IPs vary enormously in latency and reliability depending on where you are — especially from networks where Cloudflare traffic is deprioritized or throttled. The communities that live with this daily (Iran, Russia, China) have built excellent single-purpose tools (bepass-org's WARP tools, XIU2/CloudflareSpeedTest, wgcf). Each is standalone, each reinvents scanning, none share an engine or a UI.

cftool consolidates the *techniques* those tools pioneered into one clean, modular Rust toolkit that we own and can extend: find the fastest healthy WARP endpoint; find the fastest healthy CDN edge IP for your network; export the winners.

## 3. Product principles

1. **Modules are citizens, not plugins-as-afterthought.** Adding a scanner module must require zero edits to core, and zero edits to a frontend beyond one registration line in each — a new crate + one `.register(...)` line per frontend (plus the manifest entries that crate needs). Removing a module must leave the rest fully functional.
2. **One engine, every scanner.** Concurrency, timeouts, cancellation, output, and progress reporting live in core. A module writes *what to probe and how to judge it*, never *how to run the loop*.
3. **Honest numbers.** Latency figures must mean what they say (TCP handshake time, UDP handshake RTT, TTFB, download rate). No silent retries inflating results; loss rates reported, not hidden.
4. **Legal & polite by construction.** The tool scans only Cloudflare's own published/known service ranges, at the capped volume in §3.1. No arbitrary-internet scanning, no rate-limit evasion, no abuse features. This is a hard product boundary, not a suggestion.
5. **CLI-first ergonomics, GUI-first experience.** The CLI must be scriptable and composable (JSON out, exit codes). The GUI must make the same capability feel native and fast (gpui-kit). Same core, same results.
6. **The user's machine is the limit.** Defaults must work on ordinary hardware/networks; heavy sweeps are opt-in.

### 3.1 Volume budget (normative)

This table is normative for module defaults. A module may choose lower values, never higher; a module that needs more is a change to this document first. The 4,096 concurrency cap is the only overridable ceiling — every other row is a fixed limit.

| Budget | Limit |
| --- | --- |
| Concurrent outbound probes | module default ≤ 512; a user override may raise it up to the engine's hard ceiling of 4,096 (a cap, not a target) — a module may enforce a stricter ceiling (cdn: 512 tcp / 200 http) |
| Packets emitted per scan | ≤ 250,000 — the charged packet count is endpoints × (attempts per probe + warm-ups per probe + noise datagrams per probe) |
| Attempts per probe | 1..4 measurement tries of one endpoint; the retry-vs-fixed choice is module policy (cdn fixes 4 tries per endpoint in tcp mode and 1 in http mode; warp makes 1) |
| Endpoints per address | the ports the module tries for that address — warp: 1 pinned / 4 standard / up to 54 full; cdn: 1 |
| Scans per process | 1 at a time |
| HTTP-mode concurrency | ≤ 200 — higher rates have been observed to trigger temporary Cloudflare-side rate limiting |
| Download/throughput phase | ≤ 512 MB per scan, ≤ 10 candidates |
| Target space | Cloudflare-owned ranges only, enforced at runtime (`01-architecture.md` §3) |

An **address** is a network address the module tests. An **endpoint** is an (address, port) pair — the unit the engine probes. A **probe** is one endpoint's measurement, made as 1..4 **attempts**: the first try plus up to 3 retries, counted and reported in `ProbeOutcome.attempts` (core never retries; the module's probe does). The **charged packet count** is the total packets a scan may emit — endpoints × (attempts + warm-up connections + noise datagrams) — so the 250,000 ceiling bounds emitted packets, not merely measurements:

- cdn default: 5,956 × (4 + 1 + 0) = 29,780 packets.
- warp pinned/light: 3,584 × (1 + 1 + 5) = 25,088 packets.
- warp full at 3,584 addresses: 3,584 × 54 = 193,536 endpoints, charging 387,072 packets even with noise off (1,354,752 at the default `light`, 10,063,872 at `heavy`) — rejected by the ceiling.

`port-mode full` is therefore not a loophole. The packet ceiling is also what makes principle 4 concrete: the same 250,000 is the scan's emission budget, checked at plan time (`01-architecture.md` §9) before any socket opens.

## 4. Goals (v1)

- G1: Cargo workspace with `core`, two scanner module crates (`warp`, `cdn`), `cli`, `gui`.
- G2: `warp-scan` finds alive WARP endpoints by performing real WireGuard Noise_IKpsk2 handshakes with a registered WARP identity (naive UDP probes are silently dropped by WARP servers — see research §2.3), over the community-proven endpoint pools and port set (see `02-warp-scan.md`).
- G3: `cdn-scan` measures Cloudflare CDN edge latency (TCP handshake + optional HTTP TTFB + optional speed test) over Cloudflare's published IP ranges (see `03-cdn-scan.md`).
- G4: CLI binary `cftool` with per-module subcommands, table/JSON/CSV output, live progress, clean Ctrl-C.
- G5: gpui-kit GUI with sidebar module navigation, per-module option forms, live results table, progress + cancel, export.
- G6: All scanner results share one result model, so export/copy/parsing is identical in both frontends.

## 5. Non-goals (v1)

- N1: Not a VPN/proxy client. cftool finds endpoints; it does not tunnel through them (the warp module's tier-2 tunnel validation is a measurement harness, not a data path — see `02-warp-scan.md` §7).
- N2: No wgcf-style WireGuard profile generation/export in v1. The warp module's *identity bootstrap* (registering a WARP identity via the official client API so handshake probes are accepted) IS in v1 because the scanner cannot work without it (research §2.3, §2.7); exporting configs for other tools is out of scope.
- N3: No scanning outside Cloudflare-owned space. Two tiers. **Global gate:** every plan is validated at runtime against the Cloudflare-owned allowlist and rejected otherwise, whatever the module (`01-architecture.md` §3, §6). **Per-module policy:** inside that gate each module applies a stricter policy, and a module's policy only ever narrows the gate, never widens it — `cdn-scan` v1 scans only Cloudflare's published CDN ranges and accepts no custom input (`03-cdn-scan.md` §2.2); `warp-scan` v1 accepts custom CIDRs only from the WARP endpoint-pool superset (`02-warp-scan.md` §2.2). Full arbitrary-range scanning is explicitly out of scope for v1.
- N4: No dynamic plugin loading (.dll/.so) in v1. Modules are compile-time crates (see `01-architecture.md` §5 for the decision and the future path).
- N5: No DNS-over-HTTPS resolver module, no proxy-protocol testing in v1.

## 6. Users

- Primary: qmahyar — a technical user on Windows who wants working Cloudflare endpoints/edges fast, in a GUI, with a CLI for scripting.
- Secondary: technical users in throttled networks (IR/RU/CN contexts) who currently juggle CloudflareSpeedTest / warp endpoint scanners.

## 7. Success criteria for v1

Each row names the load that produces it and the check that observes it. All five are verified in the P5 acceptance run (`06-qa.md` §4.6), and `06-qa.md` §2 carries the same bound per row.

| # | Criterion | Load config | Check |
| --- | --- | --- | --- |
| S1 | `cargo build --release` produces one CLI exe and one GUI exe | release profile, clean checkout | build output lists `cftool` and `cftool-gui` |
| S2 | The default warp scan completes in ≤ 90 s on a 100 Mbps consumer connection. Coverage is observed, not gated: warp-plus is stochastic and stops at a bounded queue, so the P5 session records both tools' alive sets and cftool's set is expected to cover warp-plus's, any gap written up as a finding | 14 IPv4 /24s fully enumerated (3,584 targets), pinned port 2408, concurrency 512 | `02-warp-scan.md` §9 T5 (ignored-live) for the time bound; the P5 acceptance session (`06-qa.md` §4) records both tools' alive sets in a transcript — a coverage gap is a recorded finding, never a build failure |
| S3 | A cdn latency scan of Cloudflare's published v4 ranges completes in ≤ 180 s wall clock, warm-up included | cdn-scan over the published v4 ranges at module defaults (5,956 targets, concurrency 200, 4 attempts, 1 warm-up per target) — `03-cdn-scan.md` §5 | `03-cdn-scan.md` §7 T4 (ignored-live) |
| S4 | Module-removal job: delete one module crate and its registration line in each frontend — both frontends build and the remaining module runs a scan | one run per module | scripted check at P5 (`06-qa.md` §4.6) |
| S5 | During a scan of ≥ 10,000 targets: no frame gap > 100 ms, a finished probe's result shows within 1 s, and Cancel halts the scan within 500 ms | cdn-scan over the published v4 ranges with `--sample-per-subnet 2` (11,912 addresses) and `--timeout 330` (the plan's floor at that size is 300 s; 330 s leaves headroom so the acceptance recording is not cut short by the budget) — the default 180 s ceiling is below this plan's 300 s feasibility floor, ceil(11,912 / 200) × 5 × 1 s | manual-GUI run recorded at 60 fps (`06-qa.md` §3) for frame gap and Cancel; the 1 s result bound is asserted by the mock stream test (`05-gui.md` §7) |

## 8. Name and license

- Crate/binary prefix: `cftool` (workspace crates `cftool-core`, `cftool-warp`, `cftool-cdn`, binaries `cftool`, `cftool-gui`).
- License: MIT for all workspace crates.

## 9. Open questions

- Q1: Binary name — is `cftool` fine, or do we want something more distinctive (e.g. `flare`, `cfkit`)? Decision owner: qmahyar. Not blocking spec phase; rename is mechanical.
- Q2: Should the GUI ship in the same repo (workspace member) — yes per G1 — but do we also want a separate distribution (installer) story in v1? Deferred to P5 planning (`06-qa.md` §4).
