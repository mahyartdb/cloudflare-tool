# cftool — Architecture Spec

- Status: Draft v1 (spec phase)
- Date: 2026-11-16
- Depends on: `00-vision.md`

## 1. Workspace layout

```
cloudflare-tool/
├── Cargo.toml                  # workspace manifest, shared deps, release profile
├── crates/
│   ├── core/                   # cftool-core: engine + shared types (no UI, no module logic)
│   ├── modules/
│   │   ├── warp/               # cftool-warp: WARP endpoint scanner module
│   │   └── cdn/                # cftool-cdn: CDN edge scanner module
│   ├── cli/                    # cftool: CLI frontend — [[bin]] and [lib] targets
│   └── gui/                    # cftool-gui: gpui-kit frontend
└── docs/
    ├── specs/                  # this spec set
    └── research/               # tool-landscape research notes
```

Dependency rule (hard): `core` depends on nothing workspace-internal. A module depends only on `core`. Frontends depend on `core` + the modules they ship; `cftool-gui` additionally dev-depends on the `cftool` lib for the export-parity test only (below). Modules never depend on each other or on frontends. Violations fail review.

**`crates/cli` ships two targets.** The package is `cftool`: `[[bin]] name = "cftool"` (`src/main.rs` — argument parsing and exit codes) plus `[lib] name = "cftool"` (`src/lib.rs` — the frontend's export path, `cftool::export::save_csv(columns, rows, path)` and `cftool::export::save_json(summary, path)`; each is a thin wrapper over `core::output::write_csv` / `write_json` and formats nothing itself). The lib target exists so an export can be called from a test: `crates/gui` (package `cftool-gui`) declares `cftool = { path = "../cli" }` in `[dev-dependencies]`, and its export-parity test (§11) calls BOTH real frontend export functions — `cftool::export::…` and the GUI's own — over one fixture and compares the bytes. That dev-dependency is the workspace's one frontend→frontend edge: test-only, absent from both release builds, and it carries no UI code, no module logic and no second formatter.

## 2. The three layers

| Layer | Owns | Never contains |
| --- | --- | --- |
| core | probe runner, target planning, event stream, result model, range sources, config, output sinks | any scanner-specific knowledge, any UI types |
| module | target selection, probe judging, module options, module metadata | the probe loop and its in-flight endpoint slots, UI code, output formatting |
| frontend | CLI parsing, GUI views, module registration, table rendering and output file handling | probe algorithms |

## 3. Scan execution model

A scan is a pipeline of three phases, all owned by core: Plan → Run → Finalize.

**Scan start surface.** The frontend owns the start sequence and it is the only way a scan begins: (1) the frontend builds `ModuleOptions` from the module's `OptionsSpec` (CLI flags + config file, or the GUI form) and writes the resolved wall-clock ceiling into the module's `scan-timeout` option; (2) it calls the module's `plan(opts)` and receives a validated `TargetPlan`; (3) it creates the `CancellationToken`, constructs the `ProbeRunner` with the resolved `ProbeRunnerConfig` (`concurrency`, `total_budget`; `concurrency` comes from the reserved option key, §5) and the scan's `ModuleOptions`, and calls `run(plan, source, events, cancel)` (§3, Runner surface) — awaiting it, or spawning it and holding the task as the `ScanHandle` — handing it the scan's `ProbeSource` (§5.2) and the `EventSink`'s two event lanes; (4) the runner emits `Started { plan_endpoints, concurrency }` and then the progress and result events. The frontend never acquires the scan permit: `ProbeRunner::run` acquires the one process-wide permit itself (§3.3) and returns `Err(ScanError::Busy)` when the slot is held — a second start while the first run is alive — so the frontend only starts the run and surfaces the `Busy` error (CLI: exit 4, §8; GUI: an inline error). The endpoint total in `Started` is the denominator both frontends render (the GUI's progress bar, the CLI's status line) and it counts ENDPOINTS — addresses × their port lists — never addresses. A recipe-only plan (addresses generated on demand) still reports the endpoint total: `TargetPlan::plan_endpoints` carries it — computed from the recipe when the address list is empty — so the denominator always exists.

**Units.** An **address** is a network address the module wants to test (the plan's unit). An **endpoint** is `(address, port)` — the probe unit. A **probe** is one endpoint's measurement: 1..=4 **attempts** (measurement tries of that endpoint), recorded per try in the outcome's `AttemptRecord` (§3.2). Failure handling is module policy (cdn: 4 attempts in tcp mode and 1 in http mode, each failed attempt = loss; warp: one attempt). A **finding** is one alive endpoint.

1. **Plan** — the module builds a `TargetPlan` (§5) from its options: a generation recipe, one port list per address, the exact `charged_packet_count` (§5), and a per-probe timeout. The frontend has already written the resolved wall-clock ceiling into the module's `scan-timeout` option (§5), so the feasibility floor is checked against the value the engine will enforce. `plan()` validates the plan before any socket opens, in this order — (1) option validation → `OptionsInvalid`; (2) RANGE-policy validation → `AllowlistViolation`; (3) plan shape — including the 64,512-endpoint result-lane bound, a core-level plan check every module must apply — and `charged_packet_count` budget → `InvalidPlan`; (4) module preconditions such as a registered identity → `IdentityMissing`. The first failure wins, and the order is contract: the packet count must never be computed over addresses that failed the range check, so a too-wide CIDR is rejected as an allowlist violation rather than a budget error, and an allowlist rejection never depends on the identity being present. Warm-up packets and noise datagrams are charged inside `charged_packet_count`, so the 250,000-packet ceiling (§9) bounds everything the scan emits, not only measurements. Nothing is probed unless all four checks pass. Plans above 100,000 resident addresses keep the recipe and generate addresses on demand (§9).
2. **Run** — core's `ProbeRunner` expands each address × its port list into endpoints and executes the module's probe function against every endpoint with bounded in-flight endpoint slots (`ProbeRunnerConfig { concurrency, total_budget }`, resolved per §5), building each probe's `ProbeBudget` from the plan's timing fields (§5) so the frontend never needs module-specific timings, and emitting `ScanEvent`s on the two lanes in §3.1 as results arrive. When the plan sets `stop_on_first_answer`, the runner skips an address's remaining ports once one endpoint answered. Cancellation via `tokio_util::sync::CancellationToken`; every await in the runner and probe path is cancellation-aware, and a probe cancelled mid-flight yields `Dead { reason: DeadReason::Cancelled }` for that endpoint — counted dead, never a finding.
3. **Finalize** — core awaits the module's async `finalize` (§5), the single outcomes → findings step: cdn's filter + download and warp's tier-2 validation (when enabled) run inside it. `finalize` returns the module's findings, one per alive endpoint, each with its module-set `sort_rank`; core orders them by rank (`Some` ascending, then `None`, stable) and wraps the result in a `ScanSummary` with wall time, counts, and the module id. `finalize` receives every outcome, the scan's `ModuleOptions` and the `CancellationToken`; §9 gives the buffer bound. The token is observed at every await inside `finalize`, and a token fire does NOT truncate its result to a prefix: `finalize` returns ONE FINDING PER `Alive` OUTCOME it was given, with the post-phase columns the cancelled phase would have computed left `CellValue::Null` (cdn's speed; any colo or status a module only learns in `finalize`) — so a cancel during cdn's download keeps every row the progress lane already counted, and answered endpoints are never turned into `dead`. A `Dead` outcome still produces no finding, so `alive` = findings = the count of `Alive` verdicts on every path, cancel included, and `probed = alive + dead` holds throughout (§4).

**Runner surface.** The runner is `ProbeRunner`, constructed per start with the resolved `ProbeRunnerConfig` and the scan's `ModuleOptions`; its entry point is an `async fn`:

```rust
impl ProbeRunner {
    pub async fn run(
        &self,
        plan: TargetPlan,
        source: Arc<dyn ProbeSource>,                // §5.2: the module path, or ScriptedProbeSource
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<ScanSummary, ScanError>;             // acquires the scan permit; Err(Busy) when held
}

pub struct EventSink {
    pub progress: tokio::sync::watch::Sender<ProgressSnapshot>, // lane 1 (§3.1): latest ProgressSnapshot counters, 50 ms coalescing in core
    pub results: tokio::sync::mpsc::Sender<ScanEvent>,          // lane 2 (§3.1): ordered, capacity 65,536
}

pub struct ProgressSnapshot { pub completed: usize, pub alive: usize }
```

`EventSink` is the pair of lanes §3.1 defines — the progress `watch` (the latest `ProgressSnapshot` values) and the ordered result `mpsc` — so the runner is handed the two lanes, never an undefined event parameter. `run` resolves the probe through `source.probe(opts)` (§5.2), so the module path and the scripted path are one engine path. The frontend either awaits the returned future directly or spawns it and holds the task as the `ScanHandle` — the `JoinHandle<Result<ScanSummary, ScanError>>` that `05-gui.md` §4's `Running { handle }` keeps — and the summary or error is received there while the events arrive on the two lanes meanwhile (§3.1). A panic inside a probe is contained — it becomes `Dead { reason: DeadReason::Internal }` for that endpoint and the scan continues (§8) — so the error arm is a hard failure, never one bad probe.

### 3.1 Event stream

One `ScanEvent` type, two lanes:

```rust
pub enum ScanEvent {
    Started { plan_endpoints: usize, concurrency: usize }, // endpoints the plan will probe (the progress denominator)
    Result(ProbeOutcome),                           // result lane, one per finished probe
    Phase(ScanPhase),                               // Plan -> Run -> Finalize transitions
    Log { level: LogLevel, message: String },       // module/engine diagnostics
    Done(ScanSummary),
    Failed(ScanError),
}
```

Progress is NOT an event: the progress lane carries `ProgressSnapshot` values only, and the six variants above are the whole of `ScanEvent`, all on the result lane.

| Lane | Events | Transport | Guarantee |
| --- | --- | --- | --- |
| Progress | `ProgressSnapshot` (not a `ScanEvent`) | `tokio::sync::watch` latest value, 50 ms coalescing ticker in core | never blocks the runner; latest snapshot wins; intermediate values dropped by design |
| Result | `Started`, `Result`, `Phase`, `Log`, `Done`, `Failed` | `tokio::sync::mpsc`, capacity 65,536 | ordered, never dropped |

- **Progress lane:** core keeps atomic completed/alive counters and publishes at most one snapshot per 50 ms. A slow consumer costs the runner nothing; it reads the latest value.
- **Result lane:** every result-lane send is `try_send`. A full lane (65,536 pending events) means the consumer cannot keep up: the runner stops probing, cancels in-flight probes, and aborts with `ScanError::ResultLaneOverflow { capacity: 65_536 }` — it never blocks forever and never drops a result. `Failed(ScanError::ResultLaneOverflow { capacity: 65_536 })` is attempted on the lane; if that also fails, the typed error is the scan future's return value.
- `Done` is enqueued only after every `Result` has been enqueued; the single result-lane order means a consumer sees all results before `Done`.
- A send error because the receiver was dropped is cancellation: the runner stops and returns `Cancelled`, emitting nothing further.

**Terminal contract.** For a scan whose lanes are alive, `Done` and `Failed` are mutually exclusive: exactly one of them is the last event, and it decides the scan future's value.
- Completion: `Done(ScanSummary)` with `totals.cancelled = false`; the scan future returns `Ok(summary)`.
- User cancel or budget exhaustion: the order is (results on the result lane) → `Done(ScanSummary)` with `totals.cancelled = true`, carrying the PARTIAL findings → the future returns `Ok(summary)`. It does NOT emit `Failed`. The one exception is a budget that expires before any summary can be produced: then the future returns `Err(BudgetExhausted)` (§8), the only path that constructs that variant.
- `Failed(ScanError)` is emitted only for a hard failure with no usable summary; then the future returns `Err(error)`.
- The CLI derives exit 5 from `totals.cancelled == true` when a summary exists; `Err(Cancelled)` / `Err(BudgetExhausted)` are only the no-summary fallback (§8). The GUI enters its `Cancelled` state on `totals.cancelled == true`, so a user cancel and a budget exhaustion share one terminal state.

### 3.2 Probe abstraction

A module does not implement the loop; it implements a probe step. The trait is object-safe so `Arc<dyn Probe>` can be shared across tasks:

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Probe: Send + Sync + 'static {
    /// One endpoint's measurement: 1..=4 attempts (measurement tries) of that
    /// endpoint, the count fixed by module policy. Cancellation-aware and
    /// internally bounded by its ProbeBudget.
    fn probe<'a>(&'a self, target: ProbeTarget, budget: ProbeBudget) -> BoxFuture<'a, ProbeOutcome>;
}
```

The boxed future is `Send`; that is the bound that lets the runner `tokio::spawn` probe tasks and hold `Arc<dyn Probe>` across them. An `async fn` in the trait would not be dyn-compatible and could not back `Arc<dyn Probe>`. `ProbeBudget.per_attempt_timeout` applies to each attempt and the whole probe is capped by the single formula in §5's probe time model (`overhead + max_attempts × per_attempt_timeout`); a module's warm-up work happens inside that same probe budget. `ProbeBudget.cancel` carries the scan's token, so the probe observes cancellation at every await: a probe stopped by the token reports `Dead { reason: DeadReason::Cancelled }` — even when an earlier try succeeded, cancellation overrides it; counted dead, never a finding — and `tries_succeeded` still reports the tries that completed before it fired.

`ProbeOutcome` is the shared honest-numbers record, and it carries its per-attempt results:

```rust
pub struct ProbeOutcome {
    pub target: ProbeTarget,         // the endpoint this probe measured
    pub verdict: ProbeVerdict,       // Alive { rtt, detail } | Dead { reason }
    pub attempts: AttemptRecord,     // the per-attempt record, see below
    pub started_at: OffsetDateTime,  // for reproducible dumps
}

pub struct AttemptRecord {
    pub tries_made: u8,        // 1..=4
    pub tries_succeeded: u8,   // 0..=tries_made
    pub try_rtts_us: Vec<u32>, // the RTT of each successful try (≤ tries_succeeded entries)
}

pub enum ProbeVerdict {
    Alive { rtt: Option<Duration>, detail: AliveDetail },
    Dead { reason: DeadReason },     // no finding: never answered, or cancelled mid-flight (§4)
}

pub enum DeadReason { Timeout, Unreachable, ParseFailure, Cancelled, Internal }
```

Every derived figure is read from the record, and liveness is read from the verdict alone. Loss = (`tries_made` − `tries_succeeded`) / `tries_made`; the reported mean RTT is the mean of `try_rtts_us` when the list is non-empty, else `None`. `tries_made`, `tries_succeeded` and `try_rtts_us` exist for LOSS and mean RTT, not for liveness — an endpoint is alive iff its verdict is `Alive`. `ProbeVerdict::Alive { rtt }` carries that mean when it exists; `rtt` is `None` when the endpoint gave no timing (a cookie reply), and a timing is never fabricated. A probe cancelled mid-flight is `Dead { reason: DeadReason::Cancelled }` even when an earlier try had succeeded: cancellation overrides earlier successes, and the endpoint is counted dead and never produces a finding. warp makes one try per probe (`tries_succeeded` is 0 or 1); cdn makes four in tcp mode and one in http mode (`03-cdn-scan.md` §5), and its `loss_pct` column is read from this record — so `finalize` computes loss without guessing.

`AliveDetail` is core's probe-level record — what the probe itself observed — and `AliveKind` is its closed kind. `facts` is how a module carries facts observed DURING the probe into `finalize`: cdn observes the HTTP status and the `cf-ray` colo there, and `finalize` may read them. Module post-phase results (tier-2 validation, download speed) are finding columns (§4), never `AliveDetail` values. `AliveKind::Cookie` is how a cookie reply is represented: alive, with `rtt: None`.

```rust
pub struct AliveDetail {
    pub kind: AliveKind,                      // Type2Response | Cookie | Connected
    pub facts: BTreeMap<String, CellValue>,   // module-observed facts (cdn: status, colo); CellValue is §4's cell type
}

pub enum AliveKind {
    Type2Response,   // full handshake response (warp)
    Cookie,          // cookie reply: endpoint up, rate-limiting, no RTT (warp)
    Connected,       // transport-level success with no protocol-specific fact (cdn)
}
```

Attempts and retries live *inside* a module's probe step — it knows what a transient failure looks like and how many tries its failure handling requires (cdn: 4 in tcp mode and 1 in http mode, `03-cdn-scan.md` §5, each failed try = loss; warp: one try), but the `AttemptRecord` is always reported so latency and loss can't be silently flattered. Core itself never retries. Filtering is not a probe verdict: a probe reports only what it observed, and each module applies its filter to findings in `finalize` (§4).

### 3.3 Async & state ownership

- **Runtime:** frontends own the tokio runtime; core never creates one. The CLI builds its own multi-thread runtime and blocks on the scan future. The GUI builds one dedicated multi-thread runtime for engine work (never GPUI's executor) and bridges `ScanEvent`s onto the GPUI context through `cx.update`; no engine future is awaited on the UI thread.
- **One scan at a time:** a single process-wide scan permit (one slot — Vision §3.1's scans-per-process limit), acquired inside `ProbeRunner::run` and released when the run ends (§3, start surface); no frontend acquires it. The admitted scan carries the Vision §3.1 budget: ≤ 512 in-flight endpoint slots by module default (hard engine ceiling 4,096, §5) and ≤ 250,000 charged packets per scan. A second `run` while the slot is held returns `ScanError::Busy`, never queued or interleaved. Frontends still disable Start while running as the UX guard.
- **Cancellation ownership:** the frontend creates the per-scan `CancellationToken` and passes it to the engine; the engine only observes it and never creates or cancels a token on its own. The token reaches the module seam through `ProbeBudget.cancel` for probes and as the `finalize` argument, so every await in the probe path and in `finalize` observes it. A cancel during `finalize` returns one finding per `Alive` outcome it was given, with the post-phase columns null — never a prefix, never a discard — which keeps Vision S5's 500 ms cancel bound and the GUI's 2 s window-close join reachable even while cdn's download (up to 10 × 10 s) or warp's tier-2 teardown is running. Ctrl-C (CLI) and Cancel (GUI) trip the frontend-owned token.
- **GPUI state:** entities (`ScanViewState`, `ResultsModel`) are mutated only on the UI context; engine tasks send events/commands to the UI task and never touch entity state from runtime threads. The generation counter (`05-gui.md` §4) rejects events from a superseded scan.
- **Shutdown:** dropping the frontend's runtime aborts engine tasks and releases the scan slot on task drop; the GUI drops its runtime after the last window closes.

This is the async rule referenced by `05-gui.md` §4.

## 4. Result model

One `ScanSummary` shape for every module (Vision G6):

```rust
pub struct ScanSummary {
    pub module_id: ModuleId,                // serialized as "module"
    pub started_at: OffsetDateTime,         // time crate; serialized RFC 3339 in JSON
    pub wall_time: Duration,
    pub totals: ScanTotals,                 // serialized: probed, alive, filtered, cancelled
    pub findings: Vec<Box<dyn ModuleFinding>>,
}

pub struct FindingRow {
    pub columns: Vec<(String, CellValue)>,
}

pub enum CellValue { Text(String), Number(f64), Bool(bool), Null }

pub trait ModuleFinding: Send {           // one finding = one alive endpoint; one row in any output format
    fn sort_rank(&self) -> Option<u64>;   // module-defined "best first"; None = unranked, last
    fn to_row(&self) -> FindingRow;       // concrete, serde-able row
    fn is_filtered(&self) -> bool;        // responded, but the module's filter or top-N dropped it
}

pub struct ColumnSpec { pub key: &'static str, pub header: &'static str }
```

- `ModuleFinding` is object-safe and carries no serde bound; `Send` is required because findings travel in `ScanSummary` across the event lane.
- `sort_rank` — `Some(rank)` is a ranked finding: ascending, lower is better, module-defined; `None` is unranked: listed after every ranked finding and never excluded from output. The module sets each finding's rank in `finalize`; core sorts after it, so ordering is stable — equal ranks keep `finalize`'s returned order, and unranked findings keep that order among themselves. Frontend display filters (e.g. `--show-filtered`, `04-cli.md` §3) are a separate, explicit opt-out and do not change the model.
- `is_filtered` — trait default `false`. A finding returns `true` when its endpoint responded but the module's filter dropped it (over max-rtt, under min-rtt, over max-loss, colo mismatch) or when it fell outside the module's retained top-N. It is the only shared "filtered" notion: core counts those findings into `totals.filtered` and never interprets a module's `status` strings.
- `ScanSummary` implements `Serialize` by projecting each finding through `to_row()` into `FindingRow` (a hand-written impl, not derive); `FindingRow` and `CellValue` implement serde, with `FindingRow` serialized as a JSON object keyed by column key. No trait object is serialized directly, and no serde-generic trait bound is needed. The same hand-written impl emits the summary's own top-level keys and its `totals` field set.

**Provisional live rows.** Findings exist only after `finalize`, but both frontends render live results during the run (Vision S5's 1 s bound; the CLI's rolling top-5, `04-cli.md` §3). During the Run phase the frontends render PROVISIONAL rows built from `ProbeOutcome`, one per alive endpoint: endpoint, the verdict's RTT (empty when `None`) and the verdict kind. A column whose value only `finalize` can compute (cdn's speed, a module's post-phase status) is empty in a provisional row. On `Done`, the finalize-produced findings REPLACE the provisional rows; a provisional row is never a finding, is never serialized, and does not survive the run.

`totals` follows one counter partition:

| Field | Meaning | Serialized |
| --- | --- | --- |
| `probed` | endpoints attempted | yes |
| `alive` | endpoints whose verdict is `Alive` (= the number of findings) | yes |
| `dead` | endpoints whose verdict is `Dead` — never answered, or cancelled mid-flight; core-internal counter, `probed − alive`, never serialized and never a row | no |
| `filtered` | a SUBSET of `alive`: findings whose `is_filtered()` is true — endpoints that responded but the module's filter dropped (over max-rtt, under min-rtt, over max-loss, colo mismatch) or that fell outside the module's retained top-N. An endpoint whose verdict is `Dead` — never answered, or cancelled mid-flight — is `dead`, never `filtered`. | yes |
| `cancelled` | bool: the scan ended before its plan completed (user cancel or budget exhaustion, §8) | yes |

- Consequence: `probed = alive + dead` exactly, `filtered ≤ alive`, and no counter can be negative. A finding exists only for an alive endpoint, so a filtered finding is always also `alive`. This holds on every path: a token fire during `finalize` still yields one finding per `Alive` outcome (§3), so a cancelled post-phase never moves an answered endpoint from `alive` to `dead`, and the frontends' row counts still reconcile with `alive` after a cancel.
- Findings exist only for ALIVE endpoints: a finding is one alive endpoint. A module emits no finding row for an endpoint that never answered; core derives `dead` from the probe outcomes (`probed − alive`), counts it internally, and never serializes it. An endpoint whose verdict is `Dead` — never answered, or cancelled mid-flight — is therefore never a row and never `filtered`.
- `totals.filtered` = the number of findings whose `is_filtered()` is true, and `totals.alive` = the number of findings (one per alive endpoint), so `filtered ⊆ alive` holds by construction rather than by a module's counting discipline.
- A module's own `status` column keeps its own vocabulary (warp: `alive` / `cookie` / `torn-down`; cdn: `ok` / `origin-suspect`). Core never interprets it: the shared "filtered" notion is `is_filtered()`, not a status string, so a module can add status values without changing core.
- The SERIALIZED field set is exactly `{probed, alive, filtered, cancelled}` — the object `04-cli.md` §3 mandates and the module specs repeat. `dead` is not part of the JSON/CSV contract. The serialized module id uses the key `module` (the CLI's `{ module, … }` document); the Rust field stays `module_id` and is renamed only in the hand-written `Serialize` impl.
- `wall_time` serializes as an integer number of milliseconds (the impl converts the `Duration`; serde's `{secs, nanos}` default never reaches the document).
- JSON: the projected summary; each finding is an object keyed by the row's column keys.
- CSV: headers are the module's `ColumnSpec` list in declared order; one row per finding, in the same order as the table (ranked ascending, then unranked in stable `finalize` order); each cell is looked up by `key` in the finding's `FindingRow` (`Null`/missing renders empty). Headers never come from the finding type; rendering is `core::output::write_csv` (§4.1).
- `to_row()` emits exactly the keys declared by `columns()`; a missing or extra key is a module bug. There is no `extra` map in v1 (§12 Q1): a fact a module does not produce is `CellValue::Null` in a declared column.
- Table output: the same `ColumnSpec` columns; rows are ranked first in ascending `sort_rank` order, then every unranked finding in stable `finalize` order — unranked rows still render; frontends may hide columns but not invent module data.
- Modules that want extra human columns extend their frontend table config, not the core model.

### 4.1 Shared output writer

Formatting lives in core, once, so the CLI and the GUI emit identical bytes:

```rust
// core::output
pub fn write_csv(columns: &[ColumnSpec], rows: &[FindingRow], out: &mut impl Write) -> Result<(), OutputError>;
pub fn write_json(summary: &ScanSummary, out: &mut impl Write) -> Result<(), OutputError>;
```

BOTH frontends call `core::output`; no frontend formats rows itself. The rendering rules are fixed here because they are the cross-frontend contract:
- A `CellValue::Number` renders with at most 3 decimals and trailing zeros trimmed — `12`, `12.5`, `12.125`. `CellValue::Text` is written as-is; `Bool` renders `true`/`false`; `Null` renders empty in CSV and `null` in JSON.
- The line terminator is `"\n"` on every platform, never CRLF, so two writers produce identical bytes.
- CSV headers are the declared `ColumnSpec` list in declared order, one row per finding, cells looked up by `key` (`Null`/missing renders empty); JSON is the serialized summary (§4), each finding keyed by its column keys.

This writer is a P0 deliverable (`06-qa.md` §4): CLI↔GUI byte parity is tested against one implementation, never against two formatters.

## 5. Module system

A module is a crate exposing one stateless `ScannerModule` instance + metadata:

```rust
pub trait ScannerModule: Send + Sync + 'static {
    fn meta(&self) -> &ModuleMeta;
    fn subcommands(&self) -> &[SubcommandSpec];
    fn run_command(&self, id: &'static str, args: &ModuleOptions, cancel: &CancellationToken)
        -> BoxFuture<'_, Result<(), ScanError>>;
    fn options_spec(&self) -> &OptionsSpec;
    fn columns(&self) -> &[ColumnSpec];
    fn plan(&self, opts: &ModuleOptions) -> Result<TargetPlan, ScanError>;
    fn probe(&self, opts: &ModuleOptions) -> Arc<dyn Probe>;
    fn finalize<'a>(&'a self, outcomes: &'a [ProbeOutcome], opts: &'a ModuleOptions,
                    cancel: &'a CancellationToken)
        -> BoxFuture<'a, Result<Vec<Box<dyn ModuleFinding>>, ScanError>>;
}

pub struct ModuleMeta {
    pub id: ModuleId,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub cli_name: Option<&'static str>,                // optional CLI override; None => "<id>-scan"
    pub range_policy: RangePolicy,                     // §6
    pub actions: &'static [ActionSpec],                // module-declared UI actions, rendered generically
    pub dialogs: &'static [DialogSpec],                // module-declared dialogs; a dialog's confirm runs run_command
}

pub struct ActionSpec {
    pub id: &'static str,                              // stable, module-owned; the GUI dispatches on it
    pub label: &'static str,                           // display text in the action row
    pub kind: ActionKind,
}

pub enum ActionKind {
    OpenDialog { dialog: &'static str },   // names a DialogSpec in meta().dialogs; the GUI hosts it generically
}

pub struct DialogSpec {
    pub id: &'static str,                              // stable, module-owned; ActionSpec::OpenDialog names it
    pub title: &'static str,                           // dialog title
    pub fields: &'static [OptionSpec],                 // generic form fields (the OptionSpec kinds OptionsSpec declares)
    pub confirm_command: &'static str,                 // run_command id executed on confirm
}
```

`meta().range_policy` is the module's single declared policy; plan validation consults it, never a global allowlist. `meta().cli_name` is the optional override for the default CLI subcommand name `<id>-scan`: `Some(name)` replaces it, `None` lets the CLI frontend derive `<id>-scan`. It changes nothing else — the config table (`[modules.<id>]`) and the subcommand group prefix stay keyed by `id` (`04-cli.md` §2). `subcommands()` on the trait is the only accessor and the single source of module-owned CLI commands (no copy on `ModuleMeta`); v1 has one group, `warp identity` (`02-warp-scan.md` §5), declared as its commands `identity register` (`--force`), `identity import <file>` and `identity show`, each with the `args` it accepts.

`meta().actions` is how a module-specific action reaches the shared GUI: the generic module view renders every declared `ActionSpec` in its action row and implements `OpenDialog { dialog }` by name — the id must name a `DialogSpec` in `meta().dialogs`, which the GUI hosts generically — so adding a module, or an action to one (warp's "Identity…"), requires zero frontend edits (Vision P1). A command-style action (a button that runs a command with no dialog) is a future extension point; v1 declares none, and no frontend resolves one. `subcommands()` stays the CLI-facing declaration and `dialogs` the GUI-facing one, and neither implies the other: both execute through `run_command`.

**Command and dialog execution.** Declarations do not execute: `subcommands()` and `meta().dialogs` say what a module provides, and `run_command(id, args, cancel)` is the one trait entry that runs a declared command or a dialog's confirm. BOTH frontends dispatch by declared id/name only. The CLI builds the nested command tree from each `SubcommandSpec.name`'s path segments, renders each command's declared `args`, resolves the invocation into a `ModuleOptions` and calls `run_command(name, &args, &token)` — so no CLI code parses `identity import`'s file path or `identity register --force`, and no CLI code holds a per-command arm. The GUI renders a declared dialog as a generic form from `DialogSpec.fields` (the same `OptionSpec` kinds the option form uses) and, on confirm, calls `run_command(confirm_command, &args, &token)`. A command is not a scan: it takes no `TargetPlan`, emits no `ScanEvent`s and sits outside the Plan → Run → Finalize pipeline; it reports failure through the same typed seam — a missing or malformed argument is the module's own `OptionsInvalid` (exit 1), and identity bootstrap failures are `Network { .. }` / `RegistrationRejected { .. }` / `IdentityMissing` (§8). Because the module validates its own argument surface, the frontends encode neither which args exist nor which are required. And because dispatch is by declared id alone, neither frontend names a module crate in a command or dialog path: `cftool warp identity import <file>`, `register --force` and the GUI's identity confirm all reach the warp crate through `run_command`, which is what keeps §5.1's removal edit set sufficient.

Options travel per call, never through module state: `plan`, `probe` and `finalize` all receive the scan's `ModuleOptions`, and `finalize` also receives the scan's `CancellationToken` — its post-probe phases can run for tens of seconds, so cancellation must reach it (§3.3); when the token fires, `finalize` returns one finding per `Alive` outcome it was given — the post-phase columns the cancelled phase would have computed left `CellValue::Null` — never a prefix and never an error: a `Dead` outcome alone produces no finding, so a cancelled post-phase cannot turn an answered endpoint into `dead`. The registry therefore holds one stateless instance per module — no factory and no per-scan construction. `finalize` is the single outcomes → findings step: a module's post-probe phases run inside it (cdn's filter + download; warp's tier-2 validation when enabled), which is why it is async. `finalize` returns the module's findings, each with its module-set `sort_rank`; core awaits it, then orders them. A module with no post-probe phase returns its findings directly.

The seam's vocabulary — each is a short data type, not a trait:

```rust
pub struct ModuleOptions {
    pub values: BTreeMap<String, OptionValue>,       // one entry per option the frontend resolved; a ModuleResolved key is absent unless set
}

pub enum OptionValue { Bool(bool), Number(f64), Text(String), List(Vec<String>) }

pub struct ProbeTarget {                // one endpoint: the probe unit
    pub addr: IpAddr,
    pub port: u16,
}

pub struct ScanTarget {                 // one address and the ports to try on it
    pub addr: IpAddr,
    pub ports: Vec<u16>,
}

pub struct TargetPlan {
    pub recipe: GenerationRecipe,              // how addresses are generated; kept when the plan is built on demand
    pub targets: Vec<ScanTarget>,              // resolved addresses + ports; empty when the recipe generates them on demand
    pub plan_endpoints: usize,                 // endpoint total (resolved AND recipe-only): the progress denominator
    pub stop_on_first_answer: bool,            // module policy: skip an address's remaining ports once one endpoint answered
    pub attempts_per_probe: u8,                // 1..=4, module policy
    pub per_attempt_timeout: Duration,         // each attempt's cap, module-selected (cdn: 1 s tcp / 2 s http)
    pub probe_overhead: Duration,              // the module's fixed per-probe cost (warm-up connection, noise delay)
    pub per_probe_timeout: Duration,           // probe_overhead + attempts_per_probe × per_attempt_timeout
    pub charged_packet_count: u64,             // endpoints × per-probe packet cost (formula below)
}

pub struct ProbeBudget {
    pub per_attempt_timeout: Duration,  // each attempt gets this
    pub max_attempts: u8,              // 1..=4
    pub overhead: Duration,             // the module's fixed per-probe cost (warm-up connection, noise delay)
    pub cancel: CancellationToken,      // the scan's token: observe it at every await
}

pub struct OptionsSpec {
    pub entries: &'static [OptionSpec],
}

pub struct OptionSpec {
    pub key: &'static str,
    pub kind: OptionKind,           // bool | number(min,max) | enum(variants) | text | list
    pub default: OptionDefault,
    pub help: &'static str,
}

pub enum OptionDefault {
    Static(OptionValue),   // always present in ModuleOptions
    ModuleResolved,        // absent unless the user set it; the module derives it from the other options
}

pub enum OptionKind {
    Bool,
    Number { min: f64, max: Option<f64> },   // max: None = no upper bound
    Enum { variants: &'static [&'static str] },
    Text,
    List,
}

pub struct SubcommandSpec {
    pub name: &'static str,                            // command path under the module's group: "identity import"
    pub description: &'static str,
    pub args: &'static [OptionSpec],                   // the command's declared arguments (Text: the file path; Bool: --force)
}
```

`ModuleOptions` is the module's option map — key → typed value — built by the frontend from `OptionsSpec` (CLI from flags + config file; GUI from the spec-driven form); the module converts it into its own typed options struct. It is the single value the frontend produces and the module consumes, which closes the CLI and GUI paths onto one seam. **Credentials are not options:** a module that needs one loads it itself when it builds its probe — the warp module's `probe()` construction reads `identity.json` from the resolved config dir (`02-warp-scan.md` §5), and an identity that is missing after plan validation passed is a typed `IdentityMissing` failure, never a silent probe with no key. `ScanTarget` is one address plus the ports to try on it; the runner expands addresses × ports into `ProbeTarget` endpoints, and `ProbeTarget { addr, port }` is the probe unit. `TargetPlan` is what `plan()` returns and core validates (§3), and it is SELF-SUFFICIENT for the run: it carries `plan_endpoints` (resolved and recipe-only alike) and the timing inputs (`per_attempt_timeout`, `probe_overhead`, `per_probe_timeout`), so the runner builds each probe's `ProbeBudget` from the plan (`attempts_per_probe` → `max_attempts`, plus `per_attempt_timeout`, `probe_overhead` and the scan token) and the frontend never has to know a module's per-mode timings. `ProbeBudget` is what the runner hands each probe — per-attempt timeout, attempt cap, fixed overhead, and the scan's cancellation token; the whole probe is capped by the one normative formula in the probe time model (`overhead + max_attempts × per_attempt_timeout`). `SubcommandSpec` declares one module-owned CLI command: `name` is its path under the module's group, `args` its declared argument surface — the same `OptionSpec` field kinds the option form uses — so the CLI renders arguments it was told about and never hard-codes one.

**Charged packet count.** `charged_packet_count` = endpoints × (attempts per probe + warm-ups per probe + noise datagrams per probe) — the total packets the scan may emit, where endpoints is the total endpoint count the plan will probe — Σ `targets[i].ports.len()` when the plan is resolved, or the recipe's equivalent when addresses are generated on demand. `attempts_per_probe` is a plan field; `warmups_per_probe` and `noise_datagrams_per_probe` are module policy constants. It is the only charged counter; the ceiling is 250,000 packets per scan (§9). Examples: cdn default = 5,956 × (4 + 1 + 0) = 29,780; warp pinned/light = 3,584 × (1 + 1 + 5) = 25,088; warp full at 3,584 addresses = 3,584 × 54 × (1 + 1 + 0) = 387,072 packets with noise off, 1,354,752 at the default `light` and 10,063,872 at `heavy` — so `full` at the default address count is rejected by the packet ceiling whatever the noise preset, and at `heavy` the figure is 10,063,872 → rejected.

**Probe time model (normative).** A probe's wall-clock cost has three parts: the module's fixed `overhead` (its warm-up connection(s) and any noise-delay phase), plus up to `max_attempts` attempts, each bounded by `per_attempt_timeout`. The probe's total cap is `overhead + max_attempts × per_attempt_timeout`, and the plan's `per_probe_timeout` IS that cap. Every time figure in the set — the feasibility floor, the module specs' per-probe costs, the budget examples — uses this one model. Worked examples: cdn tcp = overhead 1 s (one warm-up connect) + 4 × 1 s = **5 s per probe** → 30 address-waves × 5 s = 150 s floor; warp pinned/light = overhead 25 ms (5 noise datagrams × 5 ms) + 1 × 1.5 s ≈ **1.525 s per probe** → 7 waves ≈ 10.7 s; warp heavy = overhead 7.5 s (50 datagrams × 150 ms) + 1 × 1.5 s = **9 s per probe** → 7 waves = 63 s. The noise preset therefore charges the scan twice — packets (the datagrams) and time (the delay) — and the two must agree.

**How `--timeout` reaches the plan.** The frontend resolves the wall-clock ceiling (CLI `--timeout`, GUI field, or the `[engine]` default per `04-cli.md` §2) and writes it into the module's `scan-timeout` option inside `ModuleOptions` before calling `plan()`. Every module declares that option in its `OptionsSpec`; `plan()` validates the module's feasibility floor against that value, so an impossible ceiling is rejected before any socket opens.

**How `concurrency` reaches the runner.** `concurrency` is a RESERVED option key: every module declares it in its `OptionsSpec` with a static default (warp 512, ceiling 4,096; cdn 200, ceiling 512 in tcp mode and 200 in http mode), and it is the ONLY declared source of `ProbeRunnerConfig.concurrency` — `TargetPlan` carries no concurrency field and `OptionsSpec` is generic, so nothing else can supply it. The frontend resolves the value as the module's CLI option → `[modules.<id>] concurrency` → `[engine] concurrency` → the module's declared default (`04-cli.md` §2), and passes it as `ProbeRunnerConfig.concurrency`. The ceilings have one runtime owner each, and the module's is the one that fires: the MODULE's option-validation step owns its declared ceiling and returns `OptionsInvalid` (exit 1) from `plan()` — the first of §3's four checks — so a value above a module's ceiling never reaches core, and core never reports a module's declared bound. Core's 4,096 is a RUNNER-CONSTRUCTION BACKSTOP, not a plan-time check: the `ProbeRunner` constructor rejects `concurrency > 4_096` with `InvalidPlan` (exit 3) before any probe or socket exists, and no plan-time check can see the value at all because `TargetPlan` carries no concurrency field. So 5,000 is the module's `OptionsInvalid`, not core's error; 513 is inside warp's declared 4,096 ceiling (accepted there) but above cdn's 512 tcp / 200 http ceiling, so the cdn module returns `OptionsInvalid`. The backstop is unreachable through a correctly declared module, which is why it has its own test that constructs the runner directly — C7, §11.

`OptionsSpec` is the declarative option schema above — entries of kind bool / number(min,max) / enum(variants) / text / list, each with a static or a module-resolved default and help text. It drives: CLI `--help` generation, config-file parsing, and GUI form layout. Modules own one typed options struct and a `From<ModuleOptions>` conversion; the spec is generated alongside it via a small macro or written by hand in v1 (decision: hand-written spec + typed struct, kept adjacent in one file; macro deferred until the third module makes the boilerplate real).

**Option defaults.** `OptionDefault::Static(value)` means the key is always present in `ModuleOptions`. `OptionDefault::ModuleResolved` means the key is ABSENT from `ModuleOptions` unless the user set it, and the module computes the effective value from the other resolved options; the help text documents the derivation. A module declares either form per key, and the frontend must not guess a missing key — absent means module-resolved, never "use a default". The distinction exists because one static value cannot express a per-mode default: cdn's `attempts` is 4 in tcp mode and 1 in http mode, and its `timeout-per-probe` is 1000 ms tcp / 2000 ms http; with a static default, `cdn-scan --mode http` would receive `attempts = 4`, which that module's typed options declare an error. Module-resolved keys stay user-settable (flag, config, GUI field) and are still validated by the option spec.

### 5.1 Registration

Frontends declare the modules they ship in one place:

```rust
// crates/cli/src/modules.rs
pub fn registry() -> ModuleRegistry {
    ModuleRegistry::new()
        .register(cftool_warp::WarpModule::default())
        .register(cftool_cdn::CdnModule::default())
}
```

`ModuleRegistry` is a `Vec<Box<dyn ScannerModule>>` keyed by `ModuleId` with duplicate-id rejection. That is the entire integration surface — but a removal still touches every place the build names the crate. Vision S4 (remove a module) means exactly: delete the crate directory (`crates/modules/<id>/`), drop its entry from the workspace manifest's `members`, remove each frontend's `Cargo.toml` dependency line, and remove each frontend's `.register(...)` line. There is no fifth edit: both frontends dispatch a module's commands and dialogs by declared id only (§5), so neither carries a per-module arm or a dialog body that names the crate, and removing the registration removes the command group, the dialogs and the sidebar entry together. The evidence for a removal is `cargo build --release` succeeding for both frontends plus the remaining module running a scan; the gates cannot be green exactly as before, because the module-specific tests that name the removed module are removed with it.

Dynamic loading (cdylib plugins) is **out of scope for v1** (Vision N4): the maintenance cost (ABI stability, cross-platform loading, security surface) buys nothing while all modules ship in-repo. The trait boundary above is the seam; if a plugin story is ever wanted, module construction moves behind a loaded-library shim without touching frontends' consumption code.

### 5.2 Test seams

`cftool-core` owns the probe-source injection point. `ProbeSource` is a one-method core trait:

```rust
pub trait ProbeSource: Send + Sync + 'static {
    fn probe(&self, opts: &ModuleOptions) -> Arc<dyn Probe>;
}
```

Its DEFAULT implementation — the source a production scan passes — wraps the scan's module and returns `module.probe(opts)` (§5's `ScannerModule::probe`), so the engine has exactly one way to obtain a probe and a module is never bypassed: no second engine path exists. The start surface takes the `ProbeSource` (§3, Runner surface), never a raw `Arc<dyn Probe>`. `ScriptedProbeSource` overrides `probe` to replay scripted probe responses — its probes satisfy the same `Probe` bound — so the mock substitutes at exactly one seam. The core mock **types** are always compiled — they are ordinary core code, not feature-gated. The cargo feature `mock` on `cftool-core` enables only the SCRIPT LOADER (reading the JSON script file); the CLI's own `mock` feature forwards it and compiles the `--mock` flag; the GUI enables core's `mock` as a dev-dependency. Production builds carry the types, but no flag and no loader exist in them.

The scripted identity is NOT core's: the identity artifact and the `IdentityMissing` gate belong to the warp module (`02-warp-scan.md` §5), so the scripted identity is a WARP-side seam — `cftool-warp` provides it and its own `mock` feature enables the scripted-identity loader. Core must not depend on a module (§1), and does not.

The script defines the target set and the probe responses: `{ targets: [{ ip, port, verdict, rtt_ms }] }`, where `{ ip, port }` is a `ProbeTarget` and `verdict` is `alive` | `cookie` | `dead` (mirroring `AliveKind` / `DeadReason`). `rtt_ms` is REQUIRED for `alive`, OMITTED for `cookie` (a cookie reply has no RTT) and optional for `dead`. The scripted probe consumes wall-clock `rtt_ms` per target before returning its verdict — bounded by the scan's resolved ceiling — so a scripted scan is fast by default and can be made to outlast a ceiling on purpose.

When a script is supplied it REPLACES the plan's target set AFTER plan validation has run: the replacement rewrites `targets` AND `plan_endpoints` together — the progress denominator (§3.1) — so `totals.probed` equals the script's target count (the CLI's T3 scenario expects 3). The rewrite is performed by the `mock`-gated script loader in core — the same helper the CLI's `--mock` path and the GUI test wiring both call — returning a plan whose `targets` and `plan_endpoints` come from the script. The packet-budget and feasibility-floor checks are evaluated PRE-replacement, because they describe the plan the module would really run: a scripted scan's charged count is the plan's, not the script's. A plan-validation-only check (the CLI's T2 positive half) needs only the scripted identity.

**Command and dialog runtime.** `run_command` is a module entry outside the scan pipeline, so it reuses the frontends' existing async path and nothing new: the CLI awaits the returned future on its own multi-thread runtime and maps the `ScanError` to §8's exit codes; the GUI runs it on the dedicated engine runtime of §3.3 — never GPUI's executor — and bridges the result onto the UI context with `cx.update` (an inline error on failure, the dialog's confirm disabled while the command is in flight), the same bridge scans use. A command takes NO scan permit: only `ProbeRunner::run` acquires the process-wide slot (§3.3), so `run_command` never returns `Busy` and never holds the slot against a scan. The frontend creates the per-command `CancellationToken` and trips it when the dialog is dismissed or the window closes; the module observes it at every await (registration transport, identity-file write) and returns `Err(Cancelled)` rather than a silent partial success.

## 6. Range sources & policies

Two named policies, both subsets of Cloudflare-owned space:

| Policy | Membership | Source |
| --- | --- | --- |
| `RangePolicy::PublishedCdn` | Cloudflare's published CDN lists (15 IPv4 + 7 IPv6 CIDRs) | `cloudflare.com/ips-v4` + `cloudflare.com/ips-v6` (`03-cdn-scan.md` §2.1), fetched by `core::ranges::RangeSource`; compiled-in snapshot fallback |
| `RangePolicy::WarpEndpointPools` | the WARP endpoint-pool superset: 14 IPv4 /24s + 2 IPv6 /48s (`02-warp-scan.md` §2.1) | compiled-in snapshot only — Cloudflare publishes no list for these |

- Each module declares exactly one policy in `ModuleMeta::range_policy`. Core validates a plan against that declared policy, never against one global list: the WARP default plan contains `8.x` /24s that are Cloudflare-owned but absent from the published CDN lists, so a global published-list allowlist would reject the warp module's own default. (The v6 pools are not such a case: `2606:4700:d0::/48` sits inside `2606:4700::/32`, which is in Cloudflare's published v6 list.)
- **Outer gate (Vision P4/N3):** the union of both policies is the documented Cloudflare-owned boundary, and `core::ranges::is_cloudflare_owned(IpAddr)` answers membership in it. It is NOT a second runtime plan check: a module's declared policy is by definition a subset of the union, so a union test run after the declared-policy test could never reject anything the first one admitted — the second runtime check and its `AllowlistViolation` arm are not built. Core validates the DECLARED policy only, at runtime, before any probe. The subset relation is a test-time invariant instead: the P0 range-policy test (C1, §11) asserts it over the two compiled snapshots — every CIDR in either snapshot is inside the union, and an address outside both is outside it — so the union function stays pinned to the compiled policies and a snapshot edited away from them fails the tests rather than passing a plan. The union remains the boundary a new module's policy must sit inside.
- `RangeSource` refreshes only `PublishedCdn`: HTTP fetch, 24 h cache under the platform config dir, compiled snapshot on network failure with a `Log` event (scanning works offline). `WarpEndpointPools` is snapshot-only; no refresh exists.
- Module-level custom input (`--cidr` in warp, `02-warp-scan.md` §2.2) is validated against the same declared policy; the union is not a way around a module's narrower policy.

## 7. Configuration

Layered, later wins: compiled defaults → user config file (`cftool.toml` in platform config dir; GUI may write it) → frontend overrides (CLI flags / GUI fields). Serde-typed; unknown keys are errors (typo protection), with the module-section lifecycle below as the one exception.

| Table | Contents |
| --- | --- |
| `[engine]` | default concurrency, output dir, scan-timeout defaults |
| `[modules.<id>]` | one table per registered module; keys are that module's options |
| `[gui]` | GUI-owned keys exactly: `theme` (mode: `dark`/`light`), `window` (geometry: size, position), `last_module` (last selected module id) |

- **Stale module sections:** a `[modules.<id>]` table whose `<id>` is not in the current build's registry is ignored with a `Log` warning; it does not fail the config. This keeps Vision S4 workable — removing a module crate must not break an existing `cftool.toml`.
- **Unknown keys:** a key not present in a *registered* module's option spec, or an unknown `[engine]`/`[gui]` key, is an error naming the key. A typo'd module id is therefore a warning, not a hard failure.
- Both frontends parse the whole file; `[gui]` has no CLI effect.
- **Secrets:** the WARP identity private key (`identity.json`, `02-warp-scan.md` §5) is v1's only credential: 0600 on unix, user-profile ACL on Windows. It never appears in `cftool.toml`, JSON/CSV output, logs, or the GUI (`identity show` masks it, `04-cli.md` §7).

## 8. Error model

- `ScanError`: typed enum at the core/module boundary, `thiserror`-derived, converts to `anyhow` at frontend edges: `InvalidPlan`, `AllowlistViolation`, `OptionsInvalid { .. }`, `Network { .. }`, `Cancelled`, `BudgetExhausted`, `Busy`, `ResultLaneOverflow { capacity }`, `Internal { .. }`, `IdentityMissing`, `RegistrationRejected { status, api_version }`.
- **Exit codes (authoritative — `04-cli.md` §6 is the CLI's copy of this table):**

  | `ScanError` | Exit code |
  | --- | --- |
  | `OptionsInvalid { .. }` | 1 |
  | `InvalidPlan`, `AllowlistViolation`, `IdentityMissing` | 3 |
  | `Network { .. }`, `Busy`, `RegistrationRejected { status, api_version }` | 4 |
  | `Cancelled` | 5 |
  | `BudgetExhausted` | 5 |
  | `ResultLaneOverflow { capacity }`, `Internal { .. }` | 6 |

  Usage and argument-parse errors are the argument parser's own exit 2 and are never a `ScanError`. GUI presents recoverable errors inline/notifications, never panics. Exit 5 is derived from `totals.cancelled == true` whenever a summary exists — a user cancel and a budget exhaustion both terminate in `Done` with `Ok(summary)` (§3.1). The `Cancelled` and `BudgetExhausted` rows are the no-summary fallback, not the primary path: `Err(Cancelled)` when the result-lane receiver was dropped (the consumer went away) before `Done` could be enqueued, and `Err(BudgetExhausted)` when the budget expired before any summary could be produced. Neither applies to a normal cancel or budget stop.
- **Output-write failure:** a failure writing an output file (CLI `--csv`, GUI export) is a CLI/runtime error → exit 4, surfaced as `error: could not write <path> — <cause>`. It is not a `ScanError` variant: the scan succeeded, only the sink failed.
- **Budget exhaustion (`BudgetExhausted`):** reaching the engine's wall-clock `total_budget` ends the scan with the partial results collected so far and `totals.cancelled = true`; it is a graceful stop, not a crash, and it terminates through `Done`, not `Failed` (§3.1). The runner returns `Err(BudgetExhausted)` ONLY when the budget expires before any summary could be produced; otherwise the stop is `Ok(summary)` with `totals.cancelled = true`. Exit code 5 — the same code as a user cancel, derived from `totals.cancelled == true` when a summary exists and from the error variant only as the no-summary fallback (§3.1) — and a `Log` line names the reason ("total budget exhausted", with elapsed time and the budget).
- **Plan-time floor:** if the resolved scan ceiling (the engine's `total_budget`; resolved by the frontend and written into `scan-timeout` per §5) is below the plan's feasibility floor, `plan()` returns `InvalidPlan` (exit 3) before anything is probed. The floor is the MODULE's own (`02-warp-scan.md` §6, `03-cdn-scan.md` §5): `scan-timeout ≥ ceil(addresses / concurrency) × ports_per_address × per_probe_timeout`, where `per_probe_timeout` is the probe's total cap under the probe time model (§5). Core defines no second formula.
- **`Network { .. }`:** produced by registration transport failures — DNS resolution, connect, or TLS handshake — in the warp module's identity bootstrap (`02-warp-scan.md` §5); exit 4. Probe-level network failures are not this variant: they are `DeadReason`s on a `ProbeOutcome`.
- `IdentityMissing` and `RegistrationRejected` are raised by the warp module's identity bootstrap (`02-warp-scan.md` §5), not by the engine; both carry a user-facing remedy — register an identity, or check whether Cloudflare moved the API version.
- **Panics:**
  - A panic in a spawned tokio task surfaces as `JoinError`, not as a catch. The runner maps a `JoinError` to `ScanError::Internal` and fails the scan.
  - Probe futures are wrapped in `catch_unwind` (`futures::FutureExt`, `AssertUnwindSafe`); a panic becomes `Dead { reason: DeadReason::Internal }` for that endpoint, counted dead, and the scan continues. One bad probe never kills a scan.

## 9. Concurrency & performance budgets

Vision §3.1 sets the volume budget; architecture enforces it. Module specs own defaults, which may go lower but never higher.

| Budget | Limit | Enforcement |
| --- | --- | --- |
| In-flight endpoint slots (concurrent probes) | module default ≤ 512; user override up to the hard engine ceiling 4,096 | the module's option validation owns its declared ceiling and returns `OptionsInvalid` (§5) — the value never reaches core; core's runner-construction backstop rejects `concurrency > 4_096` with `InvalidPlan` before any probe opens (§5, tested by C7, §11); 4,096 is a hard cap, not a target |
| Charged packets per scan | 250,000 packets | plan validation rejects `charged_packet_count > 250_000` before probing (`InvalidPlan`); count = endpoints × (attempts per probe + warm-ups per probe + noise datagrams per probe) (§5) |
| Result-lane endpoint bound | ≤ 64,512 endpoints (65,536 result-lane events minus the 1,024-event control/log allowance) | enforced at plan time by EACH module's `plan()` — `02-warp-scan.md` §6 and `03-cdn-scan.md` §5 — with `InvalidPlan` (exit 3); `ResultLaneOverflow` is the runtime backstop only; a plan at exactly 65,536 endpoints is already over the line, so the allowance is never spent on more endpoints |
| Attempts per probe | 1..4 measurement tries of one endpoint, recorded in `ProbeOutcome.attempts` (an `AttemptRecord`); failure handling is module policy (cdn: 4 in tcp mode and 1 in http mode, each failed try = loss; warp: one try); probes per target = the ports tried for that address | `ProbeBudget` caps in-probe tries; the `AttemptRecord` reports `tries_made`, `tries_succeeded` and each successful try's RTT on every outcome |
| Scans per process | 1 | one process-wide scan permit (§3.3); a second start returns `Busy` |
| HTTP-mode in-flight endpoint slots | ≤ 200 | Vision §3.1; the cdn module's `concurrency` option validation (`OptionsInvalid`) |
| Download/throughput phase | ≤ 512 MB per scan, ≤ 10 candidates | Vision §3.1; enforced by the cdn-scan speed phase |
| Resident addresses | 100,000 | larger plans keep the generation recipe; addresses are produced on demand, never all materialized |

- Module defaults: warp 512 UDP in-flight endpoint slots (`02-warp-scan.md` §6); cdn 200 TCP (`03-cdn-scan.md` §4) — both are the module's `concurrency` option default (§5). HTTP-mode in-flight endpoint slots are ≤ 200 per Vision §3.1. No module default exceeds 512.
- Sockets: probes use `socket2`-backed non-blocking connects (TCP) / `tokio::net::UdpSocket` (UDP) to keep task count ≈ endpoint count without OS thread blowup.
- Memory: a 100k-address plan stays < 150 MB RSS (addresses stored as packed `IpAddr` vecs plus port lists). Outcomes ARE buffered: core retains one `ProbeOutcome` per probe for `finalize`, at a realistic bound of ≤ 250 B per outcome — the struct plus `AttemptRecord.try_rtts_us` (a heap `Vec<u32>`), `AliveDetail.facts` (a `BTreeMap` allocation for any non-empty map) and allocator overhead, not the bare struct size. At the 250,000-packet ceiling (each endpoint costs at least one packet, so at most 250,000 outcomes) that is 250,000 × 250 B ≈ 62 MB; at the real endpoint cap (65,536 minus the control-event allowance, ~64,512 endpoints) it is ~64,512 × 250 B ≈ 16 MB. Both stay inside the < 150 MB line. The result lane (§3.1) is separate and bounded at 65,536 events.

## 10. Platform notes

- Windows-first (qmahyar's daily driver), but all code stays `std`/tokio portable; GUI uses gpui-kit which supports Windows/macOS/Linux. No `windows`-crate dependencies outside optional `#[cfg(windows)]` polish (e.g. fast fallback to default config dir), with exactly one permitted exception: a console control handler that counts Ctrl-C presses and exits 130 on the second (`04-cli.md` §4). The default console handler exits with `STATUS_CONTROL_C_EXIT`, not 130, so the second-Ctrl-C exit contract needs this handler; it is the only `windows`-crate use in v1.
- Config dir: `dirs` crate convention (`%APPDATA%\cftool` on Windows).
- **Reference toolchain (the floor):** the workspace is built, and the five gates run, on **rustc/cargo 1.97.1**, and that observed toolchain is the declared floor (`rust-version = "1.97"` in the workspace manifest). gpui-kit, gpui-base and gpui-component 0.9.1 declare no `rust-version`, so the GUI's 0.9 line adds no MSRV of its own and the reference toolchain is the only floor this spec states. That floor does not reach the registration client's fallback stack: `wreq` 0.16.3 with BoringSSL requires MSRV 1.98, above the reference toolchain, so on it the fallback is unavailable and the primary path (stock rustls behind `register()`, `02-warp-scan.md` §5) MUST succeed; adopting the fallback is a toolchain upgrade first, not a Cargo change.

## 11. Testing strategy (architecture level)

- core:
  - plan validation per declared policy: a synthetic plan over the compiled `WarpEndpointPools` snapshot validates against that policy (the module's own default plan is asserted by the warp module's test, `02-warp-scan.md` §9 T3, P1 — core may not depend on a module, §1); a synthetic published-CDN plan validates against `PublishedCdn`; an address outside the DECLARED policy → `AllowlistViolation` — there is no runtime union check, so no union disjunct exists. The union relation is the same test's P0 companion assertion, over the two compiled snapshots: every CIDR in either snapshot is inside `is_cloudflare_owned`, and an address outside both is outside it — a build-time/test-time invariant, not a per-target probe-time guard (§6). `charged_packet_count` > 250,000 → `InvalidPlan`. Validation order is contract: a plan that fails both the range check and the packet budget returns `AllowlistViolation`.
  - range parsing (v4 + v6; a failed `PublishedCdn` refresh falls back to the compiled snapshot with a `Log`, never a hard failure).
  - event stream: result-lane ordering; `Done` only after the last `Result`; progress lane coalesces to at most one `ProgressSnapshot` per 50 ms and never blocks the runner; a full result lane aborts with `ResultLaneOverflow` instead of blocking; receiver drop → `Cancelled`; a user cancel and a budget stop both end in `Done` with `totals.cancelled = true` and resolve the scan future `Ok`.
  - cancellation: the engine commits to observing the cancellation token at every await, so a scan of an unreachable range stops within **500 ms** of the token firing (Vision S5's cancel bound); the token is observed by the runner, by the probe futures (via `ProbeBudget.cancel`) and by `finalize`, and the runner's own cancellation path is bounded by the same figure. A cancel during `finalize` still yields one finding per `Alive` outcome it was given, post-phase columns null — `alive` and `probed = alive + dead` are unchanged by the cancel.
  - one scan at a time: a second concurrent start returns `Busy`.
  - **C7 — runner-construction backstop:** constructing `ProbeRunner` with `concurrency = 5000` returns `InvalidPlan` before any probe is started and before any socket opens. This is not a plan-time check (`TargetPlan` carries no concurrency field, §5) and no v1 CLI path delivers a value above a module's ceiling to core — both modules' option validation rejects it first as `OptionsInvalid` (exit 1) — so the test exercises the engine cap directly at the constructor.
  - **C8 — `stop_on_first_answer` skip:** with scripted probes, an address whose port list contains an answering port mid-list: the runner skips the remaining ports (neither probed nor counted; `probed` counts only dispatched endpoints); a plan with the flag unset probes all ports. This is the only runner behavior with v1 product reachability (warp `full` mode) and previously zero coverage.
  - **C9 — cancel during `finalize`:** fire the token mid-`finalize` over a synthetic outcome set with a scripted download phase: every `Alive` outcome still yields exactly one finding, post-phase columns are `CellValue::Null`, `probed = alive + dead` holds, `totals.filtered` reflects only filters that completed, and the stop completes within 500 ms — the guarantee §3/§3.3/§5 commit to, previously tested nowhere.
  - panic containment: a panicking probe yields `Dead { reason: DeadReason::Internal }` and the scan continues.
- modules: pure tests on `finalize` folding (synthetic outcomes, via `ScriptedProbeSource`, §5.2); probe tests gated behind `#[ignore]` live-network tests run explicitly.
- frontends:
  - CLI integration: `cftool warp-scan --cidr 192.0.2.0/31` → plan/validation error (exit 3, `04-cli.md` §6), the message names the allowlist/endpoint-pool rule, and no network traffic occurs (`--cidr` is defined in `02-warp-scan.md` §2.2).
  - output parity: one fixture summary, exported by BOTH frontends' real export calls — `cftool::export::save_csv` / `save_json` from the CLI's lib target and the GUI's own export — yields byte-identical CSV and JSON, `\n` line endings included. Both wrappers call `core::output` (§4.1), and the test lives in `cftool-gui`, whose dev-dependency on the `cftool` lib (§1) is what lets it compare two real frontend exports instead of calling core twice.
  - GUI: `#[gpui_kit::test]` view tests + one smoke flow (see `05-gui.md` §7).

## 12. Open questions

- Q1 — **closed: no `extra` map in v1.** `FindingRow` carries exactly the module's declared `ColumnSpec` keys; a tier-2-style field a module does not produce (e.g. warp `colo`/`exit_country` with tier 2 off) is a `CellValue::Null` cell of a declared column (`02-warp-scan.md` §8). Extra JSON fields would be schema drift; the declared columns are the schema.
- Q2 — **closed: the `time` crate's `OffsetDateTime`**, serialized RFC 3339 in JSON; no wasm needs in v1, so no `SystemTime` fallback. The export-parity fixture (§11) is fixed on this format before P0.
