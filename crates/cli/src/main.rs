//! cftool command-line frontend.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cftool_cli::{
    config_path, config_template, exit_code, export_csv, export_json, load_config, parse_option,
};
use cftool_core::error::ScanError;
use cftool_core::events::{EventSink, RESULT_LANE_CAPACITY, ScanEvent};
use cftool_core::module::{ModuleRegistry, ScannerModule};
use cftool_core::options::{ModuleOptions, OptionDefault, OptionKind, OptionsSpec, SubcommandSpec};
use cftool_core::probe::{Probe, ProbeSource};
use cftool_core::result::ModuleId;
use cftool_core::result::{CellValue, ColumnSpec, FindingRow};
use cftool_core::runner::{ProbeRunner, ProbeRunnerConfig};
use clap::{Arg, ArgAction, ArgMatches, Command};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

struct ModuleSource {
    module: Arc<dyn ScannerModule>,
    opts: ModuleOptions,
}

impl ProbeSource for ModuleSource {
    fn probe(&self, _opts: &ModuleOptions) -> Arc<dyn Probe> {
        self.module.probe(&self.opts)
    }
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn add_option_args(command: Command, entries: &[cftool_core::options::OptionSpec]) -> Command {
    let mut command = command;
    for spec in entries {
        let mut arg = Arg::new(spec.key)
            .long(spec.key)
            .help(spec.help)
            .required(false);
        arg = match spec.kind {
            OptionKind::Bool => arg.action(ArgAction::SetTrue),
            OptionKind::Number { .. } => arg.value_parser(clap::value_parser!(f64)),
            OptionKind::Enum { variants } => arg.value_parser(
                clap::builder::PossibleValuesParser::new(variants.iter().copied()),
            ),
            OptionKind::Text | OptionKind::List => arg.action(ArgAction::Set),
        };
        command = command.arg(arg);
    }
    command
}

fn add_subcommand_paths(mut group: Command, specs: &[SubcommandSpec]) -> Command {
    for spec in specs {
        let parts: Vec<&str> = spec.name.split_whitespace().collect();
        group = add_path(group, &parts, spec);
    }
    group
}

fn add_path(mut group: Command, parts: &[&str], spec: &SubcommandSpec) -> Command {
    if parts.is_empty() {
        return group;
    }
    let name = parts[0];
    let existing = group
        .get_subcommands()
        .find(|candidate| candidate.get_name() == name)
        .cloned();
    let child = existing.unwrap_or_else(|| Command::new(leak(name.to_string())));
    let child = if parts.len() == 1 {
        child.about(spec.description)
    } else {
        child
    };
    let child = add_path(child, &parts[1..], spec);
    let child = if parts.len() == 1 {
        add_option_args(child, spec.args)
    } else {
        child
    };
    if group
        .get_subcommands()
        .any(|candidate| candidate.get_name() == name)
    {
        let slot = group
            .get_subcommands_mut()
            .find(|candidate| candidate.get_name() == name)
            .expect("subcommand present");
        *slot = child;
    } else {
        group = group.subcommand(child);
    }
    group
}

fn build_cli(registry: &ModuleRegistry) -> Command {
    let mut command = Command::new("cftool")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Modular Cloudflare scanning toolkit")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .global(true),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(Arg::new("csv").long("csv").value_name("PATH").global(true))
        .arg(
            Arg::new("show-filtered")
                .long("show-filtered")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64))
                .global(true),
        );

    #[cfg(feature = "mock")]
    {
        command = command.arg(
            Arg::new("mock")
                .long("mock")
                .value_name("SCRIPT")
                .value_name("PATH")
                .global(true),
        );
    }

    command = command.subcommand(Command::new("modules").about("List registered modules"));
    command = command.subcommand(
        Command::new("config")
            .about("Configuration helpers")
            .subcommand(Command::new("init").about("Write a config template"))
            .subcommand(Command::new("path").about("Print the config path")),
    );
    command = command.subcommand(
        Command::new("ranges")
            .about("Range helpers")
            .subcommand(Command::new("refresh").about("Use the compiled Cloudflare snapshot")),
    );

    for module in registry.iter() {
        let meta = module.meta();
        let id = meta.id.0.clone();
        let scan_name = meta
            .cli_name
            .map(str::to_string)
            .unwrap_or_else(|| format!("{id}-scan"));
        command = command.subcommand(add_option_args(
            Command::new(leak(scan_name)).about(meta.description),
            module.options_spec().entries,
        ));
        let ops = add_subcommand_paths(
            Command::new(leak(id.clone())).about(format!("{id} commands")),
            module.subcommands(),
        );
        command = command.subcommand(ops);
    }
    command
}

fn options_from_matches(spec: &OptionsSpec, matches: &ArgMatches) -> ModuleOptions {
    let mut options = ModuleOptions::default();
    for entry in spec.entries {
        if let OptionDefault::Static(value) = &entry.default {
            options.set(entry.key, value.clone());
        }
        let value = match entry.kind {
            OptionKind::Bool => matches
                .get_one::<bool>(entry.key)
                .copied()
                .map(OptionValue::Bool),
            _ => matches
                .get_one::<String>(entry.key)
                .and_then(|text| parse_option(&entry.kind, text).ok()),
        };
        if let Some(value) = value {
            options.set(entry.key, value);
        }
    }
    options
}

use cftool_core::options::OptionValue;

fn cell_text(value: &CellValue) -> String {
    match value {
        CellValue::Text(text) => text.clone(),
        CellValue::Number(number) => {
            let rendered = format!("{number:.3}");
            let rendered = rendered.trim_end_matches('0').trim_end_matches('.');
            if rendered.is_empty() {
                "0".to_string()
            } else {
                rendered.to_string()
            }
        }
        CellValue::Bool(value) => value.to_string(),
        CellValue::Null => String::new(),
    }
}

fn rows_for(
    summary: &cftool_core::result::ScanSummary,
    _columns: &[ColumnSpec],
    show_filtered: bool,
) -> Vec<FindingRow> {
    summary
        .findings
        .iter()
        .filter(|finding| show_filtered || !finding.is_filtered())
        .map(|finding| finding.to_row())
        .collect()
}

fn render_table(columns: &[ColumnSpec], rows: &[FindingRow]) {
    let mut builder = tabled::builder::Builder::default();
    builder.push_record(
        columns
            .iter()
            .map(|column| column.header.to_string())
            .collect::<Vec<String>>(),
    );
    for row in rows {
        builder.push_record(
            columns
                .iter()
                .map(|column| {
                    row.columns
                        .iter()
                        .find(|(key, _)| key == column.key)
                        .map(|(_, value)| cell_text(value))
                        .unwrap_or_default()
                })
                .collect::<Vec<String>>(),
        );
    }
    let mut table = builder.build();
    table.with(tabled::settings::Style::markdown());
    println!("{table}");
}

fn module_id_for_scan(registry: &ModuleRegistry, name: &str) -> Option<ModuleId> {
    registry
        .iter()
        .find(|module| {
            let meta = module.meta();
            meta.cli_name == Some(name)
                || (meta.cli_name.is_none() && format!("{}-scan", meta.id.0) == name)
        })
        .map(|module| module.meta().id.clone())
}

async fn run_scan(
    registry: &ModuleRegistry,
    module: &dyn ScannerModule,
    matches: &ArgMatches,
    _name: &str,
) -> i32 {
    let mut options = options_from_matches(module.options_spec(), matches);
    let config = match load_config(
        matches
            .get_one::<String>("config")
            .map(PathBuf::from)
            .as_deref(),
    ) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    if let Some(table) = config.modules.get(&module.meta().id.0) {
        for (key, value) in table {
            if options.get(key).is_none()
                && let Some(text) = value.as_str()
                && let Some(parsed) = module
                    .options_spec()
                    .entries
                    .iter()
                    .find(|entry| entry.key == key)
                    .and_then(|entry| parse_option(&entry.kind, text).ok())
            {
                options.set(key, parsed);
            }
        }
    }
    let timeout = matches
        .get_one::<u64>("timeout")
        .copied()
        .or_else(|| {
            options.get("scan-timeout").and_then(|value| match value {
                OptionValue::Number(number) => Some(*number as u64),
                _ => None,
            })
        })
        .unwrap_or_else(|| match module.meta().id.0.as_str() {
            "warp" => 90,
            _ => 180,
        });
    options.set("scan-timeout", OptionValue::Number(timeout as f64));

    let plan = match module.plan(&options) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("error: {error}");
            return exit_code(&error);
        }
    };
    #[cfg(feature = "mock")]
    let mut mock_targets: Option<Vec<cftool_core::mock::ScriptTarget>> = None;
    #[cfg(feature = "mock")]
    let plan = {
        let mut plan = plan;
        if let Some(path) = matches.get_one::<String>("mock") {
            match cftool_core::mock::load_script(path).and_then(|script| {
                mock_targets = Some(script.targets.clone());
                cftool_core::mock::apply_script(&mut plan, &script);
                Ok(())
            }) {
                Ok(()) => {}
                Err(error) => {
                    eprintln!("error: {error}");
                    return 1;
                }
            }
        }
        plan
    };

    let concurrency = options
        .get("concurrency")
        .and_then(|value| match value {
            OptionValue::Number(number) => Some(*number as usize),
            _ => None,
        })
        .unwrap_or_else(|| {
            if module.meta().id.0 == "warp" {
                512
            } else {
                200
            }
        });
    let config = ProbeRunnerConfig {
        concurrency,
        total_budget: Duration::from_secs(timeout),
    };
    let module_arc: Arc<dyn ScannerModule> = registry
        .iter()
        .find(|candidate| candidate.meta().id == module.meta().id)
        .map(|candidate| {
            // Rebuild an Arc from the registry is not possible (it owns Box); use a local proxy below.
            let _ = candidate;
            Arc::new(ProxyModule {
                id: module.meta().id.clone(),
            }) as Arc<dyn ScannerModule>
        })
        .unwrap_or_else(|| {
            Arc::new(ProxyModule {
                id: module.meta().id.clone(),
            })
        });
    let _ = module_arc;

    // The runner needs an Arc<dyn ScannerModule>; build one directly from the known id.
    let runner_module: Arc<dyn ScannerModule> = match module.meta().id.0.as_str() {
        "warp" => Arc::new(cftool_warp::WarpModule::new()),
        _ => Arc::new(cftool_cdn::CdnModule::new()),
    };
    let runner = match ProbeRunner::new(config, options.clone(), Arc::clone(&runner_module)) {
        Ok(runner) => runner,
        Err(error) => {
            eprintln!("error: {error}");
            return exit_code(&error);
        }
    };

    let (_progress_tx, _progress_rx) =
        watch::channel(cftool_core::events::ProgressSnapshot::default());
    let (results_tx, mut results_rx) = mpsc::channel(RESULT_LANE_CAPACITY);
    let events = EventSink {
        progress: _progress_tx,
        results: results_tx,
    };
    let source: Arc<dyn ProbeSource> = {
        #[cfg(feature = "mock")]
        if let Some(targets) = mock_targets {
            Arc::new(cftool_core::mock::ScriptedProbeSource::new(targets))
        } else {
            Arc::new(ModuleSource {
                module: Arc::clone(&runner_module),
                opts: options,
            })
        }
        #[cfg(not(feature = "mock"))]
        Arc::new(ModuleSource {
            module: Arc::clone(&runner_module),
            opts: options,
        })
    };
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_task.cancel();
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        }
    });

    let result = runner.run(plan, source, events, cancel.clone()).await;
    signal.abort();
    let mut events_log = Vec::new();
    while let Ok(event) = results_rx.try_recv() {
        events_log.push(event);
    }
    if matches.get_flag("verbose") {
        for event in &events_log {
            if let ScanEvent::Log { level, message } = event {
                eprintln!("[{level:?}] {message}");
            }
        }
    }

    match result {
        Ok(summary) => {
            let show_filtered = matches.get_flag("show-filtered");
            let rows = rows_for(&summary, module.columns(), show_filtered);
            let write_result = if matches.get_flag("json") {
                export_json(&summary, &mut std::io::stdout())
            } else if let Some(path) = matches.get_one::<String>("csv") {
                if path == "-" {
                    export_csv(module.columns(), &rows, &mut std::io::stdout())
                } else {
                    match std::fs::File::create(path) {
                        Ok(mut file) => export_csv(module.columns(), &rows, &mut file),
                        Err(error) => {
                            eprintln!("error: could not write {path} - {error}");
                            return 4;
                        }
                    }
                }
            } else {
                render_table(module.columns(), &rows);
                Ok(())
            };
            if let Err(error) = write_result {
                eprintln!("error: could not write output - {error}");
                return 4;
            }
            if summary.totals.cancelled { 5 } else { 0 }
        }
        Err(error) => {
            eprintln!("error: {error}");
            exit_code(&error)
        }
    }
}

struct ProxyModule {
    id: ModuleId,
}
impl ScannerModule for ProxyModule {
    fn meta(&self) -> &cftool_core::module::ModuleMeta {
        static META: std::sync::OnceLock<cftool_core::module::ModuleMeta> =
            std::sync::OnceLock::new();
        let _ = &self.id;
        META.get_or_init(|| cftool_core::module::ModuleMeta {
            id: ModuleId("proxy".into()),
            name: "proxy",
            version: "0",
            description: "",
            cli_name: None,
            range_policy: cftool_core::module::RangePolicy::PublishedCdn,
            actions: &[],
            dialogs: &[],
        })
    }
    fn subcommands(&self) -> &[SubcommandSpec] {
        &[]
    }
    fn run_command(
        &self,
        _id: &'static str,
        _args: &ModuleOptions,
        _cancel: &CancellationToken,
    ) -> cftool_core::probe::BoxFuture<'_, Result<(), ScanError>> {
        Box::pin(async { Err(ScanError::Internal("not a real module".into())) })
    }
    fn options_spec(&self) -> &OptionsSpec {
        static SPEC: OptionsSpec = OptionsSpec { entries: &[] };
        &SPEC
    }
    fn columns(&self) -> &[ColumnSpec] {
        &[]
    }
    fn plan(&self, _opts: &ModuleOptions) -> Result<cftool_core::target::TargetPlan, ScanError> {
        Err(ScanError::Internal("not a real module".into()))
    }
    fn probe(&self, _opts: &ModuleOptions) -> Arc<dyn Probe> {
        Arc::new(NeverProbe)
    }
    fn finalize<'a>(
        &'a self,
        _outcomes: &'a [cftool_core::probe::ProbeOutcome],
        _opts: &'a ModuleOptions,
        _cancel: &'a CancellationToken,
    ) -> cftool_core::probe::BoxFuture<
        'a,
        Result<Vec<Box<dyn cftool_core::result::ModuleFinding>>, ScanError>,
    > {
        Box::pin(async { Ok(Vec::new()) })
    }
}
struct NeverProbe;
impl Probe for NeverProbe {
    fn probe<'a>(
        &'a self,
        target: cftool_core::target::ProbeTarget,
        _budget: cftool_core::target::ProbeBudget,
    ) -> cftool_core::probe::BoxFuture<'a, cftool_core::probe::ProbeOutcome> {
        Box::pin(async move {
            cftool_core::probe::ProbeOutcome {
                target,
                verdict: cftool_core::probe::ProbeVerdict::Dead {
                    reason: cftool_core::probe::DeadReason::Internal,
                },
                attempts: cftool_core::probe::AttemptRecord {
                    tries_made: 1,
                    tries_succeeded: 0,
                    try_rtts_us: Vec::new(),
                },
                started_at: time::OffsetDateTime::now_utc(),
            }
        })
    }
}

#[tokio::main]
async fn main() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(cftool_warp::WarpModule::new()))
        .expect("register warp");
    registry
        .register(Box::new(cftool_cdn::CdnModule::new()))
        .expect("register cdn");
    let command = build_cli(&registry);
    let matches = command.get_matches();

    let code = match matches.subcommand() {
        Some(("modules", _)) => {
            for module in registry.iter() {
                let meta = module.meta();
                println!("{}\t{}\t{}", meta.id.0, meta.version, meta.description);
            }
            0
        }
        Some(("config", sub)) => match sub.subcommand() {
            Some(("path", _)) => {
                println!(
                    "{}",
                    config_path(
                        matches
                            .get_one::<String>("config")
                            .map(PathBuf::from)
                            .as_deref()
                    )
                    .display()
                );
                0
            }
            Some(("init", _)) => {
                let path = config_path(
                    matches
                        .get_one::<String>("config")
                        .map(PathBuf::from)
                        .as_deref(),
                );
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, config_template()) {
                    Ok(()) => {
                        println!("wrote {}", path.display());
                        0
                    }
                    Err(error) => {
                        eprintln!("error: could not write {}: {error}", path.display());
                        4
                    }
                }
            }
            _ => 2,
        },
        Some(("ranges", sub)) => match sub.subcommand() {
            Some(("refresh", _)) => {
                println!("cftool uses the compiled Cloudflare snapshot; no refresh is needed.");
                0
            }
            _ => 2,
        },
        Some((name, sub)) => {
            if let Some((id, _spec)) = find_ops(&registry, name, sub) {
                let module = registry.get(&id).expect("module present");
                let options = options_from_matches(module.options_spec(), sub);
                let cancel = CancellationToken::new();
                let command_name = op_command_name(module, sub);
                match module
                    .run_command(leak(command_name), &options, &cancel)
                    .await
                {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("error: {error}");
                        exit_code(&error)
                    }
                }
            } else if let Some(id) = module_id_for_scan(&registry, name) {
                let module = registry.get(&id).expect("module present");
                run_scan(&registry, module, sub, name).await
            } else {
                2
            }
        }
        None => 2,
    };
    std::process::exit(code);
}

fn find_ops<'a>(
    registry: &'a ModuleRegistry,
    name: &str,
    _matches: &ArgMatches,
) -> Option<(ModuleId, &'a dyn ScannerModule)> {
    registry
        .iter()
        .find(|module| module.meta().id.0 == name)
        .map(|module| (module.meta().id.clone(), module))
}

fn op_command_name(module: &dyn ScannerModule, matches: &ArgMatches) -> String {
    let mut parts = Vec::new();
    let mut cursor = Some(matches);
    while let Some(m) = cursor {
        match m.subcommand() {
            Some((name, sub)) => {
                parts.push(name.to_string());
                cursor = Some(sub);
            }
            None => cursor = None,
        }
    }
    let declared: Vec<&str> = module.subcommands().iter().map(|spec| spec.name).collect();
    let joined = parts.join(" ");
    declared
        .into_iter()
        .find(|name| name.ends_with(&joined) || joined.ends_with(name))
        .map(str::to_string)
        .unwrap_or(joined)
}
