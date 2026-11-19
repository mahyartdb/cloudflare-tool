//! cftool GUI frontend: one generic module view driven by module declarations.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cftool_core::events::{EventSink, ProgressSnapshot, RESULT_LANE_CAPACITY};
use cftool_core::module::{ModuleRegistry, ScannerModule};
use cftool_core::options::{ModuleOptions, OptionValue, OptionsSpec};
use cftool_core::probe::ProbeSource;
use cftool_core::result::{CellValue, ColumnSpec, FindingRow};
use cftool_core::runner::{ProbeRunner, ProbeRunnerConfig};
use gpui_kit::component::Disableable;
use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::*;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

static REGISTRY: OnceLock<ModuleRegistry> = OnceLock::new();

fn registry() -> &'static ModuleRegistry {
    REGISTRY.get_or_init(|| {
        let mut registry = ModuleRegistry::new();
        registry
            .register(Box::new(cftool_warp::WarpModule::new()))
            .expect("register warp");
        registry
            .register(Box::new(cftool_cdn::CdnModule::new()))
            .expect("register cdn");
        registry
    })
}

struct ModuleSource {
    module: Arc<dyn ScannerModule>,
    opts: ModuleOptions,
}

impl ProbeSource for ModuleSource {
    fn probe(&self, _opts: &ModuleOptions) -> Arc<dyn cftool_core::probe::Probe> {
        self.module.probe(&self.opts)
    }
}

struct ScanView {
    selected: usize,
    inputs: Vec<Entity<InputState>>,
    status: String,
    progress: ProgressSnapshot,
    columns: Vec<ColumnSpec>,
    rows: Vec<FindingRow>,
    cancel: Option<CancellationToken>,
    generation: u64,
}

impl ScanView {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut this = Self {
            selected: 0,
            inputs: Vec::new(),
            status: "Ready".to_string(),
            progress: ProgressSnapshot::default(),
            columns: Vec::new(),
            rows: Vec::new(),
            cancel: None,
            generation: 0,
        };
        this.rebuild_inputs(window, cx);
        this
    }

    fn current_module(&self) -> &'static dyn ScannerModule {
        let id = &registry()
            .iter()
            .nth(self.selected)
            .expect("selected module")
            .meta()
            .id;
        registry().get(id).expect("registered")
    }

    fn rebuild_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.inputs.clear();
        let spec = self.current_module().options_spec();
        for entry in spec.entries {
            let default = match &entry.default {
                cftool_core::options::OptionDefault::Static(value) => match value {
                    OptionValue::Bool(value) => value.to_string(),
                    OptionValue::Number(value) => {
                        let rendered = format!("{value:.3}");
                        rendered
                            .trim_end_matches('0')
                            .trim_end_matches('.')
                            .to_string()
                    }
                    OptionValue::Text(text) => text.clone(),
                    OptionValue::List(values) => values.join(","),
                },
                cftool_core::options::OptionDefault::ModuleResolved => String::new(),
            };
            let input = cx.new(|cx| InputState::new(window, cx).default_value(&default));
            self.inputs.push(input);
        }
        self.columns = self.current_module().columns().to_vec();
        self.rows.clear();
        cx.notify();
    }

    fn select(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected == index {
            return;
        }
        self.selected = index;
        self.rebuild_inputs(window, cx);
    }

    fn options(&self, cx: &App) -> ModuleOptions {
        let spec: &OptionsSpec = self.current_module().options_spec();
        let mut options = ModuleOptions::default();
        for (entry, input) in spec.entries.iter().zip(self.inputs.iter()) {
            if let cftool_core::options::OptionDefault::Static(value) = &entry.default {
                options.set(entry.key, value.clone());
            }
            let text = input.read(cx).value();
            if !text.is_empty()
                && let Ok(value) = cftool_cli::parse_option(&entry.kind, &text)
            {
                options.set(entry.key, value);
            }
        }
        options
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        let generation = self.generation + 1;
        self.generation = generation;
        let options = self.options(cx);
        let module: Arc<dyn ScannerModule> = match self.current_module().meta().id.0.as_str() {
            "warp" => Arc::new(cftool_warp::WarpModule::new()),
            _ => Arc::new(cftool_cdn::CdnModule::new()),
        };
        let plan = match module.plan(&options) {
            Ok(plan) => plan,
            Err(error) => {
                self.status = format!("Plan error: {error}");
                cx.notify();
                return;
            }
        };
        let timeout = match options.get("scan-timeout") {
            Some(OptionValue::Number(value)) => *value as u64,
            _ => {
                if module.meta().id.0 == "warp" {
                    90
                } else {
                    180
                }
            }
        };
        let concurrency = match options.get("concurrency") {
            Some(OptionValue::Number(value)) => *value as usize,
            _ => {
                if module.meta().id.0 == "warp" {
                    512
                } else {
                    200
                }
            }
        };
        let runner = match ProbeRunner::new(
            ProbeRunnerConfig {
                concurrency,
                total_budget: Duration::from_secs(timeout),
            },
            options.clone(),
            Arc::clone(&module),
        ) {
            Ok(runner) => runner,
            Err(error) => {
                self.status = format!("Engine error: {error}");
                cx.notify();
                return;
            }
        };
        let (progress_tx, mut progress_rx) = watch::channel(ProgressSnapshot::default());
        let (results_tx, mut results_rx) = mpsc::channel(RESULT_LANE_CAPACITY);
        let events = EventSink {
            progress: progress_tx,
            results: results_tx,
        };
        let source = Arc::new(ModuleSource {
            module: Arc::clone(&module),
            opts: options,
        });
        let cancel = CancellationToken::new();
        self.cancel = Some(cancel.clone());
        self.status = "Running…".to_string();
        self.progress = ProgressSnapshot::default();
        self.rows.clear();
        cx.notify();

        let this = cx.entity().downgrade();
        cx.spawn(async move |_, cx: &mut AsyncApp| {
            while progress_rx.changed().await.is_ok() {
                let snapshot = *progress_rx.borrow();
                this.update(cx, |view: &mut ScanView, cx| {
                    view.progress = snapshot;
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();

        cx.spawn(
            async move |_, _: &mut AsyncApp| {
                while results_rx.recv().await.is_some() {}
            },
        )
        .detach();

        let this = cx.entity().downgrade();
        cx.spawn(async move |_, cx: &mut AsyncApp| {
            let result = runner.run(plan, source, events, cancel.clone()).await;
            this.update(cx, move |view: &mut ScanView, cx| {
                if view.generation != generation {
                    return;
                }
                view.cancel = None;
                match result {
                    Ok(summary) => {
                        view.rows = summary
                            .findings
                            .iter()
                            .filter(|finding| !finding.is_filtered())
                            .map(|finding| finding.to_row())
                            .collect();
                        view.status = format!(
                            "Done — probed {}, alive {}, filtered {}",
                            summary.totals.probed, summary.totals.alive, summary.totals.filtered
                        );
                    }
                    Err(error) => view.status = format!("Scan error: {error}"),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        if let Some(token) = self.cancel.take() {
            token.cancel();
            self.status = "Cancelling…".to_string();
            cx.notify();
        }
    }
}

fn cell_text(value: &CellValue) -> String {
    match value {
        CellValue::Text(text) => text.clone(),
        CellValue::Number(number) => {
            let rendered = format!("{number:.3}");
            let rendered = rendered.trim_end_matches('0').trim_end_matches('.');
            if rendered.is_empty() {
                "0".into()
            } else {
                rendered.to_string()
            }
        }
        CellValue::Bool(value) => value.to_string(),
        CellValue::Null => String::new(),
    }
}

impl Render for ScanView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let modules = registry().iter().collect::<Vec<_>>();
        let running = self.cancel.is_some();
        let mut root = div().flex().flex_col().size_full().gap_3().p_4();

        let mut picker = div().flex().flex_row().gap_2();
        for (index, module) in modules.iter().enumerate() {
            let label = module.meta().name.to_string();
            let selected = index == self.selected;
            picker = picker.child(
                Button::new(("module", index))
                    .label(if selected {
                        format!("[{label}]")
                    } else {
                        label
                    })
                    .primary()
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.select(index, window, cx);
                    })),
            );
        }
        root = root.child(picker);

        for input in &self.inputs {
            root = root.child(Input::new(input));
        }

        let mut actions = div().flex().flex_row().gap_2();
        actions = actions.child(
            Button::new("start")
                .label("Start")
                .primary()
                .disabled(running)
                .on_click(cx.listener(|view, _, _window, cx| view.start(cx))),
        );
        actions = actions.child(
            Button::new("cancel")
                .label("Cancel")
                .disabled(!running)
                .on_click(cx.listener(|view, _, _window, cx| view.cancel(cx))),
        );
        root = root.child(actions);
        root = root.child(format!(
            "{} — {}/{} endpoints, {} alive",
            self.status, self.progress.completed, 0, self.progress.alive
        ));

        for row in &self.rows {
            let text = self
                .columns
                .iter()
                .map(|column| {
                    row.columns
                        .iter()
                        .find(|(key, _)| key == column.key)
                        .map(|(_, value)| cell_text(value))
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join(" | ");
            root = root.child(text);
        }
        root
    }
}

fn main() {
    gpui_kit::application().run(|cx| {
        gpui_kit::init(cx);
        cx.open_window(WindowOptions::default(), |window, cx| {
            cx.new(|cx| ScanView::new(window, cx))
        })
        .expect("open window");
    });
}
