#![windows_subsystem = "windows"]

mod ui;

use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use eframe::egui;
use revelation_core::{
    export::{export_csv, export_json},
    report::ScanReport,
    rules_update::{update_rules, RuleSource, UpdateOptions, RulesUpdateResult},
    scan::{scan_files, ScanOptions},
    yara_engine::YaraEngine,
};
use revelation_logs::evtx_reader::read_evtx_as_json;
use serde_json::Value;

const AUTHOR_NAME: &str = "Kennedy Aikohi";
const AUTHOR_LINKEDIN: &str = "https://linkedin.com/in/aikohikennedy";
const AUTHOR_GITHUB: &str = "https://github.com/kennedy-aikohi";

#[derive(Clone, Copy, PartialEq)]
enum UiTheme {
    CyberDark,
    CyberBlue,
}

#[derive(Clone, Copy, PartialEq)]
enum CenterTab {
    YaraFindings,
    SuspiciousApis,
}

#[derive(Debug, Clone)]
enum WorkerMsg {
    RuleUpdateDone(u64, RulesUpdateResult),
    Progress(u64, u64, u64),
    ScanDone(u64, ScanReport),
    EvtxDone(u64, Vec<Value>),
    Error(u64, String),
}

struct RevelationApp {
    rules_dir: PathBuf,
    rules_dir_text: String,
    rules_file: PathBuf,

    scan_path: PathBuf,
    scan_path_text: String,

    threads: usize,
    hashes: bool,
    max_mb: u64,

    filter_text: String,
    min_score: u32,

    api_search: String,
    selected_api_idx: Option<usize>,
    center_tab: CenterTab,

    last_rules: Option<RulesUpdateResult>,
    progress_scanned: u64,
    progress_total: u64,
    busy: bool,
    status: String,

    report: Option<ScanReport>,

    evtx_file: PathBuf,
    evtx_file_text: String,
    evtx_limit: u64,
    evtx_events: Option<Vec<Value>>,

    show_about: bool,

    theme: UiTheme,
    job_id: u64,
    active_job: u64,

    tx: mpsc::Sender<WorkerMsg>,
    rx: mpsc::Receiver<WorkerMsg>,

    open_evtx: bool,
}

impl Default for RevelationApp {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();

        let (rules_dir, rules_file) = discover_rules_paths();
        let scan_path = PathBuf::from(r"C:\");

        let mut app = Self {
            rules_dir_text: rules_dir.display().to_string(),
            scan_path_text: scan_path.display().to_string(),

            rules_dir,
            rules_file,

            scan_path,
            threads: 12,
            hashes: true,
            max_mb: 50,

            filter_text: String::new(),
            min_score: 0,

            api_search: String::new(),
            selected_api_idx: None,
            center_tab: CenterTab::YaraFindings,

            last_rules: None,
            progress_scanned: 0,
            progress_total: 0,
            busy: false,
            status: "Ready. Click \"Update Rules (Community)\" first.".into(),

            report: None,

            evtx_file: PathBuf::new(),
            evtx_file_text: String::new(),
            evtx_limit: 50000,
            evtx_events: None,

            show_about: false,

            theme: UiTheme::CyberDark,
            job_id: 0,
            active_job: 0,

            tx,
            rx,

            open_evtx: true,
        };

        if !app.rules_file.is_file() {
            app.status = "Rules missing. Auto-downloading community rules...".into();
            app.start_rules_update(RuleSource::YaraRulesCommunity, false);
        }

        app
    }
}

fn pretty_err(e: &str) -> String {
    let lower = e.to_lowercase();
    if lower.contains("access is denied") || lower.contains("permission denied") {
        "Access denied while scanning. Try running as Administrator or scan a smaller folder.".into()
    } else if lower.contains("cannot find the file") || lower.contains("os error 2") {
        "File not found. Update rules first, or check your rules directory.".into()
    } else if lower.contains("rules compile failed") {
        "Rules compile failed. Try Update Rules again.".into()
    } else {
        e.to_string()
    }
}

fn is_yara_file(p: &Path) -> bool {
    p.is_file()
        && p.extension()
            .and_then(|s| s.to_str())
            .map(|s| {
                let s = s.to_ascii_lowercase();
                s == "yar" || s == "yara"
            })
            .unwrap_or(false)
}

fn pick_preferred_compiled(mut v: Vec<PathBuf>) -> Option<PathBuf> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    for name in ["community_combined.yar", "combined.yar", "combined.yara"] {
        if let Some(p) = here(v.iter(), name) {
            return Some(p.clone());
        }
    }
    Some(v[0].clone())
}

fn here<'a>(mut it: impl Iterator<Item = &'a PathBuf>, name: &str) -> Option<&'a PathBuf> {
    it.find(|p| {
        p.file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case(name))
            .unwrap_or(false)
    })
}

fn detect_compiled_rules(dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    let compiled = dir.join("compiled");
    if compiled.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&compiled) {
            for e in rd.flatten() {
                let p = e.path();
                if is_yara_file(&p) {
                    candidates.push(p);
                }
            }
        }
    }

    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if is_yara_file(&p) {
                candidates.push(p);
            }
        }
    }

    pick_preferred_compiled(candidates)
}

fn discover_rules_paths() -> (PathBuf, PathBuf) {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let mut cur = exe_dir.as_path();
    for _ in 0..6 {
        let candidate = cur.join("rules");
        if candidate.is_dir() {
            if let Some(found) = detect_compiled_rules(&candidate) {
                return (candidate, found);
            }
            let fallback = candidate.join("compiled").join("community_combined.yar");
            return (candidate, fallback);
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }

    let rules_dir = PathBuf::from("rules");
    let rules_file = detect_compiled_rules(&rules_dir)
        .unwrap_or_else(|| rules_dir.join("compiled").join("community_combined.yar"));
    (rules_dir, rules_file)
}

fn apply_fonts(cc: &eframe::CreationContext<'_>) {
    let mut style = (*cc.egui_ctx.style()).clone();

    // Slightly bigger overall so the title/header and UI are clearer
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(24.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(16.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));

    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    cc.egui_ctx.set_style(style);
}

fn apply_theme(ctx: &egui::Context, theme: UiTheme) {
    let mut v = egui::Visuals::dark();

    match theme {
        UiTheme::CyberDark => {
            v.window_fill = egui::Color32::from_rgb(9, 16, 28);
            v.panel_fill = egui::Color32::from_rgb(10, 18, 34);
        }
        UiTheme::CyberBlue => {
            v.window_fill = egui::Color32::from_rgb(8, 14, 26);
            v.panel_fill = egui::Color32::from_rgb(9, 18, 36);
        }
    }

    ctx.set_visuals(v);
}

fn draw_pyramid_logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();

    let top = egui::pos2(rect.center().x, rect.top() + size * 0.14);
    let left = egui::pos2(rect.left() + size * 0.14, rect.bottom() - size * 0.14);
    let right = egui::pos2(rect.right() - size * 0.14, rect.bottom() - size * 0.14);

    painter.add(egui::Shape::convex_polygon(
        vec![top, right, left],
        egui::Color32::from_rgb(245, 200, 90),
        egui::Stroke::new(1.2, egui::Color32::from_gray(120)),
    ));

    // A subtle inner line for depth
    let mid = egui::pos2(rect.center().x, rect.top() + size * 0.55);
    painter.line_segment(
        [left, mid],
        egui::Stroke::new(1.0, egui::Color32::from_gray(110)),
    );
    painter.line_segment(
        [mid, right],
        egui::Stroke::new(1.0, egui::Color32::from_gray(110)),
    );
}

fn draw_header(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(4.0);
        draw_pyramid_logo(ui, 40.0);
        ui.add_space(4.0);

        ui.label(
            egui::RichText::new("REVELATION")
                .size(30.0)
                .strong()
                .color(egui::Color32::from_rgb(220, 230, 255)),
        );

        ui.label(
            egui::RichText::new("Threat analysis console")
                .size(13.5)
                .color(egui::Color32::from_rgb(140, 170, 210)),
        );

        ui.add_space(6.0);
    });
}

impl RevelationApp {
    fn next_job(&mut self) -> u64 {
        self.job_id = self.job_id.wrapping_add(1);
        self.active_job = self.job_id;
        self.active_job
    }

    fn pump_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                WorkerMsg::RuleUpdateDone(job, res) => {
                    if job != self.active_job {
                        continue;
                    }
                    self.status =
                        format!("Rules updated: {} @ {}", res.source_name, res.head_commit);
                    self.rules_file = res.combined_rules_path.clone();
                    self.last_rules = Some(res);
                    self.busy = false;
                }
                WorkerMsg::Progress(job, scanned, total) => {
                    if job != self.active_job {
                        continue;
                    }
                    self.progress_scanned = scanned;
                    self.progress_total = total;
                }
                WorkerMsg::ScanDone(job, report) => {
                    if job != self.active_job {
                        continue;
                    }
                    self.status = format!(
                        "Scan complete. matched_files={} scanned_files={}",
                        report.matched_files, report.scanned_files
                    );
                    self.report = Some(report);
                    self.busy = false;
                }
                WorkerMsg::EvtxDone(job, events) => {
                    if job != self.active_job {
                        continue;
                    }
                    self.status = format!("EVTX parsed. events={}", events.len());
                    self.evtx_events = Some(events);
                    self.busy = false;
                }
                WorkerMsg::Error(job, e) => {
                    if job != self.active_job {
                        continue;
                    }
                    self.status = format!("Error: {}", pretty_err(&e));
                    self.busy = false;
                }
            }
        }
    }

    fn apply_rules_dir_text(&mut self) {
        let p = PathBuf::from(self.rules_dir_text.trim());
        if !p.as_os_str().is_empty() {
            self.rules_dir = p;
            if let Some(found) = detect_compiled_rules(&self.rules_dir) {
                self.rules_file = found;
            }
        }
    }

    fn apply_scan_path_text(&mut self) {
        let p = PathBuf::from(self.scan_path_text.trim());
        if !p.as_os_str().is_empty() {
            self.scan_path = p;
        }
    }

    fn start_rules_update(&mut self, source: RuleSource, accept_elv2: bool) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.status = "Updating rules...".into();

        let job = self.next_job();

        self.apply_rules_dir_text();
        let tx = self.tx.clone();
        let rules_dir = self.rules_dir.clone();

        thread::spawn(move || {
            let opts = UpdateOptions {
                rules_dir,
                accept_elastic_elv2: accept_elv2,
            };

            match update_rules(source, &opts) {
                Ok(res) => {
                    let _ = tx.send(WorkerMsg::RuleUpdateDone(job, res));
                }
                Err(e) => {
                    let _ = tx.send(WorkerMsg::Error(job, format!("{:#}", e)));
                }
            }
        });
    }

    fn start_scan(&mut self) {
        if self.busy {
            return;
        }

        self.apply_scan_path_text();

        if !self.rules_file.is_file() {
            self.status = format!("Rules file not found: {}", self.rules_file.display());
            return;
        }

        self.busy = true;
        self.status = "Scanning...".into();
        self.progress_scanned = 0;
        self.progress_total = 0;

        let job = self.next_job();

        let tx = self.tx.clone();
        let rules_file = self.rules_file.clone();
        let scan_path = self.scan_path.clone();
        let threads = self.threads;
        let hashes = self.hashes;
        let max_mb = self.max_mb;

        let progress_tx = tx.clone();
        let cb = Arc::new(move |scanned: u64, total: u64| {
            let _ = progress_tx.send(WorkerMsg::Progress(job, scanned, total));
        });

        thread::spawn(move || {
            let engine = match YaraEngine::from_rules_file(&rules_file) {
                Ok(e) => e,
                Err(e) => {
                    let _ = tx.send(WorkerMsg::Error(
                        job,
                        format!("Rules compile failed: {:#}", e),
                    ));
                    return;
                }
            };

            let opts = ScanOptions {
                root: scan_path,
                threads,
                compute_hashes: hashes,
                max_file_size_mb: max_mb,
                progress: Some(cb),
            };

            match scan_files(&engine, opts) {
                Ok(report) => {
                    let _ = tx.send(WorkerMsg::ScanDone(job, report));
                }
                Err(e) => {
                    let _ = tx.send(WorkerMsg::Error(job, format!("{:#}", e)));
                }
            }
        });
    }

    fn start_evtx_parse(&mut self) {
        if self.busy {
            return;
        }

        let p = PathBuf::from(self.evtx_file_text.trim());
        if !p.is_file() {
            self.status = "EVTX file not found.".into();
            return;
        }

        self.busy = true;
        self.status = "Parsing EVTX...".into();
        self.evtx_events = None;

        let job = self.next_job();

        let tx = self.tx.clone();
        let limit = self.evtx_limit as usize;

        thread::spawn(move || match read_evtx_as_json(&p, Some(limit)) {
            Ok(events) => {
                let _ = tx.send(WorkerMsg::EvtxDone(job, events));
            }
            Err(e) => {
                let _ = tx.send(WorkerMsg::Error(job, format!("{:#}", e)));
            }
        });
    }

    fn export_report_json(&mut self) {
        if let Some(r) = self.report.as_ref() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Export JSON")
                .set_file_name("revelation_report.json")
                .save_file()
            {
                if let Err(e) = export_json(r, &path) {
                    self.status = format!("Export JSON failed: {:#}", e);
                } else {
                    self.status = format!("Exported JSON: {}", path.display());
                }
            }
        }
    }

    fn export_report_csv(&mut self) {
        if let Some(r) = self.report.as_ref() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Export CSV")
                .set_file_name("revelation_report.csv")
                .save_file()
            {
                if let Err(e) = export_csv(r, &path) {
                    self.status = format!("Export CSV failed: {:#}", e);
                } else {
                    self.status = format!("Exported CSV: {}", path.display());
                }
            }
        }
    }
}

impl eframe::App for RevelationApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(ctx, self.theme);
        self.pump_messages();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            // --- Brand header (centered) ---
            draw_header(ui);

            // --- Theme picker stays on the right (but does NOT hide the title) ---
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_source("theme_picker")
                        .selected_text(match self.theme {
                            UiTheme::CyberDark => "Cyber Dark",
                            UiTheme::CyberBlue => "Cyber Blue",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.theme, UiTheme::CyberDark, "Cyber Dark");
                            ui.selectable_value(&mut self.theme, UiTheme::CyberBlue, "Cyber Blue");
                        });
                });
            });

            ui.add_space(6.0);

            ui.horizontal_wrapped(|ui| {
                ui.label("Rules dir:");
                let resp = ui.add_sized(
                    [420.0, 0.0],
                    egui::TextEdit::singleline(&mut self.rules_dir_text),
                );
                if resp.lost_focus() {
                    self.apply_rules_dir_text();
                    self.rules_dir_text = self.rules_dir.display().to_string();
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Pick…"))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.rules_dir = p;
                        self.rules_dir_text = self.rules_dir.display().to_string();
                        if let Some(found) = detect_compiled_rules(&self.rules_dir) {
                            self.rules_file = found;
                        }
                    }
                }

                ui.separator();

                ui.label("Scan path:");
                let resp = ui.add_sized(
                    [420.0, 0.0],
                    egui::TextEdit::singleline(&mut self.scan_path_text),
                );
                if resp.lost_focus() {
                    self.apply_scan_path_text();
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Pick…"))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.scan_path = p;
                        self.scan_path_text = self.scan_path.display().to_string();
                    }
                }
            });

            ui.horizontal_wrapped(|ui| {
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut self.threads).clamp_range(1..=64));
                ui.checkbox(&mut self.hashes, "SHA-256 for matches");
                ui.label("Max MB/file:");
                ui.add(egui::DragValue::new(&mut self.max_mb).clamp_range(1..=1024));

                ui.separator();

                if ui
                    .add_enabled(!self.busy, egui::Button::new("Update Rules (Community)"))
                    .clicked()
                {
                    self.start_rules_update(RuleSource::YaraRulesCommunity, false);
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Update Rules (Elastic ELv2)"))
                    .clicked()
                {
                    self.start_rules_update(RuleSource::ElasticProtectionsArtifacts, true);
                }

                ui.separator();

                if ui
                    .add_enabled(!self.busy, egui::Button::new("Start Scan"))
                    .clicked()
                {
                    self.start_scan();
                }

                ui.separator();

                if ui
                    .add_enabled(self.report.is_some(), egui::Button::new("Export JSON"))
                    .clicked()
                {
                    self.export_report_json();
                }
                if ui
                    .add_enabled(self.report.is_some(), egui::Button::new("Export CSV"))
                    .clicked()
                {
                    self.export_report_csv();
                }
            });

            ui.horizontal(|ui| {
                let total = self.progress_total.max(1);
                let frac = (self.progress_scanned as f32 / total as f32).min(1.0);
                ui.add_sized(
                    [220.0, 18.0],
                    egui::ProgressBar::new(frac).show_percentage(),
                );
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::SidePanel::left("left_controls")
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                egui::CollapsingHeader::new("EVTX")
                    .default_open(self.open_evtx)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("EVTX:");
                            ui.text_edit_singleline(&mut self.evtx_file_text);
                            if ui
                                .add_enabled(!self.busy, egui::Button::new("Pick…"))
                                .clicked()
                            {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("EVTX", &["evtx"])
                                    .pick_file()
                                {
                                    self.evtx_file = p;
                                    self.evtx_file_text = self.evtx_file.display().to_string();
                                }
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Limit:");
                            ui.add(
                                egui::DragValue::new(&mut self.evtx_limit)
                                    .clamp_range(1..=5_000_000),
                            );
                            if ui
                                .add_enabled(!self.busy, egui::Button::new("Parse"))
                                .clicked()
                            {
                                self.start_evtx_parse();
                            }
                        });
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let a = ui.selectable_label(
                    self.center_tab == CenterTab::YaraFindings,
                    "YARA Findings",
                );
                if a.clicked() {
                    self.center_tab = CenterTab::YaraFindings;
                }
                let b = ui.selectable_label(
                    self.center_tab == CenterTab::SuspiciousApis,
                    "Suspicious APIs",
                );
                if b.clicked() {
                    self.center_tab = CenterTab::SuspiciousApis;
                }
            });

            ui.separator();

            if let Some(events) = &self.evtx_events {
                ui.label(format!("EVTX events loaded: {}", events.len()));
                egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                    for (i, ev) in events.iter().take(5).enumerate() {
                        ui.monospace(format!("#{i}: {ev}"));
                        ui.separator();
                    }
                });
                ui.separator();
            }

            let Some(report) = &self.report else {
                ui.label("No results yet. Update rules, then Start Scan.");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Author:");
                    ui.label(AUTHOR_NAME);
                    ui.label("•");
                    ui.add(egui::Hyperlink::from_label_and_url("LinkedIn", AUTHOR_LINKEDIN));
                    ui.label("•");
                    ui.add(egui::Hyperlink::from_label_and_url("GitHub", AUTHOR_GITHUB));
                });
                return;
            };

            match self.center_tab {
                CenterTab::YaraFindings => {
                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.text_edit_singleline(&mut self.filter_text);
                        ui.separator();
                        ui.label("Min score:");
                        ui.add(egui::DragValue::new(&mut self.min_score).clamp_range(0..=100));
                        if ui.button("Clear").clicked() {
                            self.filter_text.clear();
                            self.min_score = 0;
                        }
                    });

                    ui.separator();

                    let q = self.filter_text.trim().to_lowercase();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for f in &report.findings {
                            if f.score < self.min_score {
                                continue;
                            }

                            if !q.is_empty() {
                                let path_hit = f
                                    .path
                                    .display()
                                    .to_string()
                                    .to_lowercase()
                                    .contains(&q);
                                let rule_hit = f.yara.iter().any(|m| m.rule.to_lowercase().contains(&q));
                                if !(path_hit || rule_hit) {
                                    continue;
                                }
                            }

                            let sev = if f.score >= 85 {
                                "HIGH"
                            } else if f.score >= 60 {
                                "MED"
                            } else {
                                "LOW"
                            };

                            ui.horizontal(|ui| {
                                ui.label(sev);
                                ui.label(f.score.to_string());
                                ui.monospace(f.path.display().to_string());
                            });

                            if let Some(m) = f.yara.first() {
                                ui.monospace(format!("Rule: {}", m.rule));
                                if let Some(s) = m.strings.first() {
                                    ui.monospace(format!(
                                        "{} @0x{:x} \"{}\"",
                                        s.identifier, s.offset, s.data_preview
                                    ));
                                }
                            }

                            ui.separator();
                        }
                    });
                }

                CenterTab::SuspiciousApis => {
                    ui::results::suspicious_apis_tab(
                        ui,
                        report,
                        &mut self.api_search,
                        &mut self.selected_api_idx,
                    );
                }
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Author:");
                ui.label(AUTHOR_NAME);
                ui.label("•");
                ui.add(egui::Hyperlink::from_label_and_url("LinkedIn", AUTHOR_LINKEDIN));
                ui.label("•");
                ui.add(egui::Hyperlink::from_label_and_url("GitHub", AUTHOR_GITHUB));
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("REVELATION")
            .with_inner_size([1200.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        "REVELATION",
        opts,
        Box::new(|cc| {
            apply_fonts(cc);
            Box::<RevelationApp>::default()
        }),
    )
}
