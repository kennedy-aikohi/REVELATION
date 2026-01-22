use eframe::egui;
use revelation_core::report::ScanReport;
use revelation_core::ui::results::{ApiAnalysisResult, ApiCategory};

fn cat_name(cat: &ApiCategory) -> &'static str {
    match cat {
        ApiCategory::ProcessInjection => "Process Injection",
        ApiCategory::CredentialAccess => "Credential Access",
        ApiCategory::Persistence => "Persistence",
        ApiCategory::CommandAndControl => "Command & Control",
        ApiCategory::Exfiltration => "Exfiltration",
        ApiCategory::DefenseEvasion => "Defense Evasion",
        ApiCategory::PrivilegeEscalation => "Privilege Escalation",
        ApiCategory::Networking => "Networking",
        ApiCategory::Crypto => "Crypto",
        ApiCategory::Registry => "Registry",
        ApiCategory::Process => "Process",
        ApiCategory::AntiDebug => "Anti-Debug",
        ApiCategory::Other => "Other",
    }
}

fn sev_badge(ui: &mut egui::Ui, sev: &str) {
    let (bg, fg) = match sev.to_ascii_lowercase().as_str() {
        "high" => (egui::Color32::from_rgb(220, 60, 60), egui::Color32::WHITE),
        "medium" => (egui::Color32::from_rgb(235, 160, 50), egui::Color32::WHITE),
        "low" => (egui::Color32::from_rgb(100, 160, 120), egui::Color32::WHITE),
        _ => (egui::Color32::from_rgb(100, 110, 130), egui::Color32::WHITE),
    };

    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(sev).color(fg).strong());
        });
}

fn api_name_display(a: &revelation_core::ui::results::ApiImport) -> String {
    // ApiImport.name is Option<String> in your build (ordinal imports may have None)
    match a.name.as_ref() {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            if a.is_ordinal {
                "ordinal".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }
}

/// Suspicious APIs tab (scrollable + auto-scroll to Selected section on click)
pub fn suspicious_apis_tab(
    ui: &mut egui::Ui,
    report: &ScanReport,
    search: &mut String,
    selected_idx: &mut Option<usize>,
) {
    // One scroll area for the WHOLE tab (this is what makes everything scroll)
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // --- Search row ---
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Search:")
                        .color(egui::Color32::from_rgb(150, 180, 220)),
                );
                ui.add_sized([260.0, 0.0], egui::TextEdit::singleline(search));
                if ui.button("Clear").clicked() {
                    search.clear();
                    *selected_idx = None;
                }
            });

            ui.add_space(8.0);

            // Build rows from findings that have API analysis
            let q = search.trim().to_lowercase();
            let mut rows: Vec<(usize, String, u32, String, usize, usize)> = Vec::new();

            for (i, f) in report.findings.iter().enumerate() {
                let Some(a) = f.api.as_ref() else { continue; };

                let path = f.path.display().to_string();
                if !q.is_empty() {
                    let hit = path.to_lowercase().contains(&q)
                        || a.severity.to_lowercase().contains(&q);
                    if !hit {
                        continue;
                    }
                }

                rows.push((
                    i,
                    path,
                    a.total_score,
                    a.severity.clone(),
                    a.suspicious_total,
                    a.imports_total,
                ));
            }

            rows.sort_by(|a, b| b.2.cmp(&a.2));

            // --- Header ---
            ui.horizontal(|ui| {
                ui.strong("File");
                ui.add_space(10.0);
                ui.strong("Score");
                ui.add_space(10.0);
                ui.strong("Severity");
                ui.add_space(10.0);
                ui.strong("Suspicious");
                ui.add_space(10.0);
                ui.strong("Imports");
            });
            ui.separator();

            // If a row is clicked, we will scroll to the Selected section this same frame
            let mut scroll_to_selected = false;

            // --- List ---
            for (idx, path, score, sev, sus, imps) in &rows {
                let selected = *selected_idx == Some(*idx);

                ui.horizontal(|ui| {
                    // File (selectable)
                    let row = ui.selectable_label(selected, path);

                    ui.add_space(8.0);
                    // Score badge
                    ui.label(
                        egui::RichText::new(score.to_string())
                            .strong()
                            .color(egui::Color32::from_rgb(230, 230, 240)),
                    );

                    ui.add_space(8.0);
                    sev_badge(ui, sev);

                    ui.add_space(8.0);
                    ui.label(format!("{sus}"));
                    ui.add_space(8.0);
                    ui.label(format!("{imps}"));

                    if row.clicked() {
                        *selected_idx = Some(*idx);
                        scroll_to_selected = true;
                    }
                });

                ui.separator();
            }

            ui.add_space(10.0);

            // --- Selected details ---
            let Some(sel) = *selected_idx else {
                ui.label(
                    egui::RichText::new("Select a file above to view API breakdown.")
                        .color(egui::Color32::from_rgb(190, 205, 225)),
                );
                return;
            };

            let Some(f) = report.findings.get(sel) else { return; };
            let Some(a) = f.api.as_ref() else {
                ui.label("No API analysis for selected item.");
                return;
            };

            // Anchor widget: scroll here when a new selection is made
            let anchor = ui
                .label(
                    egui::RichText::new("Selected")
                        .strong()
                        .color(egui::Color32::from_rgb(150, 180, 220)),
                )
                .rect;

            if scroll_to_selected {
                ui.scroll_to_rect(anchor, Some(egui::Align::Min));
            }

            ui.monospace(f.path.display().to_string());
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("API Risk: {}", a.total_score))
                        .strong()
                        .color(egui::Color32::from_rgb(235, 210, 120)),
                );
                ui.separator();
                ui.label(format!("Severity: {}", a.severity));
                ui.separator();
                ui.label(format!("Suspicious: {}", a.suspicious_total));
                ui.separator();
                ui.label(format!("Imports: {}", a.imports_total));
            });

            ui.add_space(10.0);

            // --- Category breakdown ---
            ui.label(
                egui::RichText::new("Category breakdown")
                    .strong()
                    .color(egui::Color32::from_rgb(150, 180, 220)),
            );

            if a.category_scores.is_empty() {
                ui.label("No category scores.");
            } else {
                for (cat, v) in &a.category_scores {
                    ui.horizontal(|ui| {
                        ui.label(cat_name(cat));
                        let frac = (*v as f32 / 100.0).min(1.0);
                        ui.add_sized([220.0, 16.0], egui::ProgressBar::new(frac));
                        ui.label(format!("{}", v));
                    });
                }
            }

            ui.add_space(10.0);

            // --- Top suspicious DLL!API ---
            ui.label(
                egui::RichText::new("Top suspicious DLL!API")
                    .strong()
                    .color(egui::Color32::from_rgb(150, 180, 220)),
            );

            if a.top.is_empty() {
                ui.label("No suspicious APIs flagged.");
            } else {
                // A little scroll area for the list itself (keeps page usable)
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    for x in a.top.iter().take(50) {
                        let name = api_name_display(&x.api);
                        ui.monospace(format!("{}!{}", x.api.dll, name));
                        ui.label(format!(
                            "{}  Score:{}",
                            cat_name(&x.category),
                            x.score
                        ));
                        for r in &x.reasons {
                            ui.label(format!("• {}", r));
                        }
                        ui.separator();
                    }
                });
            }

            ui.add_space(10.0);
        });
}
