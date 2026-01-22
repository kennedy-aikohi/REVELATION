use anyhow::Result;
use crate::report::ScanReport;
use std::{fs, path::Path};

pub fn export_json(report: &ScanReport, out: &Path) -> Result<()> {
    let s = serde_json::to_string_pretty(report)?;
    fs::write(out, s)?;
    Ok(())
}

pub fn export_csv(report: &ScanReport, out: &Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(out)?;

    wtr.write_record([
        "path", "severity", "score", "size", "sha256",
        "rule", "namespace", "tags",
        "string_id", "string_offset", "string_preview"
    ])?;

    for f in &report.findings {
        let sev = if f.score >= 85 { "HIGH" } else if f.score >= 60 { "MED" } else { "LOW" };
        for m in &f.yara {
            let tags = m.tags.join("|");
            if m.strings.is_empty() {
                wtr.write_record([
                    f.path.display().to_string(),
                    sev.to_string(),
                    f.score.to_string(),
                    f.size.to_string(),
                    f.sha256.clone().unwrap_or_default(),
                    m.rule.clone(),
                    m.namespace.clone(),
                    tags,
                    "".into(), "".into(), "".into()
                ])?;
            } else {
                for s in &m.strings {
                    wtr.write_record([
                        f.path.display().to_string(),
                        sev.to_string(),
                        f.score.to_string(),
                        f.size.to_string(),
                        f.sha256.clone().unwrap_or_default(),
                        m.rule.clone(),
                        m.namespace.clone(),
                        tags.clone(),
                        s.identifier.clone(),
                        format!("0x{:x}", s.offset),
                        s.data_preview.clone(),
                    ])?;
                }
            }
        }
    }

    wtr.flush()?;
    Ok(())
}
