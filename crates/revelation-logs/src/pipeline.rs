use anyhow::{anyhow, Result};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::evtx_reader::read_evtx_as_json;
use crate::timeline::{OutputFormat, Profile};

pub fn update_sigma_rules(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Err(anyhow!("sigma rules dir is empty"));
    }
    fs::create_dir_all(dir)?;
    Ok(())
}

pub fn generate_timeline(
    input_folder: &Path,
    _sigma_dir: &Path,
    out_path: &Path,
    fmt: OutputFormat,
    _profile: Profile,
    limit_per_file: Option<usize>,
    progress: impl Fn(u64, u64) + Send + Sync,
) -> Result<()> {
    if !input_folder.is_dir() {
        return Err(anyhow!("input folder not found: {}", input_folder.display()));
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for e in WalkDir::new(input_folder).follow_links(false).into_iter().flatten() {
        if e.file_type().is_file() {
            if e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("evtx"))
                .unwrap_or(false)
            {
                files.push(e.path().to_path_buf());
            }
        }
    }

    generate_timeline_from_files(
        &files,
        _sigma_dir,
        out_path,
        fmt,
        _profile,
        limit_per_file,
        progress,
    )
}

pub fn generate_timeline_from_files(
    files: &[PathBuf],
    _sigma_dir: &Path,
    out_path: &Path,
    fmt: OutputFormat,
    _profile: Profile,
    limit_per_file: Option<usize>,
    progress: impl Fn(u64, u64) + Send + Sync,
) -> Result<()> {
    if files.is_empty() {
        return Err(anyhow!("no evtx files provided"));
    }

    match fmt {
        OutputFormat::Jsonl => write_jsonl(files, out_path, limit_per_file, progress),
        OutputFormat::Csv => write_csv(files, out_path, limit_per_file, progress),
    }
}

fn write_jsonl(
    files: &[PathBuf],
    out_path: &Path,
    limit_per_file: Option<usize>,
    progress: impl Fn(u64, u64) + Send + Sync,
) -> Result<()> {
    let f = File::create(out_path)?;
    let mut w = BufWriter::new(f);

    let total = files.len() as u64;
    let mut done: u64 = 0;

    for p in files {
        let events: Vec<Value> = read_evtx_as_json(p, limit_per_file)?;
        for ev in events {
            let line = serde_json::to_string(&ev)?;
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        done += 1;
        progress(done, total);
    }

    w.flush()?;
    Ok(())
}

fn write_csv(
    files: &[PathBuf],
    out_path: &Path,
    limit_per_file: Option<usize>,
    progress: impl Fn(u64, u64) + Send + Sync,
) -> Result<()> {
    let f = File::create(out_path)?;
    let mut w = BufWriter::new(f);

    w.write_all(b"time,provider,event_id,computer,channel,message\n")?;

    let total = files.len() as u64;
    let mut done: u64 = 0;

    for p in files {
        let events: Vec<Value> = read_evtx_as_json(p, limit_per_file)?;
        for ev in events {
            let time = pick(&ev, &["Event", "System", "TimeCreated", "SystemTime"]);
            let provider = pick(&ev, &["Event", "System", "Provider", "Name"]);
            let event_id = pick(&ev, &["Event", "System", "EventID"]);
            let computer = pick(&ev, &["Event", "System", "Computer"]);
            let channel = pick(&ev, &["Event", "System", "Channel"]);
            let message = pick_message(&ev);

            write_csv_row(
                &mut w,
                &[&time, &provider, &event_id, &computer, &channel, &message],
            )?;
        }
        done += 1;
        progress(done, total);
    }

    w.flush()?;
    Ok(())
}

fn pick(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for k in path {
        match cur.get(*k) {
            Some(n) => cur = n,
            None => return String::new(),
        }
    }

    match cur {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn pick_message(v: &Value) -> String {
    if let Some(s) = v.get("Message").and_then(|x| x.as_str()) {
        return s.to_string();
    }
    if let Some(s) = v.get("RenderedMessage").and_then(|x| x.as_str()) {
        return s.to_string();
    }
    String::new()
}

fn write_csv_row(w: &mut BufWriter<File>, cols: &[&str]) -> Result<()> {
    for (i, c) in cols.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        write_csv_cell(w, c)?;
    }
    w.write_all(b"\n")?;
    Ok(())
}

fn write_csv_cell(w: &mut BufWriter<File>, s: &str) -> Result<()> {
    let needs_quotes = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if !needs_quotes {
        w.write_all(s.as_bytes())?;
        return Ok(());
    }

    w.write_all(b"\"")?;
    for ch in s.chars() {
        if ch == '"' {
            w.write_all(b"\"\"")?;
        } else {
            let mut buf = [0u8; 4];
            let slice = ch.encode_utf8(&mut buf).as_bytes();
            w.write_all(slice)?;
        }
    }
    w.write_all(b"\"")?;
    Ok(())
}
