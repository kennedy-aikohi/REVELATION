use anyhow::Result;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::analysis::{api_extractor, api_score};
use crate::hashing::sha256_file;
use crate::report::{score_finding, FileFinding, ScanReport};
use crate::yara_engine::YaraEngine;

pub struct ScanOptions {
    pub root: PathBuf,
    pub threads: usize,
    pub compute_hashes: bool,
    pub max_file_size_mb: u64,
    pub progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
}

pub fn scan_files(engine: &YaraEngine, opts: ScanOptions) -> Result<ScanReport> {
    let started = now_utc();

    let max_bytes = opts.max_file_size_mb.saturating_mul(1024 * 1024);
    let scanned = Arc::new(AtomicU64::new(0));
    let matched = Arc::new(AtomicU64::new(0));
    let denied = Arc::new(AtomicU64::new(0));
    let skipped = Arc::new(AtomicU64::new(0));

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(&opts.root).follow_links(false).into_iter() {
        match entry {
            Ok(e) => {
                if !e.file_type().is_file() {
                    continue;
                }
                paths.push(e.path().to_path_buf());
            }
            Err(err) => {
                let s = err.to_string().to_lowercase();
                if s.contains("access is denied") || s.contains("permission denied") {
                    denied.fetch_add(1, Ordering::Relaxed);
                } else {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    let total = paths.len() as u64;

    if let Some(cb) = &opts.progress {
        cb(0, total);
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads)
        .build()?;

    let findings: Vec<FileFinding> = pool.install(|| {
        paths
            .par_iter()
            .filter_map(|p| {
                let meta = std::fs::metadata(p).ok()?;
                let size = meta.len();

                if size == 0 || size > max_bytes {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    let s = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(cb) = &opts.progress {
                        cb(s, total);
                    }
                    return None;
                }

                let yara_hits = match engine.scan_file(p) {
                    Ok(v) => v,
                    Err(_) => {
                        denied.fetch_add(1, Ordering::Relaxed);
                        let s = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(cb) = &opts.progress {
                            cb(s, total);
                        }
                        return None;
                    }
                };

                let api = match api_extractor::extract_imports(p) {
                    Ok(imports) => Some(api_score::score(&imports)),
                    Err(_) => None,
                };

                let s = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(cb) = &opts.progress {
                    cb(s, total);
                }

                if yara_hits.is_empty() {
                    return None;
                }

                matched.fetch_add(1, Ordering::Relaxed);

                let sha256 = if opts.compute_hashes {
                    sha256_file(p).ok()
                } else {
                    None
                };

                let score = score_finding(&yara_hits);

                Some(FileFinding {
                    path: p.clone(),
                    sha256,
                    size,
                    yara: yara_hits,
                    score,
                    api,
                })
            })
            .collect()
    });

    let finished = now_utc();

    Ok(ScanReport {
        started_utc: started,
        finished_utc: finished,
        scanned_files: scanned.load(Ordering::Relaxed),
        matched_files: matched.load(Ordering::Relaxed),
        findings,
    })
}

fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}
