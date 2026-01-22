use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ui::results::ApiAnalysisResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub data_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFinding {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub size: u64,
    pub yara: Vec<YaraRuleMatch>,
    pub score: u32,
    #[serde(default)]
    pub api: Option<ApiAnalysisResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub started_utc: String,
    pub finished_utc: String,
    pub scanned_files: u64,
    pub matched_files: u64,
    pub findings: Vec<FileFinding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Console,
}

pub fn score_finding(yara_matches: &[YaraRuleMatch]) -> u32 {
    if yara_matches.is_empty() {
        return 0;
    }

    let rules_score = (yara_matches.len() as u32).saturating_mul(10);
    let strings_score: u32 = yara_matches
        .iter()
        .map(|m| m.strings.len() as u32)
        .sum::<u32>()
        .saturating_mul(2);

    (50u32 + rules_score + strings_score).min(100)
}
