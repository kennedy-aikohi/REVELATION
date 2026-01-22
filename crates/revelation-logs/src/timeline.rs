use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    Minimal,
    Standard,
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineHit {
    pub timestamp: Option<String>,
    pub source_file: Option<String>,

    pub computer: Option<String>,
    pub channel: Option<String>,
    pub event_id: Option<u32>,
    pub record_id: Option<u64>,
    pub level: Option<String>,

    pub sigma_rule: Option<String>,
    pub sigma_title: Option<String>,
    pub sigma_level: Option<String>,
    pub tags: Vec<String>,

    pub message: Option<String>,

    #[serde(default)]
    pub raw: Option<Value>,
}

impl Default for TimelineHit {
    fn default() -> Self {
        Self {
            timestamp: None,
            source_file: None,
            computer: None,
            channel: None,
            event_id: None,
            record_id: None,
            level: None,
            sigma_rule: None,
            sigma_title: None,
            sigma_level: None,
            tags: Vec::new(),
            message: None,
            raw: None,
        }
    }
}
