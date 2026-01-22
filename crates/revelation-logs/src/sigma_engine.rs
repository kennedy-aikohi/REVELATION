use std::path::Path;

use serde_json::Value;
use walkdir::WalkDir;

use sigma_rust::{check_rule, event_from_json, rule_from_yaml, Rule};

use crate::timeline::TimelineHit;

pub struct SigmaEngine {
    pub rules: Vec<Rule>,
}

impl SigmaEngine {
    pub fn load_from_dir(dir: &Path) -> anyhow::Result<Self> {
        let mut rules = Vec::new();

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }

            let p = entry.path();
            let ext = p
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            if ext != "yml" && ext != "yaml" {
                continue;
            }

            let txt = std::fs::read_to_string(p)?;
            if let Ok(rule) = rule_from_yaml(&txt) {
                rules.push(rule);
            }
        }

        Ok(Self { rules })
    }

    pub fn match_events(&self, events: &[Value]) -> Vec<TimelineHit> {
        let mut hits = Vec::new();

        for ev in events {
            let json_str = ev.to_string();
            let event = match event_from_json(&json_str) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for rule in &self.rules {
                if !check_rule(rule, &event) {
                    continue;
                }

                let timestamp = ev
                    .pointer("/Event/System/TimeCreated/@SystemTime")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let channel = ev
                    .pointer("/Event/System/Channel")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let event_id = ev
                    .pointer("/Event/System/EventID")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);

                let computer = ev
                    .pointer("/Event/System/Computer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let record_id = ev
                    .pointer("/Event/System/EventRecordID")
                    .and_then(|v| v.as_u64());

                let sigma_level = rule.level.as_ref().map(|l| format!("{l:?}"));
                let sigma_title = Some(rule.title.clone());

                let sigma_rule = rule
                    .id
                    .as_ref()
                    .map(|s| s.to_string())
                    .or_else(|| Some(rule.title.clone()));

                let message = rule
                    .description
                    .clone()
                    .or_else(|| Some(rule.title.clone()));

                hits.push(TimelineHit {
                    timestamp,
                    source_file: None,

                    computer,
                    channel,
                    event_id,
                    record_id,
                    level: None,

                    sigma_rule,
                    sigma_title,
                    sigma_level,
                    tags: Vec::new(),

                    message,
                    raw: Some(ev.clone()),
                });
            }
        }

        hits
    }
}
