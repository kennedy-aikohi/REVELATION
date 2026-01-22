use anyhow::{Context, Result};
use std::path::Path;

use yara::{Compiler, MetadataValue, Rules, Yara};

use crate::report::{YaraRuleMatch, YaraStringMatch};

pub struct YaraEngine {
    _yara: Yara,
    rules: Rules,
}

impl YaraEngine {
    pub fn from_rules_file(path: &Path) -> Result<Self> {
        let yara = Yara::new().context("Failed to initialize libyara")?;
        let compiler = Compiler::new().context("Failed to create YARA compiler")?;
        let compiler = compiler
            .add_rules_file(path)
            .with_context(|| format!("Failed to add rules file: {}", path.display()))?;

        let rules = compiler
            .compile_rules()
            .with_context(|| format!("Failed to compile rules: {}", path.display()))?;

        Ok(Self { _yara: yara, rules })
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraRuleMatch>> {
        let results = self
            .rules
            .scan_file(path.to_string_lossy().as_ref(), 5)
            .with_context(|| format!("YARA scan_file failed: {}", path.display()))?;

        Ok(convert_matches(&results))
    }
}

fn convert_matches(results: &[yara::Rule]) -> Vec<YaraRuleMatch> {
    let mut out = Vec::with_capacity(results.len());

    for rule in results {
        let tags = rule.tags.iter().map(|t| t.to_string()).collect();

        let mut meta = Vec::new();
        for md in &rule.metadatas {
            let val = match &md.value {
                MetadataValue::Integer(i) => i.to_string(),
                MetadataValue::Boolean(b) => b.to_string(),
                MetadataValue::String(s) => s.to_string(),
            };
            meta.push((md.identifier.to_string(), val));
        }

        let mut strings = Vec::new();
        for ys in &rule.strings {
            for m in &ys.matches {
                strings.push(YaraStringMatch {
                    identifier: ys.identifier.to_string(),
                    offset: m.offset as u64,
                    data_preview: preview(&m.data),
                });
            }
        }

        out.push(YaraRuleMatch {
            rule: rule.identifier.to_string(),
            namespace: rule.namespace.to_string(),
            tags,
            meta,
            strings,
        });
    }

    out
}

fn preview(data: &[u8]) -> String {
    let take = data.len().min(48);
    let slice = &data[..take];
    if slice.iter().all(|b| matches!(b, 0x20..=0x7E)) {
        String::from_utf8_lossy(slice).to_string()
    } else {
        slice.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
