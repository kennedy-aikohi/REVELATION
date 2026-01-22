use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    ProcessInjection,
    CredentialAccess,
    Persistence,
    CommandAndControl,
    Exfiltration,
    DefenseEvasion,
    PrivilegeEscalation,
    Networking,
    Crypto,
    Registry,
    Process,
    AntiDebug,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiImport {
    pub dll: String,
    pub name: Option<String>,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
}

impl ApiImport {
    /// Lowercased dll name (used by api_classifier)
    pub fn dll_lower(&self) -> String {
        self.dll.to_ascii_lowercase()
    }

    /// Lowercased import name (if present)
    pub fn name_lower(&self) -> String {
        self.name
            .as_ref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default()
    }

    /// Display form for GUI listing
    pub fn display_name(&self) -> String {
        match (&self.name, self.is_ordinal, self.ordinal) {
            (Some(n), _, _) => n.clone(),
            (None, true, Some(o)) => format!("#{}", o),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFinding {
    pub api: ApiImport,
    pub category: ApiCategory,
    pub score: u32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAnalysisResult {
    pub total_score: u32,
    pub severity: String,
    pub imports_total: usize,
    pub suspicious_total: usize,
    pub top: Vec<ApiFinding>,
    pub category_scores: Vec<(ApiCategory, u32)>,
    pub is_pe: bool,
    pub note: Option<String>,
}

impl Default for ApiAnalysisResult {
    fn default() -> Self {
        Self {
            total_score: 0,
            severity: "None".to_string(),
            imports_total: 0,
            suspicious_total: 0,
            top: Vec::new(),
            category_scores: Vec::new(),
            is_pe: false,
            note: None,
        }
    }
}
