use crate::analysis::api_classifier::{classify_imports, ClassifiedImport};
use crate::ui::results::{ApiAnalysisResult, ApiCategory, ApiFinding, ApiImport};
use std::collections::HashMap;

fn sev_from_score(score: u32) -> String {
    if score >= 85 {
        "High".to_string()
    } else if score >= 60 {
        "Medium".to_string()
    } else if score > 0 {
        "Low".to_string()
    } else {
        "None".to_string()
    }
}

fn base_points(cat: ApiCategory) -> u32 {
    match cat {
        ApiCategory::ProcessInjection => 45,
        ApiCategory::CredentialAccess => 40,
        ApiCategory::Persistence => 35,
        ApiCategory::CommandAndControl => 30,
        ApiCategory::Exfiltration => 30,
        ApiCategory::DefenseEvasion => 28,
        ApiCategory::PrivilegeEscalation => 28,
        ApiCategory::Networking => 22,
        ApiCategory::Crypto => 18,
        ApiCategory::Registry => 18,
        ApiCategory::Process => 16,
        ApiCategory::AntiDebug => 16,
        _ => 8,
    }
}

fn bonus_for(imp: &ApiImport) -> u32 {
    if imp.is_ordinal {
        return 12;
    }
    let a = imp.name_lower();
    if a.contains("createremotethread") || a.contains("writeprocessmemory") || a.contains("virtualallocex")
    {
        20
    } else if a.contains("urldownloadtofile") || a.contains("httpsendrequest") {
        10
    } else {
        0
    }
}

pub fn score(imports: &[ApiImport]) -> ApiAnalysisResult {
    let mut res = ApiAnalysisResult::default();
    res.imports_total = imports.len();

    if imports.is_empty() {
        res.is_pe = false;
        res.note = Some("No imports extracted".to_string());
        return res;
    }

    res.is_pe = true;

    let classified: Vec<ClassifiedImport> = classify_imports(imports);

    let mut category_scores: HashMap<ApiCategory, u32> = HashMap::new();
    let mut findings: Vec<ApiFinding> = Vec::new();

    for c in classified {
        if !c.suspicious {
            continue;
        }

        let cat = c.category;

        let mut points = base_points(cat);
        let b = bonus_for(&c.api);
        points = points.saturating_add(b).min(100);

        *category_scores.entry(cat).or_insert(0) += points;

        let mut reasons = c.reasons;
        if b > 0 {
            reasons.push("High-signal API".to_string());
        }

        findings.push(ApiFinding {
            api: c.api,
            category: cat,
            score: points,
            reasons,
        });
    }

    findings.sort_by(|a, b| b.score.cmp(&a.score));

    res.suspicious_total = findings.len();
    res.top = findings.into_iter().take(50).collect();

    let mut cats: Vec<(ApiCategory, u32)> = category_scores.into_iter().collect();
    cats.sort_by(|a, b| b.1.cmp(&a.1));
    res.category_scores = cats;

    let sum: u32 = res.category_scores.iter().map(|(_, v)| *v).sum();
    res.total_score = sum.min(100);
    res.severity = sev_from_score(res.total_score);

    res
}
