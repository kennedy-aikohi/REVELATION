use crate::ui::results::{ApiCategory, ApiImport};

pub struct ClassifiedImport {
    pub api: ApiImport,
    pub category: ApiCategory,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

fn has_any(api: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| api.contains(n))
}

pub fn classify_imports(imports: &[ApiImport]) -> Vec<ClassifiedImport> {
    let mut out = Vec::with_capacity(imports.len());
    for imp in imports {
        let (cat, sus, reasons) = classify_one(imp);
        out.push(ClassifiedImport {
            api: imp.clone(),
            category: cat,
            suspicious: sus,
            reasons,
        });
    }
    out
}

fn classify_one(imp: &ApiImport) -> (ApiCategory, bool, Vec<String>) {
    let dll = imp.dll_lower();
    let api = imp.name_lower();

    if imp.is_ordinal {
        return (
            ApiCategory::Other,
            true,
            vec!["Import by ordinal".to_string()],
        );
    }

    if dll.contains("advapi32") && has_any(&api, &["regsetvalue", "regcreatekey", "regopenkey"]) {
        return (
            ApiCategory::Registry,
            true,
            vec!["Registry modification".to_string()],
        );
    }

    if dll.contains("kernel32") && has_any(&api, &["createprocess", "winexec", "shellexecute"]) {
        return (
            ApiCategory::Process,
            true,
            vec!["Process execution".to_string()],
        );
    }

    if has_any(
        &api,
        &[
            "createremotethread",
            "virtualallocex",
            "writeprocessmemory",
            "openprocess",
            "setthreadcontext",
            "getthreadcontext",
            "resumethread",
            "rtlmovememory",
            "ntunmapviewofsection",
            "queueuserapc",
        ],
    ) {
        return (
            ApiCategory::ProcessInjection,
            true,
            vec!["Common injection primitive".to_string()],
        );
    }

    if has_any(
        &api,
        &[
            "internetopen",
            "internetconnect",
            "httpopenrequest",
            "httpsendrequest",
            "internetreadfile",
            "urldownloadtofile",
            "winhttpopen",
            "winhttpsendrequest",
            "winhttpreceiveresponse",
            "wsastartup",
            "connect",
            "recv",
            "send",
        ],
    ) || dll.contains("wininet")
        || dll.contains("winhttp")
        || dll.contains("ws2_32")
    {
        return (
            ApiCategory::Networking,
            true,
            vec!["Network capability".to_string()],
        );
    }

    if has_any(
        &api,
        &[
            "cryptacquirecontext",
            "cryptencrypt",
            "cryptdecrypt",
            "bcrypt",
            "bcryptencrypt",
            "bcryptdecrypt",
        ],
    ) {
        return (
            ApiCategory::Crypto,
            true,
            vec!["Crypto API usage".to_string()],
        );
    }

    if has_any(
        &api,
        &[
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
        ],
    ) {
        return (
            ApiCategory::AntiDebug,
            true,
            vec!["Anti-debug technique".to_string()],
        );
    }

    (ApiCategory::Other, false, Vec::new())
}
