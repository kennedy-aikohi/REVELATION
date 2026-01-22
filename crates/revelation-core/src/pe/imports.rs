use crate::ui::results::ApiImport;
use anyhow::Result;

pub fn imports_from_bytes(bytes: &[u8]) -> Result<Vec<ApiImport>> {
    let pe = match goblin::pe::PE::parse(bytes) {
        Ok(v) => v,
        Err(e) => return Err(anyhow::anyhow!("{e}")),
    };

    let mut out: Vec<ApiImport> = Vec::new();

    for imp in pe.imports.iter() {
        let dll = imp.dll.to_string();

        let name_raw = imp.name.to_string();
        let name = if name_raw.trim().is_empty() {
            None
        } else {
            Some(name_raw)
        };

        let ordinal = if imp.ordinal == 0 {
            None
        } else {
            Some(imp.ordinal as u16)
        };

        let is_ordinal = name.is_none() && ordinal.is_some();

        out.push(ApiImport {
            dll,
            name,
            ordinal,
            is_ordinal,
        });
    }

    Ok(out)
}

pub fn imports_from_path(path: &std::path::Path) -> Result<Vec<ApiImport>> {
    let bytes = std::fs::read(path)?;
    imports_from_bytes(&bytes)
}
