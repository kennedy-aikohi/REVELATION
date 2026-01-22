use crate::pe::imports::imports_from_path;
use crate::ui::results::ApiImport;
use anyhow::Result;
use std::path::Path;

pub fn extract_imports(path: &Path) -> Result<Vec<ApiImport>> {
    imports_from_path(path)
}
