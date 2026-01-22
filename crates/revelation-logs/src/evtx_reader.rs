use std::path::Path;

use evtx::EvtxParser;
use serde_json::Value;

pub fn read_evtx_as_json(path: &Path, limit: Option<usize>) -> anyhow::Result<Vec<Value>> {
    let mut parser = EvtxParser::from_path(path)?;
    let mut out: Vec<Value> = Vec::new();

    for (i, rec) in parser.records().enumerate() {
        if let Some(max) = limit {
            if i >= max {
                break;
            }
        }

        let rec = rec?;

        let v: Value = match serde_json::from_str(&rec.data) {
            Ok(j) => j,
            Err(_) => Value::String(rec.data),
        };

        out.push(v);
    }

    Ok(out)
}
