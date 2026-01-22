use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{fs::File, io::{Read, BufReader}, path::Path};

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}
