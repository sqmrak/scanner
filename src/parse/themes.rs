// subdir names are engines. trailing -<version> stripped. no table.

use crate::read;
use std::path::Path;

pub fn kind(dir: &Path) -> String {
    let mut engines: Vec<String> = read::entries(dir)
        .iter()
        .filter(|e| e.is_dir)
        .filter_map(|e| e.path.file_name().and_then(|n| n.to_str()))
        .map(|n| engine_stem(n).to_string())
        .collect();
    engines.sort();
    engines.dedup();
    engines.join(",")
}

fn engine_stem(name: &str) -> &str {
    let bytes = name.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'-' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return &name[..i];
        }
    }
    name
}
