// .desktop file parser: first [Desktop Entry] group, no locale keys

use crate::profile::{Desktop, Session};
use std::path::Path;

pub fn app(rel: &Path, abs: &Path) -> Desktop {
    let v = read(abs, &["Name", "Icon", "Exec"]);
    Desktop { path: rel.to_path_buf(), name: v[0].clone(), icon: v[1].clone(), exec: v[2].clone() }
}

pub fn session(rel: &Path, abs: &Path, kind: &str) -> Session {
    let v = read(abs, &["Name", "Exec"]);
    Session { path: rel.to_path_buf(), name: v[0].clone(), exec: v[1].clone(), kind: kind.into() }
}

// the first group is the primary entry. later groups ([Desktop Action ...])
// do not override it. first value wins, locale keys (Name[ru]) are ignored
fn read(abs: &Path, keys: &[&str]) -> Vec<Option<String>> {
    let text = std::fs::read_to_string(abs).unwrap_or_default();
    let mut out = vec![None; keys.len()];
    let mut group_seen = false;
    let mut in_first = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if group_seen {
                break; // past the primary entry
            }
            group_seen = true;
            in_first = true;
            continue;
        }
        if !in_first {
            continue;
        }
        if let Some((k, val)) = line.split_once('=') {
            if let Some(i) = keys.iter().position(|x| *x == k.trim()) {
                if out[i].is_none() {
                    out[i] = Some(val.trim().to_string());
                }
            }
        }
    }
    out
}
