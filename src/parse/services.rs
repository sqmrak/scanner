// three structural shapes, no name tables:
//   dir with run file                 > supervised
//   executable file                   > script
//   text: [section] or key=value      > unit
// extension is kind, stem is name

use crate::profile::Service;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn detect(rel: &Path, abs: &Path, is_dir: bool) -> Option<Service> {
    let kind = service_kind(abs, is_dir)?;
    let name = if kind == "supervised" {
        rel.file_name()?.to_string_lossy().into_owned()
    } else if rel.extension().is_some() {
        rel.file_stem()?.to_string_lossy().into_owned()
    } else {
        rel.file_name()?.to_string_lossy().into_owned()
    };
    Some(Service { path: rel.to_path_buf(), kind, name })
}

pub fn peek(abs: &Path, is_dir: bool) -> bool {
    service_kind(abs, is_dir).is_some()
}

// is_dir comes from the readdir d_type, so the dir/file split costs no stat
fn service_kind(abs: &Path, is_dir: bool) -> Option<String> {
    if is_dir {
        return abs.join("run").is_file().then(|| "supervised".to_string());
    }
    // skip fifo/socket/device: open would block. stat follows symlinks
    let meta = std::fs::metadata(abs).ok()?;
    if !meta.is_file() {
        return None;
    }
    let ext = abs.extension().and_then(|e| e.to_str()).map(str::to_string);
    if meta.permissions().mode() & 0o111 != 0 {
        return Some(ext.unwrap_or_else(|| "initscript".to_string()));
    }
    if is_unit_text(abs) {
        return Some(ext.unwrap_or_else(|| "unit".to_string()));
    }
    None
}

// form 1: first meaningful line is [section]
// form 2: ≥2 leading lines are `key = value` / `key: value`, bare dotless key
fn is_unit_text(abs: &Path) -> bool {
    const HEAD: usize = 1024;
    const MAX_LINES: usize = 16;
    let Ok(mut f) = std::fs::File::open(abs) else {
        return false;
    };
    let mut buf = [0u8; HEAD];
    let n = f.read(&mut buf).unwrap_or(0);
    let mut first = true;
    let mut directives = 0;
    let mut other = 0;
    let mut considered = 0;
    for raw in buf[..n].split(|&b| b == b'\n') {
        let line = raw.trim_ascii();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        if first {
            first = false;
            if line[0] == b'[' {
                return true; // form 1
            }
        }
        if is_directive(line) {
            directives += 1;
        } else {
            other += 1;
        }
        considered += 1;
        if considered >= MAX_LINES {
            break;
        }
    }
    directives >= 2 && directives >= other // form 2
}

// `key = value` or `key: value`, bare alpha key, no dots. excludes sysctl,
// prose (no separator) and `key value` configs
fn is_directive(line: &[u8]) -> bool {
    if !line.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    let mut i = 0;
    while i < line.len() && (line[i].is_ascii_alphanumeric() || matches!(line[i], b'_' | b'-')) {
        i += 1;
    }
    let mut j = i;
    while j < line.len() && matches!(line[j], b' ' | b'\t') {
        j += 1;
    }
    matches!(line.get(j), Some(b'=') | Some(b':'))
}
