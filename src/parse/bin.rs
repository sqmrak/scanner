// binary detection: ELF first, then #! interpreter. relates paths (layer-relative)
// and absolute (for open), returns a Bin with the path relative to the root

use crate::parse::elf;
use crate::profile::Bin;
use std::io::Read;
use std::path::Path;

pub fn parse(rel: &Path, abs: &Path) -> Bin {
    match elf::bin(abs) {
        Some(b) => {
            Bin { path: rel.to_path_buf(), interp: b.interp, dynamic: b.dynamic, script: None }
        }
        None => {
            let script = shebang_interp(abs);
            Bin { path: rel.to_path_buf(), interp: None, dynamic: false, script }
        }
    }
}

fn shebang_interp(abs: &Path) -> Option<String> {
    let mut f = std::fs::File::open(abs).ok()?;
    let mut head = [0u8; 256];
    let n = f.read(&mut head).ok()?;
    if n < 2 || head[0] != b'#' || head[1] != b'!' {
        return None;
    }
    let line = String::from_utf8_lossy(&head[2..n]);
    let path = line.lines().next()?.trim();
    if path.is_empty() {
        return None;
    }
    // split off arguments: `/usr/bin/env python3` → `/usr/bin/env`
    let interpreter = path.split_whitespace().next()?;
    if interpreter.is_empty() { None } else { Some(interpreter.to_string()) }
}
