// d_type from readdir, no stat per entry. no symlink follow
// sorted once at the end, not per directory

use std::path::{Path, PathBuf};

// bin/lib root prefixes for file routing. boundary-matched (usr/bin matches
// usr/bin/foo but not usr/binfoo)
pub const BIN_ROOTS: &[&str] = &[
    "usr/bin",
    "usr/sbin",
    "usr/local/bin",
    "usr/local/sbin",
    "usr/games",
    "usr/libexec",
    "bin",
    "sbin",
    "opt/bin",
];
pub const LIB_ROOTS: &[&str] = &["usr/lib", "lib", "usr/lib64", "lib64", "usr/local/lib"];

pub struct Entry {
    pub path: PathBuf,
    pub is_dir: bool,
}

pub fn entries(dir: &Path) -> Vec<Entry> {
    if is_symlink(dir) {
        return Vec::new();
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| Entry {
            is_dir: e.file_type().map(|t| t.is_dir()).unwrap_or(false),
            path: e.path(),
        })
        .collect()
}

// up to `limit` entries + flag whether the dir holds more
pub fn probe(dir: &Path, limit: usize) -> (Vec<Entry>, bool) {
    if is_symlink(dir) {
        return (Vec::new(), false);
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (Vec::new(), false);
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        out.push(Entry {
            is_dir: e.file_type().map(|t| t.is_dir()).unwrap_or(false),
            path: e.path(),
        });
        if out.len() >= limit {
            return (out, true);
        }
    }
    (out, false)
}

fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

// recursive, no symlink follow. CAP bounds pathological trees
pub fn count_files(dir: &Path, keep: impl Fn(&Path) -> bool) -> usize {
    const CAP: usize = 200_000;
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in entries(&d) {
            if e.is_dir {
                stack.push(e.path);
            } else if keep(&e.path) {
                n += 1;
                if n >= CAP {
                    return n;
                }
            }
        }
    }
    n
}
