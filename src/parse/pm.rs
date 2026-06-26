// populated dirs under var/lib and var/db. policy picks the pm

use crate::read;
use std::path::Path;

pub fn dirs(root: &Path) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for base in ["var/lib", "var/db"] {
        for dir in read::entries(&root.join(base)) {
            if !dir.is_dir {
                continue;
            }
            let Some(name) = dir.path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let files = read::count_files(&dir.path, |_| true);
            if files > 0 {
                out.push((name.to_string(), files));
            }
        }
    }
    out
}
