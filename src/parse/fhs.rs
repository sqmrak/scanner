// fhs detection: usr/bin + etc present

use std::path::Path;

pub fn detect(root: &Path) -> bool {
    root.join("usr/bin").is_dir() && root.join("etc").is_dir()
}
