// kernel module: .ko file under lib/modules/<kernel>/

use crate::profile::Module;
use std::path::Path;

pub fn parse(rel: &Path) -> Option<Module> {
    let s = rel.to_string_lossy();
    let idx = match s.find("/lib/modules/") {
        Some(i) => i + "/lib/modules/".len(),
        None => return None,
    };
    let rest = &s[idx..];
    let (kernel, _) = rest.split_once('/')?;
    let file = rel.file_name()?.to_str()?;
    if !file.contains(".ko") {
        return None;
    }
    let name = file.split(".ko").next().unwrap_or(file).to_string();
    Some(Module { path: rel.to_path_buf(), name, kernel: kernel.to_string() })
}
