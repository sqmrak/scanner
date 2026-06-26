// man page path: .../man/<lang?>/man<sec>/<name>.<sec>.<ext?>
// section from the directory name, lang from the optional locale dir

use crate::profile::ManPage;
use std::path::Path;

pub fn parse(rel: &Path) -> Option<ManPage> {
    let path = rel.to_string_lossy();
    let idx = path.find("/man/")?;
    let after = &path[idx + "/man/".len()..];

    let (_rest, section, lang) = if let Some((l, r)) = after.split_once('/') {
        if let Some(sec) = strip_man_prefix(l) {
            (r, sec, None)
        } else {
            let sec_dir = r.split('/').next()?;
            let sec = strip_man_prefix(sec_dir)?;
            let rest = r[sec_dir.len()..].trim_start_matches('/');
            (rest, sec, Some(l.to_string()))
        }
    } else {
        return None;
    };

    let file = rel.file_name()?.to_str()?;
    let name = parse_name(file)?;
    if name.is_empty() {
        return None;
    }
    Some(ManPage { path: rel.to_path_buf(), name, section, lang })
}

fn strip_man_prefix(dir: &str) -> Option<String> {
    if dir.starts_with("man") && dir.len() > 3 {
        Some(dir[3..].to_string())
    } else {
        None
    }
}

fn parse_name(file: &str) -> Option<String> {
    // cut compression suffix: ls.1.gz > ls.1
    let base = if file.ends_with(".gz")
        || file.ends_with(".bz2")
        || file.ends_with(".xz")
        || file.ends_with(".zst")
        || file.ends_with(".lzma")
        || file.ends_with(".lz")
        || file.ends_with(".Z")
    {
        let idx = file.rfind('.')?;
        &file[..idx]
    } else {
        file
    };
    // split on first dot: ls.1 > ls, zshall.1 > zshall
    let name = base.split('.').next()?;
    if name.is_empty() { None } else { Some(name.to_string()) }
}
