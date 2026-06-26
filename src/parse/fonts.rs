// format = extension, weight = token after last separator, no tables

use crate::profile::Font;
use std::path::Path;

pub fn parse(rel: &Path) -> Option<Font> {
    let format = rel.extension()?.to_str()?.to_ascii_lowercase();
    let name = rel.file_stem()?.to_string_lossy().into_owned();
    let weight = name.rfind(['-', '_', ' ']).map(|i| name[i + 1..].to_ascii_lowercase());
    Some(Font { path: rel.to_path_buf(), name, format, weight })
}
