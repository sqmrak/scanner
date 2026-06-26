// cursor theme directory: counts non-directory entries inside

use crate::profile::Cursor;
use crate::read;
use std::path::Path;

pub fn parse(rel: &Path, abs: &Path, theme: String) -> Option<Cursor> {
    let count = read::entries(abs).iter().filter(|e| !e.is_dir).count();
    if count == 0 {
        return None;
    }
    Some(Cursor { path: rel.to_path_buf(), name: theme, count })
}
