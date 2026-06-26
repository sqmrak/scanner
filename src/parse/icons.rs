// any file at theme/size/<name> under an icons tree, no format table

use crate::profile::Icon;
use std::path::Path;

pub fn parse(rel: &Path) -> Option<Icon> {
    let s = rel.to_string_lossy();
    let rest = match s.find("/icons/") {
        Some(idx) => &s[idx + "/icons/".len()..],
        None => return None,
    };
    let mut comps = rest.split('/');
    let theme = comps.next()?.to_string();
    let size = comps.next()?.to_string();
    comps.next()?; // require at least theme/size/<name>
    if theme.is_empty() || size.is_empty() {
        return None;
    }
    let name = rel.file_stem()?.to_string_lossy().into_owned();
    Some(Icon { path: rel.to_path_buf(), theme, size, name })
}
