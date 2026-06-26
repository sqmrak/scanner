// shared library parsing: soname and DT_NEEDED entries from ELF dynamic section

use crate::parse::elf;
use crate::profile::Lib;
use std::path::Path;

pub fn parse(rel: &Path, abs: &Path) -> Lib {
    let d = elf::dynamic(abs);
    let soname = d.as_ref().and_then(|d| d.soname.clone());
    let needed = d.map(|d| d.needed).unwrap_or_default();
    Lib { path: rel.to_path_buf(), soname, needed }
}
