// first dynamic binary's interp stem, plus all unique stems across the layer

use crate::profile::{Bin, Libc};

pub fn from_bins(bins: &[Bin]) -> Vec<Libc> {
    let mut seen = std::collections::HashSet::new();
    bins.iter()
        .filter_map(|b| b.interp.as_deref())
        .filter(|&interp| seen.insert(interp.to_string()))
        .map(|interp| {
            let name = loader_stem(interp);
            Libc { name, interp: interp.to_string() }
        })
        .collect()
}

fn loader_stem(interp: &str) -> String {
    let base = interp.rsplit('/').next().unwrap_or(interp);
    match base.find(".so") {
        Some(i) => &base[..i],
        None => base,
    }
    .to_string()
}
