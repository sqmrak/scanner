//! scan module for nexus. single pass, no caching

mod parse;
mod profile;
mod read;
mod route;

pub use profile::{
    Bin, Cursor, Desktop, Font, Icon, LayerProfile, Lib, Libc, Locale, ManPage, Module, Service,
    Session, Theme, Toolchain,
};

use std::fmt;
use std::path::{Path, PathBuf};

/// a scan failure
#[derive(Debug, Clone)]
pub enum ScanError {
    /// a thread performing the scan panicked
    Panic(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Panic(msg) => write!(f, "scan panicked: {msg}"),
        }
    }
}

/// custom bin and lib roots for non-standard layouts.
/// register paths like `/System/Applications` so files under them
/// are detected as binaries without recompiling the scanner
#[derive(Clone, Debug, Default)]
pub struct ScanConfig {
    /// extra directories whose direct children are treated as binaries.
    /// no trailing slash. the built-in list always applies
    pub bin_roots: Vec<String>,
    /// extra directories whose direct children are treated as libraries.
    /// no trailing slash. the built-in list always applies
    pub lib_roots: Vec<String>,
    /// max depth for probing unclassified directories. the built-in default
    /// (4) works for standard trees; deep Nix or Gobo layouts may need more.
    /// set to 0 to use the built-in default
    pub probe_depth: usize,
}

impl ScanConfig {
    /// empty config: only the built-in bin and lib roots are used
    pub fn new() -> Self {
        Self::default()
    }

    /// register an extra bin root
    pub fn with_bin_root(mut self, path: impl Into<String>) -> Self {
        self.bin_roots.push(path.into());
        self
    }

    /// register an extra lib root
    pub fn with_lib_root(mut self, path: impl Into<String>) -> Self {
        self.lib_roots.push(path.into());
        self
    }

    /// override the probe depth for unclassified directories
    pub fn with_probe_depth(mut self, depth: usize) -> Self {
        self.probe_depth = depth;
        self
    }
}

const PARALLEL_THRESHOLD: usize = 3;

/// scan a rootfs tree with the built-in bin and lib roots
pub fn scan(root: &Path) -> LayerProfile {
    scan_with(root, &ScanConfig::default())
}

/// scan a rootfs tree with custom bin and lib roots registered in `config`.
/// top-level directories descend in parallel, then ELF parsing is
/// deferred and also parallelised. paths in the profile are relative to the root
pub fn scan_with(root: &Path, config: &ScanConfig) -> LayerProfile {
    let fhs = parse::fhs::detect(root);
    let pm_dirs = parse::pm::dirs(root);

    let entries = read::entries(root);
    let top_dirs: Vec<PathBuf> = entries
        .iter()
        .filter(|e| e.is_dir)
        .filter(|e| !is_kernel_vfs(&strip_root(&e.path, root)))
        .map(|e| e.path.clone())
        .collect();

    let results: Vec<_> = if top_dirs.len() < PARALLEL_THRESHOLD {
        top_dirs.iter().map(|dir| traverse(dir, root, fhs, config)).collect()
    } else {
        std::thread::scope(|s| {
            let handles: Vec<_> = top_dirs
                .into_iter()
                .map(|dir| s.spawn(move || traverse(&dir, root, fhs, config)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("traverse worker thread panicked"))
                .collect()
        })
    };

    let mut p = LayerProfile { fhs, pm_dirs, ..Default::default() };
    let mut all_pending = Vec::new();
    for (profile, pending) in results {
        merge_profile(&mut p, profile);
        all_pending.extend(pending);
    }

    if !all_pending.is_empty() {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(all_pending.len());
        let chunk_size = all_pending.len().div_ceil(threads);
        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for chunk in all_pending.chunks(chunk_size) {
                handles.push(s.spawn(move || {
                    chunk.iter().map(|(rel, abs)| parse::bin::parse(rel, abs)).collect::<Vec<_>>()
                }));
            }
            for h in handles {
                if let Ok(bins) = h.join() {
                    p.bin.extend(bins);
                }
            }
        });
    }

    sort(&mut p);
    p.all_libcs = parse::libc::from_bins(&p.bin);
    p.libc = p.all_libcs.first().cloned();
    p
}

// descend a single directory and return its profile and pending ELF paths
fn traverse(
    dir: &Path,
    root: &Path,
    fhs: bool,
    config: &ScanConfig,
) -> (LayerProfile, Vec<(PathBuf, PathBuf)>) {
    let mut p = LayerProfile { fhs, ..Default::default() };
    let mut pending = Vec::new();
    route::descend(dir, root, &mut p, &mut pending, 1, config);
    (p, pending)
}

// merge vec fields and counters from a sub-profile into the main one
fn merge_profile(dst: &mut LayerProfile, src: LayerProfile) {
    dst.bin.extend(src.bin);
    dst.lib.extend(src.lib);
    dst.apps.extend(src.apps);
    dst.sessions.extend(src.sessions);
    dst.icons.extend(src.icons);
    dst.cursors.extend(src.cursors);
    dst.themes.extend(src.themes);
    dst.fonts.extend(src.fonts);
    dst.services.extend(src.services);
    dst.locale.extend(src.locale);
    dst.modules.extend(src.modules);
    dst.toolchains.extend(src.toolchains);
    dst.man.extend(src.man);
    dst.mime += src.mime;
    dst.mime_paths.extend(src.mime_paths);
    dst.autostart.extend(src.autostart);
    dst.dbus_services.extend(src.dbus_services);
    dst.firmware += src.firmware;
    dst.firmware_paths.extend(src.firmware_paths);
}

fn is_kernel_vfs(rel: &str) -> bool {
    matches!(rel, "proc" | "sys" | "dev" | "run" | "tmp")
}

fn strip_root(path: &Path, root: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned()
}

// one sort per profile, not per directory
fn sort(p: &mut LayerProfile) {
    macro_rules! by_path {
        ($($v:expr),*) => { $($v.sort_by(|a, b| a.path.cmp(&b.path));)* };
    }
    by_path!(
        p.bin,
        p.lib,
        p.apps,
        p.sessions,
        p.icons,
        p.cursors,
        p.themes,
        p.fonts,
        p.services,
        p.locale,
        p.modules,
        p.toolchains,
        p.man
    );
    p.pm_dirs.sort();
    p.mime_paths.sort();
    p.firmware_paths.sort();
    p.autostart.sort();
    p.dbus_services.sort();
}

/// scan several roots with the built-in bin and lib roots.
/// a thread panic in one root does not affect the others;
/// the error carries the panic message
pub fn scan_many(roots: &[std::path::PathBuf]) -> Vec<Result<LayerProfile, ScanError>> {
    scan_many_with(roots, &ScanConfig::default())
}

/// scan several roots with custom bin and lib roots.
/// sequential when fewer than 3 roots, otherwise `std::thread::scope`
pub fn scan_many_with(
    roots: &[std::path::PathBuf],
    config: &ScanConfig,
) -> Vec<Result<LayerProfile, ScanError>> {
    if roots.len() < PARALLEL_THRESHOLD {
        return roots.iter().map(|r| caught(|| scan_with(r, config))).collect();
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = roots.iter().map(|r| s.spawn(|| scan_with(r, config))).collect();
        handles.into_iter().map(|h| h.join().map_err(panic_to_error)).collect()
    })
}

fn caught(f: impl FnOnce() -> LayerProfile) -> Result<LayerProfile, ScanError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(panic_to_error)
}

fn panic_to_error(payload: Box<dyn std::any::Any + Send>) -> ScanError {
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown".to_string()
    };
    ScanError::Panic(msg)
}
