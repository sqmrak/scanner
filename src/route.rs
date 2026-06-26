// one tree pass, routes by path prefix

use crate::parse::{cursors, desktop, fonts, icons, libs, man, modules, services, themes};
use crate::profile::{LayerProfile, Locale, Theme};
use crate::read;
use crate::ScanConfig;
use std::path::{Path, PathBuf};

// sample size for service probe, early-exit caps actual opens below this
const SERVICE_SAMPLE: usize = 12;
// distinct shapes (extension + subdir flag), more spread is rejected
const MAX_EXTENSIONS: usize = 10;
// bulk data dir width, resource dirs (bin/lib/share) exempt
const MAX_FANOUT: usize = 500;
// probe_unknown depth cap: service collections are at depth ≤3 (etc/init.d,
// usr/lib/systemd/system), deeper is source or data
const PROBE_DEPTH: usize = 4;

pub(crate) fn descend(
    dir: &Path,
    root: &Path,
    p: &mut LayerProfile,
    pending: &mut Vec<(PathBuf, PathBuf)>,
    depth: usize,
    config: &ScanConfig,
) {
    enter(read::entries(dir), root, p, depth, pending, config);
}

fn enter(
    children: Vec<read::Entry>,
    root: &Path,
    p: &mut LayerProfile,
    depth: usize,
    pending: &mut Vec<(PathBuf, PathBuf)>,
    config: &ScanConfig,
) {
    for child in children {
        let Ok(rel) = child.path.strip_prefix(root) else {
            continue;
        };
        let Some(rels) = rel.to_str() else {
            continue;
        };
        if !child.is_dir {
            file_route(rels, rel, &child.path, p, pending, config);
            continue;
        }
        if is_pm_data(rels) {
            continue;
        }
        match dir_route(rels, p.fhs, config) {
            Dir::Theme(name) => {
                let kind = themes::kind(&child.path);
                p.themes.push(Theme { path: rel.to_path_buf(), name, kind });
            }
            Dir::Locale(lang) => p.locale.push(Locale { path: rel.to_path_buf(), lang }),
            Dir::Cursors(theme) => {
                if let Some(c) = cursors::parse(rel, &child.path, theme) {
                    p.cursors.push(c);
                }
            }
            Dir::Descend => descend(&child.path, root, p, pending, 0, config),
            Dir::Unknown => probe_unknown(&child.path, root, p, depth + 1, pending, config),
        }
    }
}

fn probe_unknown(
    dir: &Path,
    root: &Path,
    p: &mut LayerProfile,
    depth: usize,
    pending: &mut Vec<(PathBuf, PathBuf)>,
    config: &ScanConfig,
) {
    if depth >= PROBE_DEPTH {
        return;
    }
    let (probed, has_more) = read::probe(dir, MAX_FANOUT);
    let is_service = !too_diverse(&probed) && votes_service(&probed);
    if is_service {
        let before = p.services.len();
        // service collection may exceed probe; read fully to catch all
        if has_more {
            for e in &read::entries(dir) {
                let Ok(srel) = e.path.strip_prefix(root) else {
                    continue;
                };
                if let Some(s) = services::detect(srel, &e.path, e.is_dir) {
                    p.services.push(s);
                }
            }
        } else {
            for e in &probed {
                let Ok(srel) = e.path.strip_prefix(root) else {
                    continue;
                };
                if let Some(s) = services::detect(srel, &e.path, e.is_dir) {
                    p.services.push(s);
                }
            }
        }
        if p.services.len() > before {
            return;
        }
        // service-shaped but nothing detected: fall through to enter
    }
    if has_more {
        return;
    }
    enter(probed, root, p, depth, pending, config);
}

// distinct shapes in the sample: extension for a file, "/" for a subdir,
// "" for an extensionless file. a service dir reuses few; source/data many
fn too_diverse(children: &[read::Entry]) -> bool {
    let n = children.len().min(SERVICE_SAMPLE);
    let mut keys: Vec<&str> = children[..n]
        .iter()
        .map(|e| {
            if e.is_dir {
                "/"
            } else {
                e.path.extension().and_then(|x| x.to_str()).unwrap_or("")
            }
        })
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys.len() > MAX_EXTENSIONS
}

// majority of the sample is service-shaped. opens files, stops early when
// the verdict can no longer change
fn votes_service(children: &[read::Entry]) -> bool {
    let n = children.len().min(SERVICE_SAMPLE);
    let mut svc = 0;
    for (seen, e) in children[..n].iter().enumerate() {
        if services::peek(&e.path, e.is_dir) {
            svc += 1;
            if svc * 2 >= n {
                return true;
            }
        }
        if (svc + n - seen - 1) * 2 < n {
            return false;
        }
    }
    n > 1 && svc >= 1 && svc * 2 >= n
}

enum Dir {
    Theme(String),
    Locale(String),
    Cursors(String),
    Descend,
    Unknown,
}

fn dir_route(rel: &str, fhs: bool, config: &ScanConfig) -> Dir {
    if let Some(n) = name_after_prefix(rel, "usr/share/themes/") {
        return Dir::Theme(n);
    }
    if let Some(l) = name_after_prefix(rel, "usr/share/locale/") {
        return Dir::Locale(l);
    }
    if let Some(theme) = cursors_theme(rel) {
        return Dir::Cursors(theme);
    }
    if !fhs && rel.contains("/share/") {
        let last = rel.rsplit('/').next().unwrap_or(rel);
        if let Some(parent) = rel.strip_suffix(&format!("/{last}")) {
            if parent.ends_with("/share/themes") && !last.is_empty() {
                return Dir::Theme(last.to_string());
            }
            if parent.ends_with("/share/locale") && !last.is_empty() {
                return Dir::Locale(last.to_string());
            }
        }
    }
    if is_resource_dir(rel, config) {
        return Dir::Descend;
    }
    Dir::Unknown
}

fn file_route(
    rel: &str,
    relp: &Path,
    abs: &Path,
    p: &mut LayerProfile,
    pending: &mut Vec<(PathBuf, PathBuf)>,
    config: &ScanConfig,
) {
    if rel.contains("/lib/modules/") {
        if let Some(m) = modules::parse(relp) {
            p.modules.push(m);
        }
        return;
    }
    if under_any(rel, read::BIN_ROOTS) || under_custom(rel, &config.bin_roots) {
        pending.push((relp.to_path_buf(), abs.to_path_buf()));
        return;
    }
    if under_any(rel, read::LIB_ROOTS) || under_custom(rel, &config.lib_roots) {
        if is_shared_library(rel) {
            p.lib.push(libs::parse(relp, abs));
        }
        if let Some(tc) = detect_toolchain(relp) {
            p.toolchains.push(tc);
        }
        // firmware blobs and toolchain artifacts sit under lib roots
        if is_firmware(rel) {
            p.firmware += 1;
        }
        return;
    }
    if let Some(kind) = fhs_share(relp) {
        collect_share(kind, relp, abs, p);
        return;
    }
    // mime xml types: count .xml files under usr/share/mime
    if rel.starts_with("usr/share/mime/")
        && relp.extension().and_then(|e| e.to_str()) == Some("xml")
    {
        p.mime += 1;
        return;
    }
    if !p.fhs {
        match non_fhs_role(rel) {
            Some("bin") => {
                pending.push((relp.to_path_buf(), abs.to_path_buf()));
                return;
            }
            Some("lib") if is_shared_library(rel) => {
                p.lib.push(libs::parse(relp, abs));
                return;
            }
            Some("lib") => {
                if let Some(tc) = detect_toolchain(relp) {
                    p.toolchains.push(tc);
                }
                if is_firmware(rel) {
                    p.firmware += 1;
                }
                return;
            }
            _ => {}
        }
        if let Some(kind) = nonfhs_share(relp) {
            collect_share(kind, relp, abs, p);
        }
    }
}

fn non_fhs_role(rel: &str) -> Option<&'static str> {
    let parent = rel.rsplit('/').nth(1)?;
    match parent {
        "bin" | "sbin" => Some("bin"),
        "lib" | "lib64" => Some("lib"),
        _ => None,
    }
}

// pm data dirs are pre-counted by parse::pm, skip the tree walk into them
fn is_pm_data(rel: &str) -> bool {
    rel == "var/lib" || rel == "var/db" || rel.starts_with("var/lib/") || rel.starts_with("var/db/")
}

fn is_resource_dir(rel: &str, config: &ScanConfig) -> bool {
    let leaf = rel.rsplit('/').next().unwrap_or(rel);
    matches!(leaf, "bin" | "sbin" | "libexec" | "games" | "lib" | "lib64" | "modules" | "firmware")
        || rel.contains("/lib/modules/")
        || rel.contains("/share/")
        || rel.starts_with("share/")
        || under_custom(rel, &config.bin_roots)
        || under_custom(rel, &config.lib_roots)
}

fn cursors_theme(rel: &str) -> Option<String> {
    let rest = if let Some(r) = rel.strip_prefix("usr/share/icons/") {
        r
    } else if let Some(idx) = rel.find("/share/icons/") {
        &rel[idx + "/share/icons/".len()..]
    } else {
        return None;
    };
    let leaf = rest.rsplit('/').next()?;
    if leaf != "cursors" || rest == "cursors" {
        return None;
    }
    let theme = rest.strip_suffix("/cursors")?.rsplit('/').next()?;
    if theme.is_empty() {
        return None;
    }
    Some(theme.to_string())
}

enum Share {
    App,
    X11Session,
    WaylandSession,
    Icon,
    Font,
    ManPage,
}

fn collect_share(kind: Share, relp: &Path, abs: &Path, p: &mut LayerProfile) {
    match kind {
        Share::App if is_desktop(relp) => p.apps.push(desktop::app(relp, abs)),
        Share::X11Session if is_desktop(relp) => {
            p.sessions.push(desktop::session(relp, abs, "x11"))
        }
        Share::WaylandSession if is_desktop(relp) => {
            p.sessions.push(desktop::session(relp, abs, "wayland"))
        }
        Share::Icon => {
            if let Some(i) = icons::parse(relp) {
                p.icons.push(i);
            }
        }
        Share::Font => {
            if let Some(f) = fonts::parse(relp) {
                p.fonts.push(f);
            }
        }
        Share::ManPage => {
            if let Some(m) = man::parse(relp) {
                p.man.push(m);
            }
        }
        _ => {}
    }
}

fn fhs_share(relp: &Path) -> Option<Share> {
    let rel = relp.to_string_lossy();
    if rel.starts_with("usr/share/applications/") {
        return Some(Share::App);
    }
    if rel.starts_with("usr/share/xsessions/") {
        return Some(Share::X11Session);
    }
    if rel.starts_with("usr/share/wayland-sessions/") {
        return Some(Share::WaylandSession);
    }
    if rel.starts_with("usr/share/icons/") {
        return Some(Share::Icon);
    }
    if under_any(&rel, &["usr/share/fonts", "usr/local/share/fonts"]) {
        return Some(Share::Font);
    }
    if under_any(&rel, &["usr/share/man"]) {
        return Some(Share::ManPage);
    }
    None
}

fn nonfhs_share(relp: &Path) -> Option<Share> {
    let rel = relp.to_string_lossy();
    if !rel.contains("/share/") {
        return None;
    }
    if rel.contains("/xsessions/") {
        return Some(Share::X11Session);
    }
    if rel.contains("/wayland-sessions/") {
        return Some(Share::WaylandSession);
    }
    if rel.ends_with(".desktop") {
        return Some(Share::App);
    }
    if rel.contains("/icons/") {
        return Some(Share::Icon);
    }
    if rel.contains("/fonts/") {
        return Some(Share::Font);
    }
    if rel.contains("/man/") {
        return Some(Share::ManPage);
    }
    None
}

// find the <name>/<version> pair above a toolchain artifact, skipping
// intermediate dirs like "lib" or "include"
fn detect_toolchain(rel: &Path) -> Option<crate::profile::Toolchain> {
    let name = rel.file_name()?.to_str()?;
    if !(name.ends_with(".a") || (name.starts_with("crt") && name.ends_with(".o"))) {
        return None;
    }
    let mut cur = rel.parent()?;
    // skip trailing intermediate dirs
    while let Some(seg) = cur.file_name().and_then(|n| n.to_str()) {
        if seg == "lib" || seg == "include" {
            cur = cur.parent()?;
        } else {
            break;
        }
    }
    let version = cur.file_name()?.to_str()?.to_string();
    let name = cur.parent()?.file_name()?.to_str()?.to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(crate::profile::Toolchain { path: rel.to_path_buf(), name, version })
}

fn name_after_prefix(rel: &str, prefix: &str) -> Option<String> {
    let rest = rel.strip_prefix(prefix)?;
    let name = rest.split('/').next()?;
    if name.is_empty() { None } else { Some(name.to_string()) }
}

fn under_any(rel: &str, roots: &[&str]) -> bool {
    roots
        .iter()
        .any(|r| rel.starts_with(r) && rel.as_bytes().get(r.len()).is_none_or(|&b| b == b'/'))
}

fn under_custom(rel: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| {
        rel.starts_with(r.as_str()) && rel.as_bytes().get(r.len()).is_none_or(|&b| b == b'/')
    })
}

fn is_shared_library(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with(".so") || name.contains(".so.")
}

fn is_desktop(rel: &Path) -> bool {
    rel.extension().and_then(|e| e.to_str()) == Some("desktop")
}

fn is_firmware(rel: &str) -> bool {
    rel.contains("/firmware/") || rel.starts_with("firmware/")
}
