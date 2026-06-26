// profile types. paths are layer-relative. scanner fills them

use std::path::PathBuf;

/// the complete inventory of a layer rootfs
#[derive(Clone, Debug, Default)]
pub struct LayerProfile {
    /// the c runtime, derived from the first dynamic binary's PT_INTERP.
    /// the `name` is the loader filename stem, not a glibc/musl verdict
    pub libc: Option<Libc>,
    /// every unique loader found across dynamic binaries, for layers that
    /// ship multiple libc runtimes (bedrock, mixed toolchains). the first
    /// entry is the same as `libc`
    pub all_libcs: Vec<Libc>,
    /// populated directories under `var/lib` and `var/db` with file counts.
    /// policy picks the package manager, not the scanner
    pub pm_dirs: Vec<(String, usize)>,
    /// whether the rootfs follows the filesystem hierarchy standard
    pub fhs: bool,
    /// dynamic and static executables
    pub bin: Vec<Bin>,
    /// shared libraries (.so files under lib roots)
    pub lib: Vec<Lib>,
    /// application launcher entries from .desktop files
    pub apps: Vec<Desktop>,
    /// display manager and desktop session entries
    pub sessions: Vec<Session>,
    /// icon files under an icons/ tree
    pub icons: Vec<Icon>,
    /// cursor theme directories under an icons/ tree
    pub cursors: Vec<Cursor>,
    /// theme directories under a themes/ tree
    pub themes: Vec<Theme>,
    /// font files under a fonts/ tree
    pub fonts: Vec<Font>,
    /// service entries: supervised dirs, executable scripts, text units
    pub services: Vec<Service>,
    /// locale trees (language from the directory name)
    pub locale: Vec<Locale>,
    /// kernel modules (.ko files under lib/modules/)
    pub modules: Vec<Module>,
    /// compiler toolchains detected by their artifacts
    pub toolchains: Vec<Toolchain>,
    /// count of xml mime-type files under usr/share/mime
    pub mime: usize,
    /// count of firmware blobs under lib/firmware
    pub firmware: usize,
    /// man pages found under a man/ tree
    pub man: Vec<ManPage>,
}

/// the c runtime identity, derived from the first dynamic binary's PT_INTERP.
/// the `name` is the loader filename stem (ld-musl-x86_64), not a libc verdict
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Libc {
    pub name: String,
    /// the full PT_INTERP path inside the layer, same fact as Bin.interp
    pub interp: String,
}

/// a binary executable found under a bin root
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bin {
    pub path: PathBuf,
    /// the PT_INTERP path if the binary is dynamically linked. None for static.
    /// a `#!` script also reports its interpreter here (the shebang line)
    pub interp: Option<String>,
    /// whether a PT_DYNAMIC segment is present. false for scripts
    pub dynamic: bool,
    /// the shebang interpreter path when the file is not an ELF but starts
    /// with `#!`. None for ELF binaries and non-script files
    pub script: Option<String>,
}

/// a shared library (.so) under a lib root
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lib {
    pub path: PathBuf,
    /// the DT_SONAME entry, if the library declares one
    pub soname: Option<String>,
    /// DT_NEEDED entries  - the libraries this one depends on
    pub needed: Vec<String>,
}

/// a freedesktop .desktop file (application launcher entry)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Desktop {
    pub path: PathBuf,
    /// the Name key from the primary [Desktop Entry] group
    pub name: Option<String>,
    /// the Icon key
    pub icon: Option<String>,
    /// the Exec key
    pub exec: Option<String>,
}

/// a display-manager or desktop-session .desktop file
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub path: PathBuf,
    pub name: Option<String>,
    pub exec: Option<String>,
    /// "x11" for xsessions, "wayland" for wayland-sessions
    pub kind: String,
}

/// an icon file under a theme/size/name path inside an icons/ tree.
/// no format whitelist: the file's position under icons/ makes it an icon
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icon {
    pub path: PathBuf,
    pub theme: String,
    pub size: String,
    pub name: String,
}

/// a cursor theme directory under an icons/ tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub path: PathBuf,
    pub name: String,
    /// number of cursor files in this directory
    pub count: usize,
}

/// a theme directory under a themes/ tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    pub path: PathBuf,
    pub name: String,
    /// comma-separated engine names derived from subdirectory names
    pub kind: String,
}

/// a font file under a fonts/ tree. no format or weight tables: extension
/// is the format, the trailing token after a separator is the weight
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Font {
    pub path: PathBuf,
    pub name: String,
    pub format: String,
    pub weight: Option<String>,
}

/// a service entry. no name tables: three structural shapes (supervised
/// dir with run file, executable script, text unit with `[section]` or
/// key=value directives). kind is the file extension, name is the stem
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub path: PathBuf,
    pub kind: String,
    pub name: String,
}

/// a locale directory under a locale/ tree. lang is the directory name
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locale {
    pub path: PathBuf,
    pub lang: String,
}

/// a kernel module (.ko) under lib/modules/
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub path: PathBuf,
    pub name: String,
    /// the kernel version from the directory name under lib/modules/
    pub kernel: String,
}

/// a compiler toolchain detected by its artifacts (crt*.o or *.a).
/// name is the parent directory, version is the subdirectory
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toolchain {
    pub path: PathBuf,
    pub name: String,
    pub version: String,
}

/// a man page under a man/ tree. section from the directory name (man1 > "1").
/// lang is the optional locale directory between man/ and the section
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManPage {
    pub path: PathBuf,
    pub name: String,
    pub section: String,
    pub lang: Option<String>,
}
