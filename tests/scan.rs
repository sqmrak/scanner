// end-to-end scanner tests. a synthetic rootfs is built in a tempdir and the
// reported profile is checked against the facts laid down. elf binaries are
// hand-built minimal 64-bit le fixtures so the suite stays hermetic: no real
// binary from the test machine is read.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

// a throwaway directory, removed on drop
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("scanner-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    fn file(&self, rel: &str, bytes: &[u8]) {
        let f = self.0.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, bytes).unwrap();
    }

    fn exec_file(&self, rel: &str, bytes: &[u8]) {
        self.file(rel, bytes);
        let f = self.0.join(rel);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn dir(&self, rel: &str) {
        std::fs::create_dir_all(self.0.join(rel)).unwrap();
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// minimal 64-bit le elf header. e_type is informational; we set phoff/phnum
fn header(e_type: u16, phnum: u16) -> [u8; 64] {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // class: 64-bit
    h[5] = 1; // data: little-endian
    h[6] = 1; // version
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // machine: x86-64
    h[20..24].copy_from_slice(&1u32.to_le_bytes());
    h[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff: right after header
    h[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    h[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    h[56..58].copy_from_slice(&phnum.to_le_bytes());
    h
}

fn phdr(kind: u32, offset: u64, vaddr: u64, filesz: u64) -> [u8; 56] {
    let mut b = [0u8; 56];
    b[0..4].copy_from_slice(&kind.to_le_bytes());
    b[8..16].copy_from_slice(&offset.to_le_bytes());
    b[16..24].copy_from_slice(&vaddr.to_le_bytes());
    b[32..40].copy_from_slice(&filesz.to_le_bytes());
    b
}

fn dynent(tag: u64, val: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&tag.to_le_bytes());
    b[8..16].copy_from_slice(&val.to_le_bytes());
    b
}

// a dynamic executable: a PT_INTERP asking for `interp`, plus a PT_DYNAMIC so
// it reads as dynamically linked
fn dyn_exe(interp: &str) -> Vec<u8> {
    let phnum = 3u64;
    let interp_off = 64 + 56 * phnum;
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let total = interp_off + interp_bytes.len() as u64;
    let mut v = Vec::new();
    v.extend_from_slice(&header(2, phnum as u16));
    v.extend_from_slice(&phdr(1, 0, 0, total)); // PT_LOAD: whole file at vaddr 0
    v.extend_from_slice(&phdr(3, interp_off, interp_off, interp_bytes.len() as u64)); // PT_INTERP
    v.extend_from_slice(&phdr(2, 0, 0, 0)); // PT_DYNAMIC: presence only
    v.extend_from_slice(&interp_bytes);
    v
}

// a static executable: a single PT_LOAD, no interp, no dynamic section
fn static_exe() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&header(2, 1));
    v.extend_from_slice(&phdr(1, 0, 0, 64 + 56));
    v
}

// a dynamic executable that lists one DT_NEEDED. PT_INTERP routes it as a
// binary; PT_LOAD maps vaddr 0 to file offset 0 so the strtab vaddr is its
// file offset
fn dyn_exe_needed(interp: &str, needed: &str) -> Vec<u8> {
    let phnum = 3u64;
    let ph_end = 64 + 56 * phnum;
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let interp_off = ph_end;
    let dyn_off = interp_off + interp_bytes.len() as u64;
    let dyn_size = 16 * 3u64; // DT_STRTAB, DT_NEEDED, DT_NULL
    let strtab_off = dyn_off + dyn_size;

    let mut strtab = vec![0u8];
    let needed_off = strtab.len() as u64;
    strtab.extend_from_slice(needed.as_bytes());
    strtab.push(0);
    let total = strtab_off + strtab.len() as u64;

    let mut v = Vec::new();
    v.extend_from_slice(&header(2, phnum as u16));
    v.extend_from_slice(&phdr(1, 0, 0, total)); // PT_LOAD
    v.extend_from_slice(&phdr(3, interp_off, interp_off, interp_bytes.len() as u64)); // PT_INTERP
    v.extend_from_slice(&phdr(2, dyn_off, dyn_off, dyn_size)); // PT_DYNAMIC
    v.extend_from_slice(&interp_bytes);
    v.extend_from_slice(&dynent(5, strtab_off)); // DT_STRTAB (vaddr)
    v.extend_from_slice(&dynent(1, needed_off)); // DT_NEEDED
    v.extend_from_slice(&dynent(0, 0)); // DT_NULL
    v.extend_from_slice(&strtab);
    v
}

// a shared object with one SONAME and one NEEDED. PT_LOAD maps vaddr 0 to file
// offset 0, so the strtab vaddr equals its file offset
fn shared(soname: &str, needed: &str) -> Vec<u8> {
    let dyn_off = 64 + 56 * 2u64;
    let dyn_size = 16 * 4u64;
    let strtab_off = dyn_off + dyn_size;

    let mut strtab = vec![0u8];
    let needed_off = strtab.len() as u64;
    strtab.extend_from_slice(needed.as_bytes());
    strtab.push(0);
    let soname_off = strtab.len() as u64;
    strtab.extend_from_slice(soname.as_bytes());
    strtab.push(0);
    let total = strtab_off + strtab.len() as u64;

    let mut v = Vec::new();
    v.extend_from_slice(&header(3, 2));
    v.extend_from_slice(&phdr(1, 0, 0, total)); // PT_LOAD
    v.extend_from_slice(&phdr(2, dyn_off, dyn_off, dyn_size)); // PT_DYNAMIC
    v.extend_from_slice(&dynent(5, strtab_off)); // DT_STRTAB (vaddr)
    v.extend_from_slice(&dynent(1, needed_off)); // DT_NEEDED
    v.extend_from_slice(&dynent(14, soname_off)); // DT_SONAME
    v.extend_from_slice(&dynent(0, 0)); // DT_NULL
    v.extend_from_slice(&strtab);
    v
}

// 32-bit le elf header, class=1 data=1
fn header32(e_type: u16, phnum: u16) -> [u8; 52] {
    let mut h = [0u8; 52];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 1; // class: 32-bit
    h[5] = 1; // data: little-endian
    h[6] = 1;
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h[18..20].copy_from_slice(&0x28u16.to_le_bytes()); // machine: arm
    h[20..24].copy_from_slice(&1u32.to_le_bytes());
    h[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff: after header
    h[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    h[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    h[44..46].copy_from_slice(&phnum.to_le_bytes());
    h
}

fn phdr32(kind: u32, offset: u32, vaddr: u32, filesz: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&kind.to_le_bytes());
    b[4..8].copy_from_slice(&offset.to_le_bytes());
    b[8..12].copy_from_slice(&vaddr.to_le_bytes());
    b[16..20].copy_from_slice(&filesz.to_le_bytes());
    b
}

fn dyn_exe32(interp: &str) -> Vec<u8> {
    let phnum = 3u32;
    let interp_off = 52 + 32 * phnum;
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let total = interp_off + interp_bytes.len() as u32;
    let mut v = Vec::new();
    v.extend_from_slice(&header32(2, phnum as u16));
    v.extend_from_slice(&phdr32(1, 0, 0, total));
    v.extend_from_slice(&phdr32(3, interp_off, interp_off, interp_bytes.len() as u32));
    v.extend_from_slice(&phdr32(2, 0, 0, 0));
    v.extend_from_slice(&interp_bytes);
    v
}

// 64-bit be elf header, class=2 data=2
fn header_be(e_type: u16, phnum: u16) -> [u8; 64] {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // class: 64-bit
    h[5] = 2; // data: big-endian
    h[6] = 1;
    h[16..18].copy_from_slice(&e_type.to_be_bytes());
    h[18..20].copy_from_slice(&0x16u16.to_be_bytes()); // machine: s390
    h[20..24].copy_from_slice(&1u32.to_be_bytes());
    h[32..40].copy_from_slice(&64u64.to_be_bytes()); // e_phoff
    h[52..54].copy_from_slice(&64u16.to_be_bytes()); // e_ehsize
    h[54..56].copy_from_slice(&56u16.to_be_bytes()); // e_phentsize
    h[56..58].copy_from_slice(&phnum.to_be_bytes());
    h
}

fn phdr_be(kind: u32, offset: u64, vaddr: u64, filesz: u64) -> [u8; 56] {
    let mut b = [0u8; 56];
    b[0..4].copy_from_slice(&kind.to_be_bytes());
    b[8..16].copy_from_slice(&offset.to_be_bytes());
    b[16..24].copy_from_slice(&vaddr.to_be_bytes());
    b[32..40].copy_from_slice(&filesz.to_be_bytes());
    b
}

fn dyn_exe_be(interp: &str) -> Vec<u8> {
    let phnum = 3u64;
    let interp_off = 64 + 56 * phnum;
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let total = interp_off + interp_bytes.len() as u64;
    let mut v = Vec::new();
    v.extend_from_slice(&header_be(2, phnum as u16));
    v.extend_from_slice(&phdr_be(1, 0, 0, total));
    v.extend_from_slice(&phdr_be(3, interp_off, interp_off, interp_bytes.len() as u64));
    v.extend_from_slice(&phdr_be(2, 0, 0, 0));
    v.extend_from_slice(&interp_bytes);
    v
}

// build a representative rootfs and return the tempdir
fn rootfs() -> Tmp {
    let t = Tmp::new();
    t.file("usr/bin/app", &dyn_exe("/lib/ld-musl-x86_64.so.1"));
    t.file("usr/bin/busybox", &static_exe());
    t.file("usr/lib/libfoo.so.1", &shared("libfoo.so.1", "libdep.so.1"));
    t.file("usr/lib/systemd/system/sshd.service", b"[Unit]\n");
    t.exec_file("etc/init.d/networking", b"#!/bin/sh\n");
    t.file("etc/init.d/README", b"not a service\n");
    t.file(
        "usr/share/applications/foo.desktop",
        b"[Desktop Entry]\nName=Foo\nIcon=foo\nExec=/usr/bin/foo --flag\n",
    );
    t.file("usr/share/xsessions/sway.desktop", b"[Desktop Entry]\nName=Sway\nExec=sway\n");
    t.file("usr/share/icons/Hicolor/48x48/apps/firefox.png", b"x");
    t.file("usr/share/icons/Hicolor/cursors/left_ptr", b"x");
    t.file("usr/share/themes/Adwaita/index.theme", b"x");
    t.file("usr/share/themes/Adwaita/gtk-3.0/gtk.css", b"x");
    t.file("usr/share/fonts/DejaVuSans-Bold.ttf", b"x");
    t.file("usr/share/fonts/arial.ttf", b"x");
    t.file("usr/share/locale/ru/LC_MESSAGES/app.mo", b"x");
    t.file("usr/lib/modules/6.9.0/kernel/drivers/foo.ko", b"x");
    // the package db holds the most files, even though sync/ has more direct
    // children than local/, and even though systemd's state dir is busy
    t.file("var/lib/pacman/local/bash-5.2/desc", b"x");
    t.file("var/lib/pacman/local/bash-5.2/files", b"x");
    t.file("var/lib/pacman/local/coreutils-9/desc", b"x");
    t.file("var/lib/pacman/local/coreutils-9/files", b"x");
    t.file("var/lib/pacman/sync/core.db", b"x");
    t.file("var/lib/systemd/catalog/database", b"x");
    t.dir("var/lib/dbus");
    t
}

#[test]
fn libc_from_bins() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let libc = p.libc.expect("a dynamic binary is present");
    assert_eq!(libc.interp, "/lib/ld-musl-x86_64.so.1");
    // the stem is the interp name, not a glibc/musl verdict
    assert_eq!(libc.name, "ld-musl-x86_64");
}

#[test]
fn bin_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let app = p.bin.iter().find(|b| b.path.ends_with("usr/bin/app")).unwrap();
    assert_eq!(app.interp.as_deref(), Some("/lib/ld-musl-x86_64.so.1"));
    assert!(app.dynamic);
    let bb = p.bin.iter().find(|b| b.path.ends_with("usr/bin/busybox")).unwrap();
    assert_eq!(bb.interp, None);
    assert!(!bb.dynamic);
}

#[test]
fn bin_needed_parsed_for_dynamic_exe() {
    let t = Tmp::new();
    t.exec_file("usr/bin/dyn", &dyn_exe_needed("/lib/ld-musl-x86_64.so.1", "libc.so"));
    t.exec_file("usr/bin/stat", &static_exe());
    let p = scanner::scan(&t.0);

    // a dynamic binary reports its DT_NEEDED entries
    let dynbin = p.bin.iter().find(|b| b.path.ends_with("usr/bin/dyn")).unwrap();
    assert!(dynbin.dynamic);
    assert_eq!(dynbin.needed, vec!["libc.so".to_string()]);

    // a static binary lists none
    let stat = p.bin.iter().find(|b| b.path.ends_with("usr/bin/stat")).unwrap();
    assert!(stat.needed.is_empty());
}

#[test]
fn lib_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let lib = p.lib.iter().find(|l| l.path.ends_with("libfoo.so.1")).unwrap();
    assert_eq!(lib.soname.as_deref(), Some("libfoo.so.1"));
    assert_eq!(lib.needed, vec!["libdep.so.1".to_string()]);
}

#[test]
fn desktop_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let app = p.apps.iter().find(|d| d.path.ends_with("foo.desktop")).unwrap();
    assert_eq!(app.name.as_deref(), Some("Foo"));
    assert_eq!(app.exec.as_deref(), Some("/usr/bin/foo --flag"));
    let session = &p.sessions[0];
    assert_eq!(session.kind, "x11");
    assert_eq!(session.name.as_deref(), Some("Sway"));
}

#[test]
fn icons_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let icon = &p.icons[0];
    assert_eq!(
        (icon.theme.as_str(), icon.size.as_str(), icon.name.as_str()),
        ("Hicolor", "48x48", "firefox")
    );
    // the theme kind comes from the engine subdir (gtk-3.0) inside it
    let theme = p.themes.iter().find(|th| th.name == "Adwaita").unwrap();
    assert_eq!(theme.kind, "gtk");
    let cur = p.cursors.iter().find(|c| c.name == "Hicolor").unwrap();
    assert_eq!(cur.count, 1);
}

#[test]
fn fonts_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let bold = p.fonts.iter().find(|f| f.name == "DejaVuSans-Bold").unwrap();
    assert_eq!(bold.format, "ttf");
    assert_eq!(bold.weight.as_deref(), Some("bold"));
    // a name with no weight token reports none, the font is still inventoried
    let arial = p.fonts.iter().find(|f| f.name == "arial").unwrap();
    assert_eq!(arial.weight, None);
}

#[test]
fn services_parse() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    let unit = p.services.iter().find(|s| s.name == "sshd").unwrap();
    assert_eq!(unit.kind, "service");
    let init = p.services.iter().find(|s| s.name == "networking").unwrap();
    assert_eq!(init.kind, "initscript");
    // a non-executable file under init.d is not a service
    assert!(!p.services.iter().any(|s| s.name == "README"));
}

#[test]
fn locale_mods() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    assert!(p.locale.iter().any(|l| l.lang == "ru"));
    let m = &p.modules[0];
    assert_eq!((m.name.as_str(), m.kernel.as_str()), ("foo", "6.9.0"));
}

#[test]
fn fhs_pm() {
    let t = rootfs();
    let p = scanner::scan(&t.0);
    assert!(p.fhs);
    // the scanner does not pick the pm: it reports the candidate dirs with
    // weights, and pacman (per-package records) outweighs the others
    let pacman = p.pm_dirs.iter().find(|(n, _)| n == "pacman").unwrap();
    let heaviest = p.pm_dirs.iter().max_by_key(|(_, w)| *w).unwrap();
    assert_eq!(&heaviest.0, "pacman");
    assert!(pacman.1 >= 5); // 4 local files + 1 sync file
}

#[test]
fn missing_tree_ok() {
    let t = Tmp::new();
    let p = scanner::scan(&t.0);
    assert!(p.bin.is_empty() && p.libc.is_none() && !p.fhs && p.pm_dirs.is_empty());
}

#[test]
fn non_fhs_bins() {
    let t = Tmp::new();
    // no usr/bin + etc, so fhs is false; binaries live in a store path
    t.file("nix/store/abcd1234-coreutils-9/bin/ls", &dyn_exe("/lib/ld-musl-x86_64.so.1"));
    let p = scanner::scan(&t.0);
    assert!(!p.fhs);
    assert!(p.bin.iter().any(|b| b.path.ends_with("bin/ls") && b.dynamic));
    assert!(p.libc.is_some());
}

#[test]
fn malformed_elf_ok() {
    let t = Tmp::new();
    let mut bad = vec![0u8; 64];
    bad[0..4].copy_from_slice(b"\x7fXXX"); // broken magic
    t.file("usr/bin/bad", &bad);
    let p = scanner::scan(&t.0);
    let bin = p.bin.iter().find(|b| b.path.ends_with("usr/bin/bad")).unwrap();
    // not an elf: no interp, not dynamic, and the scan completed
    assert_eq!(bin.interp, None);
    assert!(!bin.dynamic);
}

#[test]
fn gobo_bin_libc() {
    let t = Tmp::new();
    // Gobo has Programs/<name>/<version>/bin/. bin is a claimed leaf, reached
    // before the generic depth cap, so binaries and libc still resolve
    t.file("Programs/Bash/3.2/bin/bash", &dyn_exe("/lib/ld-musl-x86_64.so.1"));
    t.file("Programs/GCC/11.2/bin/gcc", &static_exe());
    let p = scanner::scan(&t.0);
    // gobo has no usr/bin + etc, so fhs is false; store_bin routes the paths
    assert!(!p.fhs);
    assert!(p.bin.iter().any(|b| b.path.ends_with("bin/bash") && b.dynamic));
    assert!(p.bin.iter().any(|b| b.path.ends_with("bin/gcc") && !b.dynamic));
    // libc from the first dynamic binary
    assert_eq!(p.libc.as_ref().unwrap().name, "ld-musl-x86_64");
}

#[test]
fn fifo_no_block() {
    use std::ffi::CString;
    let t = Tmp::new();
    // a service-shaped dir holding a fifo (e.g. ~/.steam/steam.pipe). opening it
    // would block forever; the probe must stat and skip it, never open
    t.file("etc/svc/web.service", b"[Unit]\n");
    let pipe = t.0.join("etc/svc/steam.pipe");
    let c = CString::new(pipe.as_os_str().as_encoded_bytes()).unwrap();
    let rc = unsafe { libc_mkfifo(c.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo failed");
    let p = scanner::scan(&t.0);
    assert_eq!(
        p.services.iter().find(|s| s.name == "web").map(|s| s.kind.as_str()),
        Some("service")
    );
    assert!(p.services.iter().all(|s| s.name != "steam"));
}

unsafe extern "C" {
    #[link_name = "mkfifo"]
    fn libc_mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
}

#[test]
fn deep_share_skip() {
    let t = Tmp::new();
    // Programs/<name>/<version>/share sits at generic depth 4. the depth cap
    // prunes it: a share dir named like ~/.local/share is structurally identical,
    // so chasing it deep would be the door into user data. shallow share resolves,
    // deep share does not  - the documented trade for keeping / safe
    t.file(
        "Programs/Bash/3.2/share/applications/bash.desktop",
        b"[Desktop Entry]\nName=Bash\nExec=/Programs/Bash/3.2/bin/bash\n",
    );
    t.file("Programs/Foo/1.0/share/icons/Tango/32x32/foo.png", b"x");
    let p = scanner::scan(&t.0);
    assert!(p.apps.is_empty());
    assert!(p.icons.is_empty());

    // a shallow share (depth ≤3) still resolves through the non-fhs fallback
    let t2 = Tmp::new();
    t2.file("opt/share/icons/Tango/32x32/foo.png", b"x");
    let p2 = scanner::scan(&t2.0);
    assert!(p2.icons.iter().any(|i| i.theme == "Tango" && i.name == "foo"));
}

#[test]
fn supervised() {
    let t = Tmp::new();
    // s6-style: /etc/s6/sv/sshd/run, /etc/s6/sv/nginx/run
    t.dir("etc/s6/sv/sshd");
    t.file("etc/s6/sv/sshd/run", b"#!/bin/execlineb\n");
    t.dir("etc/s6/sv/nginx");
    t.file("etc/s6/sv/nginx/run", b"#!/bin/sh\n");
    let p = scanner::scan(&t.0);
    let sshd = p.services.iter().find(|s| s.name == "sshd").unwrap();
    assert_eq!(sshd.kind, "supervised");
    let nginx = p.services.iter().find(|s| s.name == "nginx").unwrap();
    assert_eq!(nginx.kind, "supervised");
}

#[test]
fn units_suffix() {
    let t = Tmp::new();
    // units carry whatever extension; the kind is that extension verbatim, no
    // whitelist. a unit is gated by an opening [section], a script by +x. a
    // sectionless data file in the same dir is not a service
    t.file("etc/svc/web.service", b"[Unit]\nDescription=web\n");
    t.file("etc/svc/cache.timer", b"[Timer]\n");
    t.file("etc/svc/odd.frobnicate", b"; comment\n[Custom]\n"); // arbitrary suffix
    t.exec_file("etc/svc/legacy", b"#!/bin/sh\n"); // extensionless script
    t.file("etc/svc/state.db", b"\x00\x01\x02binary"); // data, not a service
    let p = scanner::scan(&t.0);
    let kind = |n: &str| p.services.iter().find(|s| s.name == n).map(|s| s.kind.as_str());
    assert_eq!(kind("web"), Some("service"));
    assert_eq!(kind("cache"), Some("timer"));
    assert_eq!(kind("odd"), Some("frobnicate"));
    assert_eq!(kind("legacy"), Some("initscript"));
    assert_eq!(kind("state"), None); // the .db file is not reported

    // a pure data directory votes as nothing: no service is emitted from it
    let t2 = Tmp::new();
    t2.file("var/lib/pm/sync/core.db", b"\x00bin");
    t2.file("var/lib/pm/sync/extra.db", b"\x00bin");
    t2.file("etc/ssl/certs/a.pem", b"-----BEGIN CERTIFICATE-----\n");
    t2.file("etc/ssl/certs/b.pem", b"-----BEGIN CERTIFICATE-----\n");
    let p2 = scanner::scan(&t2.0);
    assert!(p2.services.is_empty());
}

#[test]
fn directive_units() {
    let t = Tmp::new();
    // dinit-style specs: no extension, no [section], just key = value lines
    t.file("etc/dinit.d/sshd", b"type = process\ncommand = /usr/sbin/sshd -D\n");
    t.file("etc/dinit.d/boot", b"type = internal\nwaits-for = sshd\n");
    let p = scanner::scan(&t.0);
    let sshd = p.services.iter().find(|s| s.name == "sshd").unwrap();
    assert_eq!(sshd.kind, "unit"); // no extension to use as the kind
    assert!(p.services.iter().any(|s| s.name == "boot"));

    // sysctl drop-ins are key = value too, but the keys are dotted, so the
    // directive form rejects them and the directory is not a service collection
    let t2 = Tmp::new();
    t2.file("etc/sysctl.d/10-net.conf", b"net.core.somaxconn = 1024\n");
    t2.file("etc/sysctl.d/20-fs.conf", b"fs.file-max = 100000\n");
    let p2 = scanner::scan(&t2.0);
    assert!(p2.services.is_empty());
}

#[test]
fn deep_skip_probe() {
    let t = Tmp::new();
    t.dir("etc");
    // service collection at generic depth 3 from root is probed and detected
    for n in ["web.service", "db.service"] {
        t.file(&format!("x/y/svc/{n}"), b"[Unit]\n");
    }
    // identical shape buried at depth 4 pays only readdir, no file opens
    for n in ["web.service", "db.service"] {
        t.file(&format!("a/b/c/svc/{n}"), b"[Unit]\n");
    }
    let p = scanner::scan(&t.0);
    assert_eq!(p.services.iter().filter(|s| s.name == "web").count(), 1);
    assert_eq!(p.services.iter().filter(|s| s.name == "db").count(), 1);
}

#[test]
fn icons_format() {
    let t = Tmp::new();
    // formats no whitelist would have passed are inventoried by location alone
    t.file("usr/share/icons/Papirus/64x64/apps/app.webp", b"x");
    t.file("usr/share/icons/Papirus/64x64/apps/app.ico", b"x");
    let p = scanner::scan(&t.0);
    assert!(p.icons.iter().any(|i| i.name == "app" && i.size == "64x64"));
    assert_eq!(p.icons.len(), 2);
}

#[test]
fn fonts_any() {
    let t = Tmp::new();
    // .dfont is not in any short format list; the trailing token is the weight
    t.file("usr/share/fonts/Inter-Hairline.dfont", b"x");
    let p = scanner::scan(&t.0);
    let f = p.fonts.iter().find(|f| f.name == "Inter-Hairline").unwrap();
    assert_eq!(f.format, "dfont");
    assert_eq!(f.weight.as_deref(), Some("hairline"));
}

#[test]
fn theme_subdir() {
    let t = Tmp::new();
    // the engine is whatever the subdir is named, version stripped, not a table
    t.file("usr/share/themes/Clearlooks/metacity-1/metacity-theme-3.xml", b"x");
    t.file("usr/share/themes/Clearlooks/openbox-3/themerc", b"x");
    let p = scanner::scan(&t.0);
    let theme = p.themes.iter().find(|th| th.name == "Clearlooks").unwrap();
    assert_eq!(theme.kind, "metacity,openbox");
}

#[test]
fn non_fhs_libs() {
    let t = Tmp::new();
    // a store layout: the .so lives under .../lib/, mirrored from the bin rule
    t.file("nix/store/abcd-zlib-1/lib/libz.so.1", &shared("libz.so.1", "libc.so.6"));
    let p = scanner::scan(&t.0);
    assert!(!p.fhs);
    let lib = p.lib.iter().find(|l| l.path.ends_with("libz.so.1")).unwrap();
    assert_eq!(lib.soname.as_deref(), Some("libz.so.1"));
    assert_eq!(lib.needed, vec!["libc.so.6".to_string()]);
}

#[test]
fn desktop_group() {
    let t = Tmp::new();
    // the primary entry is the first group; a later [Desktop Action] must not
    // override Exec, and the group name is not matched against a literal
    t.file(
        "usr/share/applications/term.desktop",
        b"[Desktop Entry]\nName=Term\nExec=term\n\n[Desktop Action new]\nName=New\nExec=term --new\n",
    );
    let p = scanner::scan(&t.0);
    let app = p.apps.iter().find(|d| d.path.ends_with("term.desktop")).unwrap();
    assert_eq!(app.name.as_deref(), Some("Term"));
    assert_eq!(app.exec.as_deref(), Some("term"));
}

#[test]
fn scan_many() {
    let a = rootfs();
    let b = Tmp::new();
    let c = rootfs();
    let roots = vec![a.0.clone(), b.0.clone(), c.0.clone()];
    let profiles: Vec<_> =
        scanner::scan_many(&roots).into_iter().map(|r| r.expect("scan did not panic")).collect();
    assert_eq!(profiles.len(), 3);
    assert!(profiles[0].fhs); // a
    assert!(!profiles[1].fhs); // b is empty
    assert!(profiles[2].pm_dirs.iter().any(|(n, _)| n == "pacman")); // c
}

#[test]
fn bench_base() {
    let t = Tmp::new();
    t.dir("etc");
    for i in 0..1000 {
        t.file(&format!("usr/bin/cmd{i}"), &dyn_exe("/lib/ld-linux-x86-64.so.2"));
    }
    for i in 0..100 {
        t.file(
            &format!("usr/share/applications/app{i}.desktop"),
            b"[Desktop Entry]\nName=App\nExec=app\n",
        );
    }
    for i in 0..50 {
        t.file(&format!("usr/share/icons/Theme/48x48/apps/icon{i}.png"), b"x");
    }
    let start = std::time::Instant::now();
    let p = scanner::scan(&t.0);
    let elapsed = start.elapsed();
    // not a criterion, just a baseline to watch
    eprintln!(
        "scan baseline: {} bins, {} desktop, {} icons in {:?}",
        p.bin.len(),
        p.apps.len(),
        p.icons.len(),
        elapsed
    );
    assert_eq!(p.bin.len(), 1000);
}

#[test]
fn toolchain() {
    let t = Tmp::new();
    // gcc-style: <name>/<version>/crt*.o + *.a
    t.file("usr/lib/x86_64-linux-gnu/13/crtbegin.o", b"x");
    t.file("usr/lib/x86_64-linux-gnu/13/libgcc.a", b"x");
    // archive nested one level under the version dir
    t.file("usr/lib/mylang/2.1/lib/libcore.a", b"x");
    // not a toolchain: .so-only dir (plugin/dynload shape) must be ignored
    t.file("usr/lib/python3.11/lib-dynload/_struct.so", b"x");
    let p = scanner::scan(&t.0);
    assert!(p.toolchains.iter().any(|x| x.name == "x86_64-linux-gnu" && x.version == "13"));
    assert!(p.toolchains.iter().any(|x| x.name == "mylang" && x.version == "2.1"));
    assert!(!p.toolchains.iter().any(|x| x.name == "python3.11"));
}

#[test]
fn mime_counts_xml_only() {
    let t = Tmp::new();
    t.file("usr/share/mime/text/plain.xml", b"<x/>");
    t.file("usr/share/mime/image/png.xml", b"<x/>");
    t.file("usr/share/mime/globs2", b"text/plain:*.txt");
    t.file("usr/share/mime/mime.cache", b"\0\0");
    let p = scanner::scan(&t.0);
    assert_eq!(p.mime, 2);
}

#[test]
fn firmware() {
    let t = Tmp::new();
    t.file("usr/lib/firmware/iwlwifi-1.ucode", b"x");
    t.file("usr/lib/firmware/amd/cpu.bin", b"x");
    t.file("lib/firmware/edid/1024x768.bin", b"x");
    let p = scanner::scan(&t.0);
    assert_eq!(p.firmware, 3);
    // the paths are reported too, layer-relative and sorted, so a consumer can
    // merge the blobs and not just count them
    use std::path::PathBuf;
    assert_eq!(
        p.firmware_paths,
        vec![
            PathBuf::from("lib/firmware/edid/1024x768.bin"),
            PathBuf::from("usr/lib/firmware/amd/cpu.bin"),
            PathBuf::from("usr/lib/firmware/iwlwifi-1.ucode"),
        ]
    );
}

#[test]
fn udev_and_polkit() {
    let t = Tmp::new();
    // both etc and usr locations; udev rules and polkit rules are both *.rules,
    // told apart by directory
    t.file("etc/udev/rules.d/70-net.rules", b"x");
    t.file("usr/lib/udev/rules.d/60-block.rules", b"x");
    t.file("usr/lib/udev/hwdb.d/20-pci.hwdb", b"x");
    t.file("etc/polkit-1/rules.d/50-org.rules", b"x");
    t.file("usr/share/polkit-1/actions/org.foo.policy", b"x");
    let p = scanner::scan(&t.0);
    use std::path::PathBuf;
    assert_eq!(
        p.udev_rules,
        vec![
            PathBuf::from("etc/udev/rules.d/70-net.rules"),
            PathBuf::from("usr/lib/udev/rules.d/60-block.rules"),
        ]
    );
    assert_eq!(p.udev_hwdb, vec![PathBuf::from("usr/lib/udev/hwdb.d/20-pci.hwdb")]);
    assert_eq!(p.polkit_rules, vec![PathBuf::from("etc/polkit-1/rules.d/50-org.rules")]);
    assert_eq!(p.polkit_actions, vec![PathBuf::from("usr/share/polkit-1/actions/org.foo.policy")]);
}

#[test]
fn kernel_vfs() {
    let t = Tmp::new();
    t.dir("etc");
    // service-shaped trees inside top-level kernel mountpoints must be ignored,
    // not descended into (proc/sys/dev recurse without end on a live system)
    t.file("proc/sv/p/run", b"#!/bin/sh\n");
    t.file("sys/sv/s/run", b"#!/bin/sh\n");
    t.file("dev/sv/d/run", b"#!/bin/sh\n");
    t.file("run/sv/r/run", b"#!/bin/sh\n");
    // a tmp dir nested inside a package is ordinary content, still scanned
    t.file("etc/tmp/sv/keep/run", b"#!/bin/sh\n");
    let p = scanner::scan(&t.0);
    assert!(p.services.iter().any(|s| s.name == "keep"));
    for skipped in ["p", "s", "d", "r"] {
        assert!(p.services.iter().all(|s| s.name != skipped));
    }
}

#[test]
fn large_svc() {
    // a real systemd dir can hold well over the fanout cap; the sampled vote
    // must still recognise it and harvest every unit
    let t = Tmp::new();
    t.dir("etc");
    for i in 0..600 {
        t.file(&format!("etc/myinit/unit{i}.service"), b"[Unit]\nDescription=x\n");
    }
    let p = scanner::scan(&t.0);
    let units = p.services.iter().filter(|s| s.kind == "service").count();
    assert_eq!(units, 600);
}

#[test]
fn huge_fanout() {
    // over the cap and not service-shaped: bulk data, not descended. a service
    // tree buried inside must not be harvested
    let t = Tmp::new();
    t.dir("etc");
    for i in 0..600 {
        t.file(&format!("opt/blob/data{i}"), b"\x00\x01");
    }
    t.file("opt/blob/sv/buried/run", b"#!/bin/sh\n");
    let p = scanner::scan(&t.0);
    assert!(p.services.iter().all(|s| s.name != "buried"));

    // same shape under the cap: descended, the buried service is found
    let t2 = Tmp::new();
    t2.dir("etc");
    for i in 0..10 {
        t2.file(&format!("opt/blob/data{i}"), b"\x00\x01");
    }
    t2.file("opt/blob/sv/buried/run", b"#!/bin/sh\n");
    let p2 = scanner::scan(&t2.0);
    assert!(p2.services.iter().any(|s| s.name == "buried"));
}

#[test]
fn diverse_no_svc() {
    // every file is executable (service-shaped on its own), but the suffixes are
    // all distinct: the dir is source/data, not an init dir. the diversity gate
    // rejects it without a vote, so nothing is harvested as a service
    let t = Tmp::new();
    t.dir("etc");
    for i in 0..14 {
        t.exec_file(&format!("opt/proj/tool.e{i}"), b"#!/bin/sh\n");
    }
    let p = scanner::scan(&t.0);
    assert!(p.services.is_empty());

    // the same files under one suffix are a homogeneous dir: harvested
    let t2 = Tmp::new();
    t2.dir("etc");
    for i in 0..14 {
        t2.exec_file(&format!("opt/proj/tool{i}.sh"), b"#!/bin/sh\n");
    }
    let p2 = scanner::scan(&t2.0);
    assert_eq!(p2.services.iter().filter(|s| s.kind == "sh").count(), 14);
}

#[test]
fn elf32() {
    let t = Tmp::new();
    t.file("usr/bin/app32", &dyn_exe32("/lib/ld-musl-arm.so.1"));
    let p = scanner::scan(&t.0);
    let bin = p.bin.iter().find(|b| b.path.ends_with("app32")).unwrap();
    assert_eq!(bin.interp.as_deref(), Some("/lib/ld-musl-arm.so.1"));
    assert!(bin.dynamic);
}

#[test]
fn elf64_be() {
    let t = Tmp::new();
    t.file("usr/bin/app_be", &dyn_exe_be("/lib/ld64.so.1"));
    let p = scanner::scan(&t.0);
    let bin = p.bin.iter().find(|b| b.path.ends_with("app_be")).unwrap();
    assert_eq!(bin.interp.as_deref(), Some("/lib/ld64.so.1"));
    assert!(bin.dynamic);
}

#[test]
fn module_zst() {
    let t = Tmp::new();
    t.file("usr/lib/modules/6.1.0/kernel/drivers/foo.ko.zst", b"\x28\xb5\x2f\xfd");
    t.dir("etc");
    let p = scanner::scan(&t.0);
    let m = &p.modules[0];
    assert_eq!(m.name, "foo");
    assert_eq!(m.kernel, "6.1.0");
}

#[test]
fn merged_root_dedup() {
    let t = Tmp::new();
    t.dir("usr/lib/firmware");
    t.file("usr/lib/firmware/foo.bin", b"\x00");
    std::os::unix::fs::symlink("usr/lib", t.0.join("lib")).unwrap();
    let p = scanner::scan(&t.0);
    assert_eq!(p.firmware, 1);
}

#[test]
fn scan_many_edge() {
    let empty: Vec<PathBuf> = vec![];
    let results = scanner::scan_many(&empty);
    assert!(results.is_empty());

    let t = Tmp::new();
    t.dir("etc");
    t.file("usr/bin/app", &dyn_exe("/lib/ld-linux-x86-64.so.2"));
    let results = scanner::scan_many(std::slice::from_ref(&t.0));
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
}

#[test]
fn man_pages() {
    let t = Tmp::new();
    t.dir("etc");
    t.file("usr/share/man/man1/ls.1", b".TH LS 1\n");
    t.file("usr/share/man/man1/ls.1.gz", b"\x1f\x8b");
    t.file("usr/share/man/ru/man5/termcap.5", b".TH TERMCAP 5\n");
    t.file("usr/share/man/manX/custom.5", b".TH CUSTOM 5\n");
    let p = scanner::scan(&t.0);
    assert_eq!(p.man.len(), 4);
    let ls = p.man.iter().find(|m| m.name == "ls" && m.section == "1").unwrap();
    assert_eq!(ls.lang, None);
    let ru = p.man.iter().find(|m| m.name == "termcap" && m.lang.as_deref() == Some("ru")).unwrap();
    assert_eq!(ru.section, "5");
    let custom = p.man.iter().find(|m| m.section == "X").unwrap();
    assert_eq!(custom.name, "custom");
}

#[test]
fn hash_interp_script() {
    let t = rootfs();
    t.exec_file("usr/bin/script.sh", b"#!/bin/bash\necho x\n");
    let p = scanner::scan(&t.0);
    let script = p.bin.iter().find(|b| b.path.ends_with("script.sh")).unwrap();
    assert_eq!(script.script.as_deref(), Some("/bin/bash"));
    assert!(!script.dynamic);
    assert_eq!(script.interp, None);
}

#[test]
fn new_bin_roots() {
    let t = rootfs();
    t.exec_file("opt/bin/firefox", &static_exe());
    t.exec_file("usr/libexec/helper", &dyn_exe("/lib/ld-musl-x86_64.so.1"));
    t.exec_file("usr/games/2048", &static_exe());
    let p = scanner::scan(&t.0);
    assert!(p.bin.iter().any(|b| b.path.ends_with("opt/bin/firefox")));
    assert!(p.bin.iter().any(|b| b.path.ends_with("usr/libexec/helper")));
    assert!(p.bin.iter().any(|b| b.path.ends_with("usr/games/2048")));
}

#[test]
fn shallow_non_fhs() {
    let t = Tmp::new();
    t.file("opt/foo/bin/cmd", &dyn_exe("/lib/ld-musl-x86_64.so.1"));
    let p = scanner::scan(&t.0);
    assert!(!p.fhs);
    assert!(p.bin.iter().any(|b| b.path.ends_with("opt/foo/bin/cmd")));
}

#[test]
fn mixed_libc() {
    let t = rootfs();
    t.file("usr/bin/glibc-app", &dyn_exe("/lib64/ld-linux-x86-64.so.2"));
    let p = scanner::scan(&t.0);
    assert!(p.all_libcs.iter().any(|l| l.name == "ld-musl-x86_64"));
    assert!(p.all_libcs.iter().any(|l| l.name == "ld-linux-x86-64"));
    assert_eq!(p.all_libcs.len(), 2);
    // libc is the first in sorted order (usr/bin/app with musl comes first)
    assert_eq!(p.libc.as_ref().unwrap().name, "ld-musl-x86_64");
}

#[test]
fn custom_bin_roots() {
    let t = Tmp::new();
    t.dir("etc");
    // a distro that puts binaries under /System/Applications/
    t.file("System/Applications/bash", &dyn_exe("/lib/ld-linux-x86-64.so.2"));
    t.file("System/Applications/ls", &static_exe());
    t.file("System/Libraries/libz.so.1", b"x");

    // built-in only: misses the custom layout
    let p_default = scanner::scan(&t.0);
    assert!(p_default.bin.is_empty());
    assert!(p_default.lib.is_empty());

    // with custom roots: detects binaries and libs
    let config = scanner::ScanConfig::new()
        .with_bin_root("System/Applications")
        .with_lib_root("System/Libraries");
    let p = scanner::scan_with(&t.0, &config);
    assert_eq!(p.bin.len(), 2);
    assert!(p.bin.iter().any(|b| b.path.ends_with("bash") && b.dynamic));
    assert!(p.bin.iter().any(|b| b.path.ends_with("ls") && !b.dynamic));
    assert_eq!(p.lib.len(), 1);
    assert!(p.lib.iter().any(|l| l.path.ends_with("libz.so.1")));
}
