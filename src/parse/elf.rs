// elf parser, le/be and 32/64 aware, None on malformed

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_SONAME: u64 = 14;

pub struct Dyn {
    pub soname: Option<String>,
    pub needed: Vec<String>,
}

pub struct BinInfo {
    pub interp: Option<String>,
    pub dynamic: bool,
}

pub fn bin(path: &Path) -> Option<BinInfo> {
    let mut elf = Elf::open(path)?;
    let dynamic = elf.is_dynamic();
    let interp = elf.interp();
    Some(BinInfo { interp, dynamic })
}

pub fn dynamic(path: &Path) -> Option<Dyn> {
    Elf::open(path)?.read_dyn()
}

struct Phdr {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

struct Elf {
    file: File,
    class: u8,
    data: u8,
    phdrs: Vec<Phdr>,
}

impl Elf {
    fn open(path: &Path) -> Option<Elf> {
        let mut file = File::open(path).ok()?;
        let mut idyn_entry = [0u8; 64];
        file.read_exact(&mut idyn_entry).ok()?;
        if &idyn_entry[0..4] != b"\x7fELF" {
            return None;
        }
        let class = idyn_entry[4];
        let data = idyn_entry[5];
        if (class != 1 && class != 2) || (data != 1 && data != 2) {
            return None;
        }
        let (phoff, phentsize, phnum) = match class {
            1 => (
                r32(&idyn_entry[28..32], data)? as u64,
                r16(&idyn_entry[42..44], data)? as usize,
                r16(&idyn_entry[44..46], data)? as usize,
            ),
            _ => (
                r64(&idyn_entry[32..40], data)?,
                r16(&idyn_entry[54..56], data)? as usize,
                r16(&idyn_entry[56..58], data)? as usize,
            ),
        };
        let min = if class == 1 { 32 } else { 56 };
        if phentsize < min || phnum == 0 || phnum > 4096 {
            return None;
        }
        let mut phdrs = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let off = phoff.checked_add((i * phentsize) as u64)?;
            let raw = seek_read(&mut file, off, phentsize)?;
            phdrs.push(phdr(&raw, class, data)?);
        }
        Some(Elf { file, class, data, phdrs })
    }

    fn is_dynamic(&self) -> bool {
        self.phdrs.iter().any(|p| p.kind == PT_DYNAMIC)
    }

    fn interp(&mut self) -> Option<String> {
        let (off, len) = {
            let p = self.phdrs.iter().find(|p| p.kind == PT_INTERP)?;
            (p.offset, (p.filesz as usize).min(4096))
        };
        let raw = seek_read(&mut self.file, off, len)?;
        Some(read_cstr(&raw))
    }

    fn read_dyn(mut self) -> Option<Dyn> {
        let (off, size) = {
            let p = self.phdrs.iter().find(|p| p.kind == PT_DYNAMIC)?;
            (p.offset, p.filesz as usize)
        };
        let raw = seek_read(&mut self.file, off, size)?;
        let esize = if self.class == 1 { 8 } else { 16 };

        let mut strtab_vaddr = None;
        let mut soname_off = None;
        let mut needed = Vec::new();
        let mut i = 0;
        while i + esize <= raw.len() {
            let (tag, val) = dyn_entry(&raw[i..i + esize], self.class, self.data)?;
            match tag {
                DT_NULL => break,
                DT_STRTAB => strtab_vaddr = Some(val),
                DT_SONAME => soname_off = Some(val),
                DT_NEEDED => needed.push(val),
                _ => {}
            }
            i += esize;
        }

        // vaddr to file offset via PT_LOAD
        let strtab_off = self.v2f(strtab_vaddr?)?;
        let soname = soname_off.and_then(|o| strtab(&mut self.file, strtab_off, o));
        let needed = needed.iter().filter_map(|o| strtab(&mut self.file, strtab_off, *o)).collect();
        Some(Dyn { soname, needed })
    }

    fn v2f(&self, vaddr: u64) -> Option<u64> {
        for p in &self.phdrs {
            if p.kind == PT_LOAD && vaddr >= p.vaddr && vaddr < p.vaddr.checked_add(p.filesz)? {
                return p.offset.checked_add(vaddr - p.vaddr);
            }
        }
        None
    }
}

fn phdr(b: &[u8], class: u8, data: u8) -> Option<Phdr> {
    let kind = r32(&b[0..4], data)?;
    let (offset, vaddr, filesz) = match class {
        1 => (
            r32(&b[4..8], data)? as u64,
            r32(&b[8..12], data)? as u64,
            r32(&b[16..20], data)? as u64,
        ),
        _ => (r64(&b[8..16], data)?, r64(&b[16..24], data)?, r64(&b[32..40], data)?),
    };
    Some(Phdr { kind, offset, vaddr, filesz })
}

fn dyn_entry(b: &[u8], class: u8, data: u8) -> Option<(u64, u64)> {
    match class {
        1 => Some((r32(&b[0..4], data)? as u64, r32(&b[4..8], data)? as u64)),
        _ => Some((r64(&b[0..8], data)?, r64(&b[8..16], data)?)),
    }
}

fn strtab(file: &mut File, base: u64, off: u64) -> Option<String> {
    let raw = seek_read(file, base.checked_add(off)?, 256)?;
    let s = read_cstr(&raw);
    if s.is_empty() { None } else { Some(s) }
}

fn read_cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn seek_read(file: &mut File, off: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 || len > 1 << 20 {
        return None;
    }
    file.seek(SeekFrom::Start(off)).ok()?;
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    buf.truncate(filled);
    if buf.is_empty() { None } else { Some(buf) }
}

fn r16(b: &[u8], data: u8) -> Option<u16> {
    let a = b.try_into().ok()?;
    Some(if data == 1 { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) })
}

fn r32(b: &[u8], data: u8) -> Option<u32> {
    let a = b.try_into().ok()?;
    Some(if data == 1 { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
}

fn r64(b: &[u8], data: u8) -> Option<u64> {
    let a = b.try_into().ok()?;
    Some(if data == 1 { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
}
