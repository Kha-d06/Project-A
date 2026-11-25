//! EMBER-style static features, written from the published feature
//! descriptions (Anderson & Roth, 2018), not from EMBER's code.
//!
//! Two steps, as in that paper:
//! 1. `RawFeatures`: what the file says about itself (byte statistics,
//!    strings, headers, sections, imports, exports), as plain data.
//! 2. `vectorize`: a fixed-length vector for the tree model. Names (sections,
//!    imported functions) are folded into buckets with FNV-1a, so the vector
//!    length never changes. `tools/scan-model/vectorize.py` does exactly the
//!    same; `tests/fixtures/vector-parity.json` keeps the two in step.

use goblin::Object;
use serde::{Deserialize, Serialize};

pub const FEATURE_VERSION: u32 = 1;

const ENTROPY_WINDOW: usize = 2048;
const ENTROPY_STEP: usize = 1024;
const MIN_STRING: usize = 5;
const MAX_NAMES: usize = 10_000;

/// Bucket counts for hashed name groups.
pub const SECTION_BUCKETS: usize = 50;
pub const LIBRARY_BUCKETS: usize = 256;
pub const FUNCTION_BUCKETS: usize = 1024;
pub const EXPORT_BUCKETS: usize = 128;
pub const MACHINE_BUCKETS: usize = 10;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub vsize: u64,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Header {
    pub timestamp: u64,
    pub machine: String,
    pub characteristics: u64,
    pub subsystem: u64,
    pub dll_characteristics: u64,
    pub major_image_version: u64,
    pub major_linker_version: u64,
    pub major_os_version: u64,
    pub size_of_code: u64,
    pub size_of_headers: u64,
    pub size_of_heap_commit: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Strings {
    pub count: u64,
    pub avg_length: f64,
    /// Share of each printable character (0x20..0x7f) among all string bytes.
    pub printable_dist: Vec<f64>,
    pub entropy: f64,
    pub paths: u64,
    pub urls: u64,
    pub registry: u64,
    pub mz: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RawFeatures {
    pub version: u32,
    /// "pe", "elf", "macho" or "other".
    pub format: String,
    pub size: u64,
    pub vsize: u64,
    pub byte_histogram: Vec<f64>,
    pub byte_entropy_histogram: Vec<f64>,
    pub strings: Strings,
    pub header: Header,
    pub sections: Vec<Section>,
    pub entry_section: String,
    /// "library:function", lower-case library name.
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub has_debug: bool,
    pub has_relocations: bool,
    pub has_resources: bool,
    pub has_signature: bool,
    pub has_tls: bool,
    pub symbols: u64,
    /// Set when the header claimed a format but couldn't be parsed.
    pub parse_error: Option<String>,
}

pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

pub fn byte_histogram(bytes: &[u8]) -> Vec<f64> {
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len().max(1) as f64;
    counts.iter().map(|&c| c as f64 / n).collect()
}

/// 16 x 16 joint histogram of (window entropy, high nibble of each byte).
pub fn byte_entropy_histogram(bytes: &[u8]) -> Vec<f64> {
    let mut out = vec![0f64; 256];
    let windows: Vec<&[u8]> = if bytes.len() < ENTROPY_WINDOW {
        if bytes.is_empty() {
            vec![]
        } else {
            vec![bytes]
        }
    } else {
        (0..=(bytes.len() - ENTROPY_WINDOW))
            .step_by(ENTROPY_STEP)
            .map(|i| &bytes[i..i + ENTROPY_WINDOW])
            .collect()
    };
    for w in &windows {
        let mut nibbles = [0u64; 16];
        for &b in *w {
            nibbles[(b >> 4) as usize] += 1;
        }
        let n = w.len() as f64;
        // Entropy over nibbles is at most 4 bits; scaled to 16 rows.
        let h: f64 = nibbles
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.log2()
            })
            .sum();
        let row = ((h * 4.0) as usize).min(15);
        for (col, &c) in nibbles.iter().enumerate() {
            out[row * 16 + col] += c as f64;
        }
    }
    let total: f64 = out.iter().sum();
    if total > 0.0 {
        for v in &mut out {
            *v /= total;
        }
    }
    out
}

pub fn strings(bytes: &[u8]) -> Strings {
    let mut s = Strings {
        printable_dist: vec![0.0; 96],
        ..Default::default()
    };
    let mut total_len = 0u64;
    let mut dist = [0u64; 96];
    let mut start: Option<usize> = None;
    let mut handle = |run: &[u8], s: &mut Strings| {
        if run.len() < MIN_STRING {
            return;
        }
        s.count += 1;
        total_len += run.len() as u64;
        for &b in run {
            dist[(b - 0x20) as usize] += 1;
        }
        let lower: Vec<u8> = run.iter().map(|b| b.to_ascii_lowercase()).collect();
        if contains(&lower, b"c:\\") {
            s.paths += 1;
        }
        if contains(&lower, b"http://") || contains(&lower, b"https://") {
            s.urls += 1;
        }
        if contains(&lower, b"hkey_") {
            s.registry += 1;
        }
        if contains(run, b"MZ") {
            s.mz += 1;
        }
    };
    for (i, &b) in bytes.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(st)) => {
                handle(&bytes[st..i], &mut s);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(st) = start {
        handle(&bytes[st..], &mut s);
    }
    if s.count > 0 {
        s.avg_length = total_len as f64 / s.count as f64;
    }
    if total_len > 0 {
        s.printable_dist = dist.iter().map(|&c| c as f64 / total_len as f64).collect();
        let h: f64 = dist
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total_len as f64;
                -p * p.log2()
            })
            .sum();
        s.entropy = h;
    }
    s
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn slice(bytes: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = (offset as usize).min(bytes.len());
    let end = start.saturating_add(size as usize).min(bytes.len());
    &bytes[start..end]
}

fn pe_machine(m: u16) -> &'static str {
    match m {
        0x14c => "I386",
        0x8664 => "AMD64",
        0x1c0 => "ARM",
        0x1c4 => "ARMNT",
        0xaa64 => "ARM64",
        0x200 => "IA64",
        _ => "UNKNOWN",
    }
}

pub fn extract(bytes: &[u8]) -> RawFeatures {
    let mut raw = RawFeatures {
        version: FEATURE_VERSION,
        format: "other".into(),
        size: bytes.len() as u64,
        byte_histogram: byte_histogram(bytes),
        byte_entropy_histogram: byte_entropy_histogram(bytes),
        strings: strings(bytes),
        ..Default::default()
    };
    match Object::parse(bytes) {
        Ok(Object::PE(pe)) => fill_pe(&mut raw, bytes, &pe),
        Ok(Object::Elf(elf)) => fill_elf(&mut raw, bytes, &elf),
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => fill_macho(&mut raw, bytes, &m),
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => raw.format = "macho".into(),
        Ok(_) => {}
        Err(e) => {
            if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
                raw.parse_error = Some(e.to_string().chars().take(200).collect());
            }
        }
    }
    raw
}

fn fill_pe(raw: &mut RawFeatures, bytes: &[u8], pe: &goblin::pe::PE) {
    raw.format = "pe".into();
    let coff = &pe.header.coff_header;
    raw.header.timestamp = coff.time_date_stamp as u64;
    raw.header.machine = pe_machine(coff.machine).into();
    raw.header.characteristics = coff.characteristics as u64;
    raw.symbols = coff.number_of_symbol_table as u64;
    if let Some(opt) = &pe.header.optional_header {
        let w = &opt.windows_fields;
        raw.header.subsystem = w.subsystem as u64;
        raw.header.dll_characteristics = w.dll_characteristics as u64;
        raw.header.major_image_version = w.major_image_version as u64;
        raw.header.major_os_version = w.major_operating_system_version as u64;
        raw.header.size_of_headers = w.size_of_headers as u64;
        raw.header.size_of_heap_commit = w.size_of_heap_commit;
        raw.header.major_linker_version = opt.standard_fields.major_linker_version as u64;
        raw.header.size_of_code = opt.standard_fields.size_of_code;
        raw.vsize = w.size_of_image as u64;
        let dd = &opt.data_directories;
        raw.has_resources = dd.get_resource_table().is_some_and(|d| d.size > 0);
        raw.has_signature = dd.get_certificate_table().is_some_and(|d| d.size > 0);
        raw.has_relocations = dd.get_base_relocation_table().is_some_and(|d| d.size > 0);
        raw.has_tls = dd.get_tls_table().is_some_and(|d| d.size > 0);
        raw.has_debug = dd.get_debug_table().is_some_and(|d| d.size > 0);
    }
    let entry = pe.entry as u64;
    for s in &pe.sections {
        let name = s.name().unwrap_or("").trim_end_matches('\0').to_string();
        let data = slice(bytes, s.pointer_to_raw_data as u64, s.size_of_raw_data as u64);
        let va = s.virtual_address as u64;
        if entry >= va && entry < va + (s.virtual_size.max(s.size_of_raw_data) as u64) {
            raw.entry_section = name.clone();
        }
        raw.sections.push(Section {
            name,
            size: s.size_of_raw_data as u64,
            vsize: s.virtual_size as u64,
            entropy: entropy(data),
            executable: s.characteristics & 0x2000_0000 != 0,
            writable: s.characteristics & 0x8000_0000 != 0,
        });
    }
    for i in pe.imports.iter().take(MAX_NAMES) {
        raw.imports.push(format!("{}:{}", i.dll.to_ascii_lowercase(), i.name));
    }
    for e in pe.exports.iter().take(MAX_NAMES) {
        if let Some(n) = e.name {
            raw.exports.push(n.to_string());
        }
    }
}

fn fill_elf(raw: &mut RawFeatures, bytes: &[u8], elf: &goblin::elf::Elf) {
    raw.format = "elf".into();
    raw.header.machine = format!("ELF{}", elf.header.e_machine);
    raw.header.characteristics = elf.header.e_type as u64;
    raw.symbols = elf.syms.len() as u64;
    raw.has_debug = elf
        .section_headers
        .iter()
        .any(|s| elf.shdr_strtab.get_at(s.sh_name).is_some_and(|n| n.starts_with(".debug")));
    raw.has_relocations = !elf.dynrelas.is_empty() || !elf.dynrels.is_empty();
    raw.has_tls = elf.program_headers.iter().any(|p| p.p_type == goblin::elf::program_header::PT_TLS);
    let entry = elf.entry;
    for s in &elf.section_headers {
        if s.sh_type == goblin::elf::section_header::SHT_NULL {
            continue;
        }
        let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").to_string();
        let data = if s.sh_type == goblin::elf::section_header::SHT_NOBITS {
            &[][..]
        } else {
            slice(bytes, s.sh_offset, s.sh_size)
        };
        if s.is_alloc() && entry >= s.sh_addr && entry < s.sh_addr + s.sh_size {
            raw.entry_section = name.clone();
        }
        raw.vsize += if s.is_alloc() { s.sh_size } else { 0 };
        raw.sections.push(Section {
            name,
            size: data.len() as u64,
            vsize: s.sh_size,
            entropy: entropy(data),
            executable: s.is_executable(),
            writable: s.is_writable(),
        });
    }
    let libs: Vec<String> = elf.libraries.iter().map(|l| l.to_ascii_lowercase()).collect();
    let lib = libs.first().cloned().unwrap_or_default();
    for sym in elf.dynsyms.iter().take(MAX_NAMES) {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else { continue };
        if name.is_empty() {
            continue;
        }
        if sym.is_import() {
            raw.imports.push(format!("{lib}:{name}"));
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL && sym.st_value != 0 {
            raw.exports.push(name.to_string());
        }
    }
    for l in libs {
        raw.imports.push(format!("{l}:"));
    }
}

fn fill_macho(raw: &mut RawFeatures, bytes: &[u8], m: &goblin::mach::MachO) {
    raw.format = "macho".into();
    raw.header.machine = format!("MACHO{}", m.header.cputype);
    raw.header.characteristics = m.header.flags as u64;
    for seg in &m.segments {
        let Ok(sections) = seg.sections() else { continue };
        for (s, data) in sections {
            let name = s.name().unwrap_or("").to_string();
            raw.sections.push(Section {
                name,
                size: data.len() as u64,
                vsize: s.size,
                entropy: entropy(data),
                executable: s.flags & 0x8000_0400 != 0,
                writable: seg.initprot & 0x2 != 0,
            });
        }
        raw.vsize += seg.vmsize;
    }
    let _ = bytes;
    if let Ok(imports) = m.imports() {
        for i in imports.iter().take(MAX_NAMES) {
            raw.imports.push(format!("{}:{}", i.dylib.to_ascii_lowercase(), i.name));
        }
    }
    if let Ok(exports) = m.exports() {
        for e in exports.iter().take(MAX_NAMES) {
            raw.exports.push(e.name.clone());
        }
    }
}

/// FNV-1a, 32-bit: the same in Rust and in the training script.
pub fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn hashed(names: impl IntoIterator<Item = (String, f64)>, buckets: usize) -> Vec<f64> {
    let mut out = vec![0f64; buckets];
    for (name, value) in names {
        out[(fnv1a(&name) as usize) % buckets] += value;
    }
    out
}

pub const VECTOR_LEN: usize = 256
    + 256
    + 104
    + 10
    + 3
    + 7
    + MACHINE_BUCKETS
    + 8
    + 5
    + SECTION_BUCKETS * 3
    + SECTION_BUCKETS
    + LIBRARY_BUCKETS
    + FUNCTION_BUCKETS
    + EXPORT_BUCKETS;

/// The fixed-length vector the model reads. Order matters: keep in step with vectorize.py.
pub fn vectorize(r: &RawFeatures) -> Vec<f64> {
    let mut v = Vec::with_capacity(VECTOR_LEN);
    v.extend(&r.byte_histogram);
    v.extend(&r.byte_entropy_histogram);
    // strings (104)
    let s = &r.strings;
    v.extend([
        s.count as f64,
        s.avg_length,
        s.entropy,
        s.paths as f64,
        s.urls as f64,
        s.registry as f64,
        s.mz as f64,
        (s.count as f64 + 1.0).ln(),
    ]);
    let mut dist = s.printable_dist.clone();
    dist.resize(96, 0.0);
    v.extend(dist);
    // general (10)
    v.extend([
        r.size as f64,
        r.vsize as f64,
        r.has_debug as u8 as f64,
        r.exports.len() as f64,
        r.imports.len() as f64,
        r.has_relocations as u8 as f64,
        r.has_resources as u8 as f64,
        r.has_signature as u8 as f64,
        r.has_tls as u8 as f64,
        r.symbols as f64,
    ]);
    // format (3)
    v.extend(["pe", "elf", "macho"].map(|f| (r.format == f) as u8 as f64));
    // header (7 + machine buckets + 8)
    let h = &r.header;
    v.extend([
        h.timestamp as f64,
        h.characteristics as f64,
        h.subsystem as f64,
        h.dll_characteristics as f64,
        h.major_image_version as f64,
        h.major_linker_version as f64,
        h.major_os_version as f64,
    ]);
    v.extend(hashed([(h.machine.clone(), 1.0)], MACHINE_BUCKETS));
    v.extend([h.size_of_code as f64, h.size_of_headers as f64, h.size_of_heap_commit as f64]);
    for bit in 0..5u64 {
        // A few characteristics flags as their own features.
        v.push(((h.characteristics >> bit) & 1) as f64);
    }
    // sections summary (5)
    let secs = &r.sections;
    v.extend([
        secs.len() as f64,
        secs.iter().filter(|s| s.size == 0).count() as f64,
        secs.iter().filter(|s| s.name.is_empty()).count() as f64,
        secs.iter().filter(|s| s.executable).count() as f64,
        secs.iter().filter(|s| s.writable).count() as f64,
    ]);
    // per-name size, entropy, vsize; then the entry section's name
    v.extend(hashed(secs.iter().map(|s| (s.name.clone(), s.size as f64)), SECTION_BUCKETS));
    v.extend(hashed(secs.iter().map(|s| (s.name.clone(), s.entropy)), SECTION_BUCKETS));
    v.extend(hashed(secs.iter().map(|s| (s.name.clone(), s.vsize as f64)), SECTION_BUCKETS));
    v.extend(hashed([(r.entry_section.clone(), 1.0)], SECTION_BUCKETS));
    // imports: libraries, then library:function
    let libs: std::collections::BTreeSet<String> = r.imports.iter().map(|i| i.split(':').next().unwrap_or("").to_string()).collect();
    v.extend(hashed(libs.into_iter().map(|l| (l, 1.0)), LIBRARY_BUCKETS));
    v.extend(hashed(
        r.imports.iter().filter(|i| !i.ends_with(':')).map(|i| (i.clone(), 1.0)),
        FUNCTION_BUCKETS,
    ));
    v.extend(hashed(r.exports.iter().map(|e| (e.clone(), 1.0)), EXPORT_BUCKETS));
    debug_assert_eq!(v.len(), VECTOR_LEN);
    v
}
