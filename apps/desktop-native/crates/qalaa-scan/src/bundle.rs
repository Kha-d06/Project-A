//! Signed rule and model bundles.
//!
//! A bundle is a folder:
//!
//! ```text
//! manifest.json   {"format":1,"version":"2026.11.25.1","created":"…",
//!                  "files":{"rules/qalaa.yar":{"sha256":"…","size":123},
//!                           "model.json":{"sha256":"…","size":456}}}
//! manifest.sig    base64 of the ed25519 signature over manifest.json's exact bytes
//! rules/*.yar, model.json …
//! ```
//!
//! Nothing in a bundle is used unless the signature is from a pinned key
//! (`keys/bundle-keys.txt`, compiled in) and every listed file has the listed
//! size and SHA-256. Files that aren't listed are ignored. Paths are plain
//! relative names: no `..`, no absolute paths, no backslashes.
//!
//! Updates are differential: the updater (apps/desktop/src/engine/scan-bundle.ts)
//! downloads only files whose hash changed, builds the new folder next to the
//! old one, has this code verify it, then swaps. If anything fails the old
//! bundle stays.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_MANIFEST: u64 = 1 << 20;
const MAX_FILE: u64 = 256 << 20;

/// Pinned public keys, one hex key per line; `#` starts a comment.
pub const PINNED_KEYS: &str = include_str!("../keys/bundle-keys.txt");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: u32,
    pub version: String,
    #[serde(default)]
    pub created: String,
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug)]
pub struct Bundle {
    pub root: PathBuf,
    pub manifest: Manifest,
}

pub fn pinned_keys() -> Vec<VerifyingKey> {
    parse_keys(PINNED_KEYS)
}

pub fn parse_keys(text: &str) -> Vec<VerifyingKey> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| hex32(l).and_then(|b| VerifyingKey::from_bytes(&b).ok()))
        .collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex(s)?;
    bytes.try_into().ok()
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in s.trim().bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&t| t == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A relative path inside the bundle, or None for anything that could escape it.
pub fn safe_relative(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.len() > 200 || name.contains('\\') || name.contains('\0') {
        return None;
    }
    let p = Path::new(name);
    p.components().all(|c| matches!(c, Component::Normal(_))).then(|| p.to_path_buf())
}

fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > cap {
        return Err(format!("{} is too large", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

impl Bundle {
    /// Verifies the signature and every file; on success the bundle can be used.
    pub fn open(root: &Path, keys: &[VerifyingKey]) -> Result<Bundle, String> {
        if keys.is_empty() {
            return Err("no bundle signing key is pinned in this build, so no rules or model are loaded".into());
        }
        let manifest_bytes = read_capped(&root.join("manifest.json"), MAX_MANIFEST)?;
        let sig_text = String::from_utf8(read_capped(&root.join("manifest.sig"), 1024)?).map_err(|_| "manifest.sig is not text")?;
        let sig_bytes: [u8; 64] = base64_decode(&sig_text)
            .and_then(|b| b.try_into().ok())
            .ok_or("manifest.sig is not a signature")?;
        let sig = Signature::from_bytes(&sig_bytes);
        if !keys.iter().any(|k| k.verify_strict(&manifest_bytes, &sig).is_ok()) {
            return Err("the bundle's signature doesn't match a trusted key".into());
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest.json: {e}"))?;
        if manifest.format != 1 {
            return Err(format!("unsupported bundle format {}", manifest.format));
        }
        for (name, entry) in &manifest.files {
            let rel = safe_relative(name).ok_or_else(|| format!("unsafe path in manifest: {name:?}"))?;
            if entry.size > MAX_FILE {
                return Err(format!("{name} is too large"));
            }
            let data = read_capped(&root.join(&rel), entry.size)?;
            if data.len() as u64 != entry.size || sha256_hex(&data) != entry.sha256.to_ascii_lowercase() {
                return Err(format!("{name} doesn't match the signed manifest"));
            }
        }
        Ok(Bundle {
            root: root.to_path_buf(),
            manifest,
        })
    }

    /// A listed file's bytes, checked again (the folder could change after open).
    pub fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let entry = self.manifest.files.get(name).ok_or_else(|| format!("{name} isn't in the bundle"))?;
        let rel = safe_relative(name).ok_or("unsafe path")?;
        let data = read_capped(&self.root.join(rel), entry.size)?;
        if sha256_hex(&data) != entry.sha256.to_ascii_lowercase() {
            return Err(format!("{name} changed after it was verified"));
        }
        Ok(data)
    }

    pub fn rule_files(&self) -> Vec<String> {
        self.manifest
            .files
            .keys()
            .filter(|k| k.starts_with("rules/") && (k.ends_with(".yar") || k.ends_with(".yara")))
            .cloned()
            .collect()
    }
}
