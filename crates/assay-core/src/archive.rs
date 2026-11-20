use crate::digest::{git_blob_sha1_hex, sha256_hex, sha512_hex};
use crate::model::{
    ArchiveEntry, ArchiveFact, ArchiveInventory, ArchiveLimits, EntryType, FileRole, ManifestFacts,
};
use flate2::read::MultiGzDecoder;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub struct LoadedArchive {
    pub inventory: ArchiveInventory,
    pub contents: BTreeMap<String, Vec<u8>>,
}

/// Verifies (optionally) and streams a `.tgz` npm tarball strictly in memory.
/// Never extracts to disk and never executes anything.
pub fn inspect_tgz(
    compressed: &[u8],
    expected_sha512_hex: Option<&str>,
    limits: ArchiveLimits,
) -> Result<LoadedArchive, String> {
    let actual_sha512 = sha512_hex(compressed);
    if let Some(expected) = expected_sha512_hex {
        if !actual_sha512.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "sha512 mismatch: expected {expected}, got {actual_sha512}"
            ));
        }
    }

    let mut facts = BTreeSet::new();
    let compressed_bytes = compressed.len() as u64;
    if compressed_bytes > limits.max_compressed_bytes {
        facts.insert(ArchiveFact::ArchiveOverLimit);
        return Ok(LoadedArchive {
            inventory: ArchiveInventory {
                compressed_bytes,
                expanded_bytes: 0,
                sha512: actual_sha512,
                entries: Vec::new(),
                facts,
            },
            contents: BTreeMap::new(),
        });
    }

    let mut decoder = MultiGzDecoder::new(compressed);
    let mut entries = Vec::new();
    let mut contents = BTreeMap::new();
    let mut seen_normalized_paths: BTreeSet<String> = BTreeSet::new();
    let mut expanded_bytes: u64 = 0;

    let mut global_pax: BTreeMap<String, String> = BTreeMap::new();
    let mut next_pax: BTreeMap<String, String> = BTreeMap::new();
    let mut next_gnu_longname: Option<String> = None;

    let mut header = [0u8; 512];
    loop {
        match read_exact_or_eof(&mut decoder, &mut header) {
            Ok(false) => break,
            Ok(true) => {}
            Err(_) => {
                facts.insert(ArchiveFact::ArchiveCorrupt);
                break;
            }
        }

        // Two consecutive zero blocks mark end-of-archive.
        if header.iter().all(|&b| b == 0) {
            break;
        }

        if !verify_tar_checksum(&header) {
            facts.insert(ArchiveFact::ArchiveCorrupt);
            break;
        }

        let typeflag = header[156];
        let mode = parse_octal(&header[100..108]).unwrap_or(0) as u32;
        let mut size = parse_tar_size(&header[124..136]).unwrap_or(0);
        if let Some(pax_size) = next_pax
            .get("size")
            .or_else(|| global_pax.get("size"))
            .and_then(|s| s.parse::<u64>().ok())
        {
            size = pax_size;
        }

        // Check expanded limit before allocating or reading payload.
        if expanded_bytes.saturating_add(size) > limits.max_expanded_bytes {
            facts.insert(ArchiveFact::ArchiveOverLimit);
            break;
        }

        let mut payload = vec![0u8; size as usize];
        if size > 0 && decoder.read_exact(&mut payload).is_err() {
            facts.insert(ArchiveFact::ArchiveCorrupt);
            break;
        }

        // Skip 512-byte padding.
        let pad = (512 - (size % 512)) % 512;
        if pad > 0 {
            let mut sink = [0u8; 512];
            if decoder.read_exact(&mut sink[..pad as usize]).is_err() {
                facts.insert(ArchiveFact::ArchiveCorrupt);
                break;
            }
        }

        // Handle PAX & GNU metadata headers.
        match typeflag {
            b'x' => {
                parse_pax_records(&payload, &mut next_pax);
                continue;
            }
            b'g' => {
                parse_pax_records(&payload, &mut global_pax);
                continue;
            }
            b'L' => {
                let s = String::from_utf8_lossy(&payload)
                    .trim_end_matches('\0')
                    .to_string();
                next_gnu_longname = Some(s);
                continue;
            }
            b'K' => {
                // GNU long linkname; next entry will be flagged as link entry.
                continue;
            }
            _ => {}
        }

        if entries.len() >= limits.max_entries {
            facts.insert(ArchiveFact::ArchiveOverLimit);
            break;
        }

        let raw_path = if let Some(p) = next_pax
            .remove("path")
            .or_else(|| global_pax.get("path").cloned())
        {
            p
        } else if let Some(p) = next_gnu_longname.take() {
            p
        } else {
            let name = parse_cstring(&header[0..100]);
            let prefix = parse_cstring(&header[345..500]);
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        };
        next_pax.clear();

        if has_path_escape(&raw_path) {
            facts.insert(ArchiveFact::ArchivePathEscape);
        }

        let clean_path = normalize_tar_path(&raw_path);
        let entry_type = match typeflag {
            0 | b'0' | b'7' => EntryType::File,
            b'5' => EntryType::Directory,
            b'2' => {
                facts.insert(ArchiveFact::ArchiveLinkEntry);
                EntryType::Symlink
            }
            b'1' => {
                facts.insert(ArchiveFact::ArchiveLinkEntry);
                EntryType::Hardlink
            }
            _ => {
                facts.insert(ArchiveFact::ArchiveSpecialEntry);
                EntryType::Other
            }
        };

        if entry_type == EntryType::Directory {
            continue;
        }

        expanded_bytes = expanded_bytes.saturating_add(size);

        // Collision check (exact, case-folded, Unicode NFC).
        let collision_key = canonical_collision_key(&clean_path);
        if !seen_normalized_paths.insert(collision_key) {
            facts.insert(ArchiveFact::ArchiveDuplicatePath);
        }

        let sha256 = sha256_hex(&payload);
        let git_blob_sha1 = git_blob_sha1_hex(&payload);

        entries.push(ArchiveEntry {
            path: clean_path.clone(),
            entry_type,
            mode,
            size,
            sha256,
            git_blob_sha1,
        });

        if entry_type == EntryType::File {
            contents.insert(clean_path, payload);
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(LoadedArchive {
        inventory: ArchiveInventory {
            compressed_bytes,
            expanded_bytes,
            sha512: actual_sha512,
            entries,
            facts,
        },
        contents,
    })
}

/// Strips the standard single leading npm tarball directory prefix (usually `package/`)
/// when normalizing artifact paths against repository paths.
pub fn strip_archive_root(path: &str) -> &str {
    match path.split_once('/') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => path,
    }
}

pub fn classify_file_role(path: &str, bytes: &[u8]) -> FileRole {
    let rel = strip_archive_root(path);
    let lower = rel.to_ascii_lowercase();

    if rel == "package.json" || lower.ends_with("/package.json") {
        return FileRole::Manifest;
    }
    if lower.ends_with(".map") {
        return FileRole::SourceMap;
    }
    if lower.ends_with(".d.ts")
        || lower.ends_with(".d.mts")
        || lower.ends_with(".d.cts")
        || lower.ends_with(".tsbuildinfo")
    {
        return FileRole::Declaration;
    }
    if lower.ends_with(".node")
        || lower.ends_with(".so")
        || lower.ends_with(".dylib")
        || lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".wasm")
        || is_executable_binary(bytes)
    {
        return FileRole::Binary;
    }
    if lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".jsx")
        || lower.ends_with(".ts")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".sh")
        || lower.ends_with(".bash")
        || lower.ends_with(".cmd")
        || lower.ends_with(".bat")
        || lower.ends_with(".ps1")
        || lower.ends_with(".gyp")
        || lower.ends_with(".c")
        || lower.ends_with(".cc")
        || lower.ends_with(".cpp")
        || lower.ends_with(".h")
        || lower.ends_with(".rs")
        || lower.ends_with(".py")
        || bytes.starts_with(b"#!")
    {
        return FileRole::Code;
    }
    if lower.ends_with(".md")
        || lower.ends_with(".txt")
        || lower.contains("license")
        || lower.contains("licence")
        || lower.contains("readme")
        || lower.contains("changelog")
        || lower.contains("history")
        || lower.contains("notice")
    {
        return FileRole::Doc;
    }
    FileRole::Other
}

pub fn is_executable_binary(bytes: &[u8]) -> bool {
    // ELF, Mach-O (32/64/fat), PE/MZ, WebAssembly
    if bytes.len() < 4 {
        return false;
    }
    let magic = &bytes[..4];
    magic == b"\x7fELF"
        || magic == b"\x00asm"
        || magic == [0xfe, 0xed, 0xfa, 0xce]
        || magic == [0xce, 0xfa, 0xed, 0xfe]
        || magic == [0xfe, 0xed, 0xfa, 0xcf]
        || magic == [0xcf, 0xfa, 0xed, 0xfe]
        || magic == [0xca, 0xfe, 0xba, 0xbe]
        || (bytes[0] == b'M' && bytes[1] == b'Z' && bytes.len() > 64)
}

pub fn extract_manifest_facts(loaded: &LoadedArchive) -> ManifestFacts {
    let mut facts = ManifestFacts::default();

    // Check for root binding.gyp, binary files, and nested node_modules manifests.
    let mut root_manifest_bytes: Option<&[u8]> = None;
    for (path, bytes) in &loaded.contents {
        let rel = strip_archive_root(path);
        if rel == "package.json" {
            root_manifest_bytes = Some(bytes.as_slice());
        } else if rel == "binding.gyp" {
            facts.has_binding_gyp = true;
        }
        if classify_file_role(path, bytes) == FileRole::Binary {
            facts.has_native_or_binary = true;
        }
        if rel.starts_with("node_modules/") && rel.ends_with("/package.json") {
            if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
                if let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) {
                    for hook in ["preinstall", "install", "postinstall"] {
                        if let Some(cmd) = scripts.get(hook).and_then(|c| c.as_str()) {
                            facts
                                .nested_install_scripts
                                .push(format!("{rel}:{hook}={cmd}"));
                        }
                    }
                }
            }
        }
    }

    let Some(bytes) = root_manifest_bytes else {
        facts.has_install_exec = facts.has_binding_gyp || !facts.nested_install_scripts.is_empty();
        return facts;
    };

    let Ok(val) = serde_json::from_slice::<Value>(bytes) else {
        facts.has_install_exec = facts.has_binding_gyp || !facts.nested_install_scripts.is_empty();
        return facts;
    };

    facts.name = val.get("name").and_then(|v| v.as_str()).map(String::from);
    facts.version = val
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);

    if let Some(repo) = val.get("repository") {
        match repo {
            Value::String(s) => {
                facts.repository_url = Some(s.clone());
            }
            Value::Object(map) => {
                facts.repository_url = map.get("url").and_then(|v| v.as_str()).map(String::from);
                facts.repository_directory = map
                    .get("directory")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_matches('/').to_string())
                    .filter(|s| !s.is_empty());
            }
            _ => {}
        }
    }

    if let Some(scripts) = val.get("scripts").and_then(|v| v.as_object()) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(cmd) = scripts.get(hook).and_then(|v| v.as_str()) {
                facts
                    .install_scripts
                    .insert(hook.to_string(), cmd.to_string());
            }
        }
    }

    facts.has_install_exec = !facts.install_scripts.is_empty()
        || facts.has_binding_gyp
        || !facts.nested_install_scripts.is_empty();

    collect_dep_names(&val, "dependencies", &mut facts.runtime_dependencies);
    collect_dep_names(
        &val,
        "optionalDependencies",
        &mut facts.optional_dependencies,
    );
    collect_dep_names(&val, "peerDependencies", &mut facts.peer_dependencies);

    for key in ["bundleDependencies", "bundledDependencies"] {
        if let Some(arr) = val.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(name) = item.as_str() {
                    facts.bundled_dependencies.insert(name.to_string());
                }
            }
        }
    }

    if let Some(bin) = val.get("bin") {
        match bin {
            Value::String(s) => {
                facts.bin_paths.insert(clean_rel_entry(s));
            }
            Value::Object(map) => {
                for v in map.values() {
                    if let Some(s) = v.as_str() {
                        facts.bin_paths.insert(clean_rel_entry(s));
                    }
                }
            }
            _ => {}
        }
    }

    for key in ["main", "module", "browser"] {
        if let Some(s) = val.get(key).and_then(|v| v.as_str()) {
            facts.entry_paths.insert(clean_rel_entry(s));
        }
    }
    if let Some(exports) = val.get("exports") {
        collect_export_strings(exports, &mut facts.entry_paths);
    }

    facts
}

fn clean_rel_entry(s: &str) -> String {
    s.trim_start_matches("./").to_string()
}

fn collect_export_strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(clean_rel_entry(s));
        }
        Value::Array(arr) => {
            for item in arr {
                collect_export_strings(item, out);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                collect_export_strings(val, out);
            }
        }
        _ => {}
    }
}

fn collect_dep_names(val: &Value, key: &str, out: &mut BTreeSet<String>) {
    if let Some(map) = val.get(key).and_then(|v| v.as_object()) {
        for k in map.keys() {
            out.insert(k.clone());
        }
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut read_total = 0;
    while read_total < buf.len() {
        let n = reader.read(&mut buf[read_total..])?;
        if n == 0 {
            if read_total == 0 {
                return Ok(false);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated tar header",
                ));
            }
        }
        read_total += n;
    }
    Ok(true)
}

fn verify_tar_checksum(header: &[u8; 512]) -> bool {
    let Some(expected) = parse_octal(&header[148..156]) else {
        return false;
    };
    let mut unsigned_sum: u64 = 0;
    let mut signed_sum: i64 = 0;
    for (i, &b) in header.iter().enumerate() {
        let val = if (148..156).contains(&i) { b' ' } else { b };
        unsigned_sum += val as u64;
        signed_sum += (val as i8) as i64;
    }
    unsigned_sum == expected || (signed_sum >= 0 && (signed_sum as u64) == expected)
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?;
    let trimmed = s.trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(trimmed, 8).ok()
}

fn parse_tar_size(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    // GNU base-256 binary encoding when high bit is set.
    if (field[0] & 0x80) != 0 {
        let mut val: u64 = (field[0] & 0x7f) as u64;
        for &b in &field[1..] {
            val = val.checked_shl(8)?.checked_add(b as u64)?;
        }
        return Some(val);
    }
    parse_octal(field)
}

fn parse_cstring(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).to_string()
}

fn parse_pax_records(data: &[u8], out: &mut BTreeMap<String, String>) {
    let mut idx = 0;
    while idx < data.len() {
        let Some(sp_rel) = data[idx..].iter().position(|&b| b == b' ') else {
            break;
        };
        let len_str = std::str::from_utf8(&data[idx..idx + sp_rel]).unwrap_or("");
        let Ok(rec_len) = len_str.parse::<usize>() else {
            break;
        };
        if rec_len == 0 || idx + rec_len > data.len() {
            break;
        }
        let rec = &data[idx + sp_rel + 1..idx + rec_len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&rec[..eq]).to_string();
            let val = String::from_utf8_lossy(&rec[eq + 1..]).to_string();
            out.insert(key, val);
        }
        idx += rec_len;
    }
}

fn has_path_escape(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\0') {
        return true;
    }
    for part in path.split(['/', '\\']) {
        if part == ".." {
            return true;
        }
    }
    false
}

fn normalize_tar_path(raw: &str) -> String {
    let mut parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        parts.push(part);
    }
    parts.join("/")
}

fn canonical_collision_key(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn make_tgz(files: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, data, typeflag) in files {
            let mut hdr = [0u8; 512];
            let nb = name.as_bytes();
            hdr[..nb.len()].copy_from_slice(nb);
            hdr[100..108].copy_from_slice(b"0000644\0");
            hdr[108..116].copy_from_slice(b"0000000\0");
            hdr[116..124].copy_from_slice(b"0000000\0");
            let size_oct = format!("{:011o}\0", data.len());
            hdr[124..136].copy_from_slice(size_oct.as_bytes());
            hdr[136..148].copy_from_slice(b"00000000000\0");
            hdr[148..156].copy_from_slice(b"        ");
            hdr[156] = *typeflag;
            hdr[257..263].copy_from_slice(b"ustar\0");
            hdr[263..265].copy_from_slice(b"00");
            let csum: u32 = hdr.iter().map(|&b| b as u32).sum();
            let csum_oct = format!("{csum:06o}\0 ");
            hdr[148..156].copy_from_slice(csum_oct.as_bytes());
            tar.extend_from_slice(&hdr);
            tar.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            tar.extend(std::iter::repeat_n(0u8, pad));
        }
        tar.extend(std::iter::repeat_n(0u8, 1024));
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn parses_valid_tgz_and_detects_anomalies() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"demo","version":"1.0.0"}"#, b'0'),
            ("package/index.js", b"export const x = 1;\n", b'0'),
        ]);
        let loaded = inspect_tgz(&tgz, None, ArchiveLimits::default()).unwrap();
        assert!(loaded.inventory.facts.is_empty());
        assert_eq!(loaded.inventory.entries.len(), 2);

        let hostile = make_tgz(&[
            ("package/../evil.js", b"alert(1)", b'0'),
            ("package/Index.js", b"a", b'0'),
            ("package/index.js", b"b", b'0'),
            ("package/link", b"", b'2'),
        ]);
        let loaded_h = inspect_tgz(&hostile, None, ArchiveLimits::default()).unwrap();
        assert!(loaded_h.inventory.facts.contains(&ArchiveFact::ArchivePathEscape));
        assert!(loaded_h.inventory.facts.contains(&ArchiveFact::ArchiveDuplicatePath));
        assert!(loaded_h.inventory.facts.contains(&ArchiveFact::ArchiveLinkEntry));
    }
}
