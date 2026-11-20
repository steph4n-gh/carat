use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Declared normalization #1: CRLF -> LF.
pub fn normalize_crlf_to_lf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestNormalization {
    /// Only benign publish differences exist -> `source_normalized`.
    Benign,
    /// Significant differences exist -> `unexplained`, with field descriptions.
    Significant(Vec<String>),
    /// One side could not be parsed as a JSON object.
    Unparseable,
}

const LIFECYCLE_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];
const DEP_SECTIONS: &[&str] = &[
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundleDependencies",
    "bundledDependencies",
];
const SIGNIFICANT_TOP_KEYS: &[&str] = &[
    "bin",
    "main",
    "module",
    "exports",
    "imports",
    "browser",
    "files",
    "repository",
    "gypfile",
    "os",
    "cpu",
];

/// Declared normalization #2: Published `package.json` vs source `package.json` (Section 7.3).
pub fn compare_published_manifest(
    source_bytes: &[u8],
    published_bytes: &[u8],
) -> ManifestNormalization {
    let Ok(Value::Object(src_raw)) = serde_json::from_slice::<Value>(source_bytes) else {
        return ManifestNormalization::Unparseable;
    };
    let Ok(Value::Object(pub_map)) = serde_json::from_slice::<Value>(published_bytes) else {
        return ManifestNormalization::Unparseable;
    };

    // Apply `publishConfig` overlays onto a copy of source for comparison.
    let mut src = src_raw.clone();
    if let Some(Value::Object(pc)) = src_raw.get("publishConfig") {
        for (k, v) in pc {
            // Standard fields promoted by pnpm/yarn/npm publishConfig
            if matches!(
                k.as_str(),
                "main"
                    | "module"
                    | "types"
                    | "typings"
                    | "exports"
                    | "imports"
                    | "bin"
                    | "browser"
                    | "files"
                    | "cpu"
                    | "os"
                    | "libc"
                    | "directory"
                    | "executableFiles"
            ) {
                src.insert(k.clone(), v.clone());
            }
        }
    }

    let mut significant = Vec::new();

    // 1. Lifecycle scripts (`preinstall`, `install`, `postinstall`)
    let src_scripts = src.get("scripts").and_then(|v| v.as_object());
    let pub_scripts = pub_map.get("scripts").and_then(|v| v.as_object());
    for hook in LIFECYCLE_HOOKS {
        let sv = src_scripts.and_then(|m| m.get(*hook));
        let pv = pub_scripts.and_then(|m| m.get(*hook));
        if sv != pv {
            significant.push(format!("scripts.{hook}"));
        }
    }

    // 2. Runtime / optional / peer / bundled dependency sets and ranges
    for sec in DEP_SECTIONS {
        let sv = src.get(*sec);
        let pv = pub_map.get(*sec);
        match (sv, pv) {
            (None, None) => {}
            (Some(Value::Object(sm)), Some(Value::Object(pm))) => {
                let s_keys: BTreeSet<&String> = sm.keys().collect();
                let p_keys: BTreeSet<&String> = pm.keys().collect();
                if s_keys != p_keys {
                    for added in p_keys.difference(&s_keys) {
                        significant.push(format!("{sec}.{added} (added)"));
                    }
                    for removed in s_keys.difference(&p_keys) {
                        significant.push(format!("{sec}.{removed} (removed)"));
                    }
                }
                for (dep, p_range) in pm {
                    if let Some(s_range) = sm.get(dep) {
                        if s_range != p_range {
                            let benign_protocol = s_range
                                .as_str()
                                .map(|s| {
                                    s.starts_with("workspace:")
                                        || s.starts_with("catalog:")
                                        || s.starts_with("npm:")
                                })
                                .unwrap_or(false);
                            if !benign_protocol {
                                significant.push(format!("{sec}.{dep} (range changed)"));
                            }
                        }
                    }
                }
            }
            (Some(Value::Array(sa)), Some(Value::Array(pa))) => {
                if sa != pa {
                    significant.push((*sec).to_string());
                }
            }
            (None, Some(Value::Object(pm))) if pm.is_empty() => {}
            (Some(Value::Object(sm)), None) if sm.is_empty() => {}
            (None, Some(Value::Array(pa))) if pa.is_empty() => {}
            (Some(Value::Array(sa)), None) if sa.is_empty() => {}
            _ => {
                significant.push((*sec).to_string());
            }
        }
    }

    // 3. Significant top-level keys (with light normalization for repository shorthand & ./ prefix)
    for key in SIGNIFICANT_TOP_KEYS {
        let sv = src.get(*key);
        let pv = pub_map.get(*key);
        if sv == pv {
            continue;
        }
        if *key == "repository" && same_repository_value(sv, pv) {
            continue;
        }
        if (*key == "bin" || *key == "main" || *key == "module")
            && same_entry_value(sv, pv)
        {
            continue;
        }
        significant.push((*key).to_string());
    }

    if significant.is_empty() {
        ManifestNormalization::Benign
    } else {
        ManifestNormalization::Significant(significant)
    }
}

/// Checks whether npm registry metadata disagrees with the artifact's `package.json`
/// on lifecycle scripts, runtime dependencies, or `bin`.
pub fn registry_manifest_differs(
    artifact_manifest_bytes: &[u8],
    registry_version_json: &Value,
) -> Vec<String> {
    let Ok(Value::Object(art)) = serde_json::from_slice::<Value>(artifact_manifest_bytes) else {
        return Vec::new();
    };
    let Some(reg) = registry_version_json.as_object() else {
        return Vec::new();
    };

    let mut diffs = Vec::new();

    // Lifecycle scripts
    let art_scripts = art.get("scripts").and_then(|v| v.as_object());
    let reg_scripts = reg.get("scripts").and_then(|v| v.as_object());
    for hook in LIFECYCLE_HOOKS {
        let av = art_scripts.and_then(|m| m.get(*hook));
        let rv = reg_scripts.and_then(|m| m.get(*hook));
        if av != rv {
            diffs.push(format!("scripts.{hook}"));
        }
    }

    // Dependencies
    for sec in ["dependencies", "optionalDependencies"] {
        let am = empty_if_missing(art.get(sec));
        let rm = empty_if_missing(reg.get(sec));
        if am != rm {
            diffs.push(sec.to_string());
        }
    }

    // Bin
    if !same_entry_value(art.get("bin"), reg.get("bin")) {
        // npm expands string `bin` into `{ <pkg>: <path> }` in registry metadata; tolerate that exact normalization.
        if !bin_string_matches_expanded_object(&art, reg.get("bin")) {
            diffs.push("bin".to_string());
        }
    }

    diffs
}

fn empty_if_missing(v: Option<&Value>) -> Map<String, Value> {
    match v.and_then(|x| x.as_object()) {
        Some(m) => m.clone(),
        None => Map::new(),
    }
}

fn bin_string_matches_expanded_object(
    art: &Map<String, Value>,
    reg_bin: Option<&Value>,
) -> bool {
    let Some(Value::String(art_bin_str)) = art.get("bin") else {
        return false;
    };
    let Some(Value::Object(reg_obj)) = reg_bin else {
        return false;
    };
    if reg_obj.len() != 1 {
        return false;
    }
    let Some(only_val) = reg_obj.values().next().and_then(|v| v.as_str()) else {
        return false;
    };
    only_val.trim_start_matches("./") == art_bin_str.trim_start_matches("./")
}

fn same_entry_value(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::String(sa)), Some(Value::String(sb))) => {
            sa.trim_start_matches("./") == sb.trim_start_matches("./")
        }
        (Some(Value::Object(ma)), Some(Value::Object(mb))) => {
            if ma.len() != mb.len() {
                return false;
            }
            ma.iter().all(|(k, va)| match (va.as_str(), mb.get(k).and_then(|v| v.as_str())) {
                (Some(sa), Some(sb)) => sa.trim_start_matches("./") == sb.trim_start_matches("./"),
                _ => mb.get(k) == Some(va),
            })
        }
        _ => a == b,
    }
}

fn same_repository_value(a: Option<&Value>, b: Option<&Value>) -> bool {
    let norm_a = extract_canonical_repo(a);
    let norm_b = extract_canonical_repo(b);
    norm_a.is_some() && norm_a == norm_b
}

fn extract_canonical_repo(v: Option<&Value>) -> Option<(String, Option<String>)> {
    match v? {
        Value::String(s) => Some((canonicalize_repo_url(s), None)),
        Value::Object(m) => {
            let url = m.get("url")?.as_str()?;
            let dir = m
                .get("directory")
                .and_then(|d| d.as_str())
                .map(|d| d.trim_matches('/').to_string())
                .filter(|d| !d.is_empty());
            Some((canonicalize_repo_url(url), dir))
        }
        _ => None,
    }
}

pub fn canonicalize_repo_url(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("git+") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("github:") {
        s = format!("https://github.com/{rest}");
    } else if let Some(rest) = s.strip_prefix("gitlab:") {
        s = format!("https://gitlab.com/{rest}");
    } else if let Some(rest) = s.strip_prefix("bitbucket:") {
        s = format!("https://bitbucket.org/{rest}");
    } else if !s.contains("://") && !s.starts_with("git@") && s.split('/').count() == 2 {
        s = format!("https://github.com/{s}");
    }
    if let Some(rest) = s.strip_prefix("git@") {
        if let Some((host, path)) = rest.split_once(':') {
            s = format!("https://{host}/{path}");
        }
    }
    if let Some(rest) = s.strip_prefix("ssh://git@") {
        s = format!("https://{rest}");
    }
    if let Some(rest) = s.strip_prefix("git://") {
        s = format!("https://{rest}");
    }
    if let Some(rest) = s.strip_prefix("http://") {
        s = format!("https://{rest}");
    }
    // Strip fragment or query
    if let Some((before, _)) = s.split_once('#') {
        s = before.to_string();
    }
    if let Some((before, _)) = s.split_once('?') {
        s = before.to_string();
    }
    while s.ends_with('/') {
        s.pop();
    }
    if let Some(stripped) = s.strip_suffix(".git") {
        s = stripped.to_string();
    }
    s.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_vs_significant_manifest_diffs() {
        let src = br#"{
          "name": "demo",
          "version": "0.0.0-placeholder",
          "dependencies": {"a": "workspace:^"},
          "devDependencies": {"vitest": "^2.0.0"},
          "scripts": {"test": "vitest"},
          "repository": "org/repo"
        }"#;
        let pub_benign = br#"{
          "version": "1.2.3",
          "name": "demo",
          "gitHead": "abcdef",
          "dependencies": {"a": "^1.0.0"},
          "repository": {"type": "git", "url": "git+https://github.com/org/repo.git"}
        }"#;
        assert_eq!(
            compare_published_manifest(src, pub_benign),
            ManifestNormalization::Benign
        );

        let pub_evil = br#"{
          "name": "demo",
          "version": "1.2.3",
          "dependencies": {"a": "^1.0.0", "stealer": "^1.0.0"},
          "scripts": {"postinstall": "node steal.js"},
          "repository": "org/repo"
        }"#;
        match compare_published_manifest(src, pub_evil) {
            ManifestNormalization::Significant(fields) => {
                assert!(fields.iter().any(|f| f == "scripts.postinstall"));
                assert!(fields.iter().any(|f| f.contains("stealer")));
            }
            other => panic!("expected significant diff, got {other:?}"),
        }
    }

    #[test]
    fn canonicalizes_repo_urls() {
        assert_eq!(
            canonicalize_repo_url("git+https://github.com/ViteJS/Vite.git"),
            "https://github.com/vitejs/vite"
        );
        assert_eq!(
            canonicalize_repo_url("git@github.com:vitejs/vite.git"),
            "https://github.com/vitejs/vite"
        );
        assert_eq!(
            canonicalize_repo_url("vitejs/vite"),
            "https://github.com/vitejs/vite"
        );
    }
}
