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
    /// Only explicitly allowed benign publish transforms exist -> `source_normalized`.
    Benign,
    /// Significant or unexpected differences exist -> `unexplained`, with field descriptions.
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

/// Keys that npm/pnpm/yarn legitimately add, remove, or strip during publish without changing runtime semantics.
const BENIGN_EPHEMERAL_KEYS: &[&str] = &[
    "gitHead",
    "devDependencies",
    "publishConfig",
    "packageManager",
    "pnpm",
    "volta",
    "eslintConfig",
    "prettier",
    "jest",
    "vitest",
    "lint-staged",
    "husky",
    "readme",
    "readmeFilename",
    "_id",
    "_nodeVersion",
    "_npmVersion",
    "_npmUser",
    "dist",
    "maintainers",
];

/// Declared normalization #2: Published `package.json` vs source `package.json`.
/// Applies ONLY explicitly allowed benign publish transforms and compares the COMPLETE remaining
/// manifest objects (so changes to fields like `"type"`, `"sideEffects"`, etc. are caught!).
pub fn compare_published_manifest(
    source_bytes: &[u8],
    published_bytes: &[u8],
) -> ManifestNormalization {
    let Ok(Value::Object(src_raw)) =
        serde_json::from_slice::<Value>(crate::archive::strip_utf8_bom(source_bytes))
    else {
        return ManifestNormalization::Unparseable;
    };
    let Ok(Value::Object(pub_raw)) =
        serde_json::from_slice::<Value>(crate::archive::strip_utf8_bom(published_bytes))
    else {
        return ManifestNormalization::Unparseable;
    };

    // 1. Apply `publishConfig` overlays onto a clone of source.
    let mut src = src_raw.clone();
    if let Some(Value::Object(pc)) = src_raw.get("publishConfig") {
        for (k, v) in pc {
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
    let mut pub_map = pub_raw;

    let mut significant = Vec::new();

    // 2. Version check: must match UNLESS source holds an explicit placeholder (prevents pointing gitHead at an older release).
    let src_ver = src.get("version").and_then(|v| v.as_str());
    let pub_ver = pub_map.get("version").and_then(|v| v.as_str());
    if src_ver != pub_ver {
        let is_placeholder = src_ver.map(is_placeholder_version).unwrap_or(false);
        if !is_placeholder {
            significant.push(format!(
                "version ({} != {})",
                src_ver.unwrap_or("none"),
                pub_ver.unwrap_or("none")
            ));
        }
    }
    src.remove("version");
    pub_map.remove("version");

    // 3. Lifecycle scripts (`preinstall`, `install`, `postinstall`); non-lifecycle scripts may be stripped/reordered.
    let src_scripts = src.get("scripts").and_then(|v| v.as_object());
    let pub_scripts = pub_map.get("scripts").and_then(|v| v.as_object());
    for hook in LIFECYCLE_HOOKS {
        let sv = src_scripts.and_then(|m| m.get(*hook));
        let pv = pub_scripts.and_then(|m| m.get(*hook));
        if sv != pv {
            significant.push(format!("scripts.{hook}"));
        }
    }
    src.remove("scripts");
    pub_map.remove("scripts");

    // 4. Runtime / optional / peer / bundled dependency sets and ranges
    for sec in DEP_SECTIONS {
        let sv = src.remove(*sec);
        let pv = pub_map.remove(*sec);
        match (sv, pv) {
            (None, None) => {}
            (Some(Value::Object(sm)), Some(Value::Object(pm))) => {
                let s_keys: BTreeSet<&String> = sm.keys().collect();
                let p_keys: BTreeSet<&String> = pm.keys().collect();
                for added in p_keys.difference(&s_keys) {
                    significant.push(format!("{sec}.{added} (added)"));
                }
                for removed in s_keys.difference(&p_keys) {
                    significant.push(format!("{sec}.{removed} (removed)"));
                }
                for (dep, p_range) in &pm {
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

    // 5. Repository & entry path normalization (./ prefix and git+/ssh/shorthand URL forms)
    let src_repo = src.remove("repository");
    let pub_repo = pub_map.remove("repository");
    if src_repo != pub_repo && !same_repository_value(src_repo.as_ref(), pub_repo.as_ref()) {
        significant.push("repository".to_string());
    }

    for entry_key in ["bin", "main", "module"] {
        let sv = src.remove(entry_key);
        let pv = pub_map.remove(entry_key);
        if sv != pv && !same_entry_value(sv.as_ref(), pv.as_ref()) {
            significant.push(entry_key.to_string());
        }
    }

    // 6. Strip explicitly allowed ephemeral publish keys, then compare ALL remaining keys!
    for k in BENIGN_EPHEMERAL_KEYS {
        src.remove(*k);
        pub_map.remove(*k);
    }

    let all_keys: BTreeSet<String> = src.keys().chain(pub_map.keys()).cloned().collect();
    for key in all_keys {
        if src.get(&key) != pub_map.get(&key) {
            // Allow benign `bugs`/`homepage` string-vs-object canonicalization if URL matches,
            // otherwise flag ANY remaining manifest difference (including `type`, `exports`, `imports`, `sideEffects`, etc.)!
            if (key == "bugs" || key == "homepage")
                && same_simple_url_field(src.get(&key), pub_map.get(&key))
            {
                continue;
            }
            significant.push(key);
        }
    }

    if significant.is_empty() {
        ManifestNormalization::Benign
    } else {
        ManifestNormalization::Significant(significant)
    }
}

fn is_placeholder_version(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower == "0.0.0"
        || lower.starts_with("0.0.0-")
        || lower.contains("placeholder")
        || lower.contains("development")
        || lower.contains("semantically-released")
}

fn same_simple_url_field(a: Option<&Value>, b: Option<&Value>) -> bool {
    let extract = |v: Option<&Value>| -> Option<String> {
        match v? {
            Value::String(s) => Some(s.trim_end_matches('/').to_ascii_lowercase()),
            Value::Object(m) => m
                .get("url")
                .and_then(|u| u.as_str())
                .map(|s| s.trim_end_matches('/').to_ascii_lowercase()),
            _ => None,
        }
    };
    let ea = extract(a);
    ea.is_some() && ea == extract(b)
}

/// Checks whether npm registry metadata disagrees with the artifact's `package.json`
/// on lifecycle scripts, runtime dependencies, or `bin`.
pub fn registry_manifest_differs(
    artifact_manifest_bytes: &[u8],
    registry_version_json: &Value,
    has_binding_gyp: bool,
) -> Vec<String> {
    let Ok(Value::Object(art)) =
        serde_json::from_slice::<Value>(crate::archive::strip_utf8_bom(artifact_manifest_bytes))
    else {
        return Vec::new();
    };
    let Some(reg) = registry_version_json.as_object() else {
        return Vec::new();
    };

    let mut diffs = Vec::new();

    // Lifecycle scripts (tolerating npm's automatic `scripts.install = "node-gyp rebuild"` injection when binding.gyp exists)
    let art_scripts = art.get("scripts").and_then(|v| v.as_object());
    let reg_scripts = reg.get("scripts").and_then(|v| v.as_object());
    for hook in LIFECYCLE_HOOKS {
        let av = art_scripts.and_then(|m| m.get(*hook));
        let rv = reg_scripts.and_then(|m| m.get(*hook));
        if av != rv {
            if *hook == "install"
                && has_binding_gyp
                && av.is_none()
                && rv.and_then(|v| v.as_str()) == Some("node-gyp rebuild")
            {
                continue;
            }
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
    fn benign_vs_significant_manifest_diffs_including_type_and_version() {
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

        // Changing `type` must be flagged as significant!
        let pub_type_changed = br#"{
          "version": "1.2.3",
          "name": "demo",
          "type": "module",
          "dependencies": {"a": "^1.0.0"},
          "repository": "org/repo"
        }"#;
        match compare_published_manifest(src, pub_type_changed) {
            ManifestNormalization::Significant(fields) => {
                assert!(fields.contains(&"type".to_string()));
            }
            other => panic!("expected significant diff on type, got {other:?}"),
        }

        // Pointing at an OLD concrete version in git must be flagged!
        let old_src = br#"{"name":"demo","version":"1.0.0"}"#;
        let new_pub = br#"{"name":"demo","version":"1.0.1"}"#;
        match compare_published_manifest(old_src, new_pub) {
            ManifestNormalization::Significant(fields) => {
                assert!(fields.iter().any(|f| f.starts_with("version")));
            }
            other => panic!("expected significant diff on version mismatch, got {other:?}"),
        }
    }

    #[test]
    fn tolerates_npm_binding_gyp_install_injection() {
        let art = br#"{"name":"native-pkg","version":"1.0.0"}"#;
        let reg = serde_json::json!({
            "name": "native-pkg",
            "version": "1.0.0",
            "scripts": { "install": "node-gyp rebuild" }
        });
        assert!(registry_manifest_differs(art, &reg, true).is_empty());
        assert!(!registry_manifest_differs(art, &reg, false).is_empty());
    }

    #[test]
    fn canonicalizes_repo_urls() {
        assert_eq!(
            canonicalize_repo_url("git+https://github.com/ViteJS/Vite.git"),
            "https://github.com/vitejs/vite"
        );
    }
}
