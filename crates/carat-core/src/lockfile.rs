use crate::digest::parse_sha512_sri;
use crate::model::LockAlarm;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Prod,
    Dev,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Registry,
    Git,
    Url,
    File,
    Link,
    Bundled,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockPackage {
    pub instance_path: String,
    pub name: String,
    pub version: Option<String>,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
    pub sha512: Option<String>,
    pub source_kind: SourceKind,
    pub registry_host: Option<String>,
    pub in_bundle: bool,
    pub dev: bool,
    pub optional: bool,
    pub dependencies: BTreeMap<String, EdgeKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockTransition {
    pub name: String,
    pub instance_path: String,
    pub ref_version: Option<String>,
    pub ref_resolved: Option<String>,
    pub ref_integrity: Option<String>,
    pub ref_sha512: Option<String>,
    pub new_version: Option<String>,
    pub new_resolved: Option<String>,
    pub new_integrity: Option<String>,
    pub new_sha512: Option<String>,
    pub new_source_kind: SourceKind,
    pub in_bundle: bool,
    pub is_new_direct: bool,
    pub route: Vec<RouteEdge>,
    pub unattributed: bool,
    pub lock_alarms: BTreeSet<LockAlarm>,
}

impl LockTransition {
    /// Deduplication key: transitions are only merged when package identity, version,
    /// reference/new digests, resolved URL, and bundle status all match.
    pub fn dedup_key(
        &self,
    ) -> (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    ) {
        (
            self.name.clone(),
            self.new_version.clone(),
            self.ref_sha512.clone(),
            self.new_sha512.clone(),
            self.new_resolved.clone(),
            self.in_bundle,
        )
    }
}

/// Returns the parent package's `instance_path` if `instance_path` is nested inside
/// another package's `node_modules/` (e.g. `node_modules/a/node_modules/b` -> `Some("node_modules/a")`).
pub fn parent_node_modules_instance(instance_path: &str) -> Option<String> {
    let idx = instance_path.rfind("/node_modules/")?;
    let parent = &instance_path[..idx];
    if parent.is_empty() {
        None
    } else {
        Some(parent.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedPackage {
    pub name: String,
    pub instance_path: String,
    pub version: Option<String>,
    pub sha512: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockDiff {
    pub transitions: Vec<LockTransition>,
    pub removed: Vec<RemovedPackage>,
}

#[derive(Debug, Clone, Default)]
struct RootDeps {
    all_direct: BTreeMap<String, EdgeKind>,
}

/// Parses an npm `package-lock.json` v3 file into its package instances.
pub fn parse_lockfile_packages(lock_bytes: &[u8]) -> Result<Vec<LockPackage>, String> {
    let val: Value = serde_json::from_slice(lock_bytes)
        .map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let version = val
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "package-lock.json missing integer lockfileVersion".to_string())?;
    if version != 3 {
        return Err(format!(
            "unsupported package-lock.json lockfileVersion {version} (v1 supports lockfileVersion 3)"
        ));
    }

    let packages = val
        .get("packages")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "package-lock.json missing packages map".to_string())?;

    // Collect local workspace root paths referenced by `"link": true` entries so we never
    // mistake local workspaces (e.g. `packages/sub`) for external registry packages.
    let mut workspace_dirs: BTreeSet<String> = BTreeSet::new();
    for entry in packages.values() {
        if let Some(obj) = entry.as_object() {
            if obj.get("link").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(target) = obj.get("resolved").and_then(|v| v.as_str()) {
                    let clean = target.trim_start_matches("./").trim_end_matches('/');
                    if !clean.is_empty() && !clean.starts_with("node_modules/") {
                        workspace_dirs.insert(clean.to_string());
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    for (inst_path, entry) in packages {
        if inst_path.is_empty() {
            continue;
        }
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("link").and_then(|v| v.as_bool()) == Some(true) {
            // Workspace symlink entry inside packages map; not an external archive.
            continue;
        }
        if workspace_dirs.contains(inst_path.as_str())
            && !inst_path.starts_with("node_modules/")
            && !inst_path.contains("/node_modules/")
        {
            // Local workspace definition entry (not an external package tarball).
            continue;
        }
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| infer_name_from_instance_path(inst_path))
            .unwrap_or_else(|| inst_path.clone());

        let pkg_version = obj
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);
        let resolved = obj
            .get("resolved")
            .and_then(|v| v.as_str())
            .map(String::from);
        let integrity = obj
            .get("integrity")
            .and_then(|v| v.as_str())
            .map(String::from);
        let sha512 = integrity.as_deref().and_then(parse_sha512_sri);
        // Only honor `inBundle: true` when nested inside a parent package's `node_modules/`.
        // A top-level `node_modules/<pkg>` entry can never legitimately be bundled by a parent tarball.
        let declared_in_bundle = obj.get("inBundle").and_then(|v| v.as_bool()) == Some(true);
        let in_bundle = declared_in_bundle && parent_node_modules_instance(inst_path).is_some();
        let (source_kind, registry_host) = classify_resolved(resolved.as_deref(), in_bundle);

        let mut deps = BTreeMap::new();
        collect_edge_map(obj, "dependencies", EdgeKind::Prod, &mut deps);
        collect_edge_map(obj, "optionalDependencies", EdgeKind::Optional, &mut deps);
        collect_edge_map(obj, "peerDependencies", EdgeKind::Peer, &mut deps);

        out.push(LockPackage {
            instance_path: inst_path.clone(),
            name,
            version: pkg_version,
            resolved,
            integrity,
            sha512,
            source_kind,
            registry_host,
            in_bundle,
            dev: obj.get("dev").and_then(|v| v.as_bool()) == Some(true),
            optional: obj.get("optional").and_then(|v| v.as_bool()) == Some(true),
            dependencies: deps,
        });
    }

    out.sort_by(|a, b| a.instance_path.cmp(&b.instance_path));
    Ok(out)
}

/// Diffs base vs head `package-lock.json` v3 (plus optional base/head root `package.json`).
pub fn diff_lockfiles(
    base_lock: &[u8],
    head_lock: &[u8],
    base_pkg: Option<&[u8]>,
    head_pkg: Option<&[u8]>,
) -> Result<LockDiff, String> {
    let base_pkgs = parse_lockfile_packages(base_lock)?;
    let head_pkgs = parse_lockfile_packages(head_lock)?;

    // Verify manifest-lockfile synchronization when head package.json is supplied:
    // every dependency declared in root package.json must be accounted for in head package-lock.json.
    if let Some(hp_bytes) = head_pkg {
        verify_manifest_matches_lockfile(hp_bytes, head_lock)?;
    }

    let base_root = parse_root_deps(base_pkg, Some(base_lock));
    let head_root = parse_root_deps(head_pkg, Some(head_lock));

    let base_map: BTreeMap<&str, &LockPackage> = base_pkgs
        .iter()
        .map(|p| (p.instance_path.as_str(), p))
        .collect();
    let head_map: BTreeMap<&str, &LockPackage> = head_pkgs
        .iter()
        .map(|p| (p.instance_path.as_str(), p))
        .collect();

    // Direct dependencies whose spec or presence changed between base and head (for `unattributed` check).
    let changed_direct: BTreeSet<String> = {
        let base_specs = parse_root_dep_specs(base_pkg, Some(base_lock));
        let head_specs = parse_root_dep_specs(head_pkg, Some(head_lock));
        let mut s = BTreeSet::new();
        for (name, spec) in &head_specs {
            if base_specs.get(name) != Some(spec) {
                s.insert(name.clone());
            }
        }
        s
    };

    let routes = compute_shortest_routes(&head_root, &head_map);

    let mut transitions = Vec::new();
    for hp in &head_pkgs {
        let bp = base_map.get(hp.instance_path.as_str()).copied();
        let changed = match bp {
            None => true,
            Some(b) => {
                b.name != hp.name
                    || b.version != hp.version
                    || b.resolved != hp.resolved
                    || b.integrity != hp.integrity
            }
        };
        if !changed {
            continue;
        }

        let mut alarms = BTreeSet::new();
        if hp.sha512.is_none() && !hp.in_bundle {
            alarms.insert(LockAlarm::IntegrityMissing);
        }
        if let Some(b) = bp {
            if b.name == hp.name
                && b.version.is_some()
                && b.version == hp.version
                && b.sha512 != hp.sha512
            {
                alarms.insert(LockAlarm::SameVersionBytesChanged);
            }
            if b.source_kind != hp.source_kind {
                alarms.insert(LockAlarm::SourceKindChanged);
            }
            if b.registry_host.is_some()
                && hp.registry_host.is_some()
                && b.registry_host != hp.registry_host
            {
                alarms.insert(LockAlarm::RegistryHostChanged);
            }
        } else if !hp.in_bundle {
            if hp.source_kind != SourceKind::Registry {
                alarms.insert(LockAlarm::SourceKindChanged);
            }
            if hp.registry_host.as_deref() != Some("registry.npmjs.org") {
                alarms.insert(LockAlarm::RegistryHostChanged);
            }
        }

        let is_new_direct =
            head_root.all_direct.contains_key(&hp.name) && !base_root.all_direct.contains_key(&hp.name);
        let route = routes.get(&hp.instance_path).cloned().unwrap_or_default();
        let unattributed = if changed_direct.is_empty() {
            false
        } else {
            !route
                .first()
                .map(|edge| changed_direct.contains(&edge.to))
                .unwrap_or(false)
        };

        transitions.push(LockTransition {
            name: hp.name.clone(),
            instance_path: hp.instance_path.clone(),
            ref_version: bp.and_then(|b| b.version.clone()),
            ref_resolved: bp.and_then(|b| b.resolved.clone()),
            ref_integrity: bp.and_then(|b| b.integrity.clone()),
            ref_sha512: bp.and_then(|b| b.sha512.clone()),
            new_version: hp.version.clone(),
            new_resolved: hp.resolved.clone(),
            new_integrity: hp.integrity.clone(),
            new_sha512: hp.sha512.clone(),
            new_source_kind: hp.source_kind,
            in_bundle: hp.in_bundle,
            is_new_direct,
            route,
            unattributed,
            lock_alarms: alarms,
        });
    }

    let mut removed = Vec::new();
    for bp in &base_pkgs {
        if !head_map.contains_key(bp.instance_path.as_str()) {
            removed.push(RemovedPackage {
                name: bp.name.clone(),
                instance_path: bp.instance_path.clone(),
                version: bp.version.clone(),
                sha512: bp.sha512.clone(),
            });
        }
    }

    Ok(LockDiff {
        transitions,
        removed,
    })
}

/// Deduplicates transitions that share `(name, new_version, ref_sha512, new_sha512, new_resolved, in_bundle)`
/// while merging alarms and `is_new_direct`. Returns grouped unique transitions plus all their instance paths.
pub fn deduplicate_transitions(transitions: &[LockTransition]) -> Vec<(LockTransition, Vec<String>)> {
    type DedupKey = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    );
    let mut order: Vec<DedupKey> = Vec::new();
    let mut groups: BTreeMap<DedupKey, (LockTransition, Vec<String>)> = BTreeMap::new();

    for t in transitions {
        let key = t.dedup_key();
        if let Some((rep, paths)) = groups.get_mut(&key) {
            rep.is_new_direct |= t.is_new_direct;
            rep.in_bundle &= t.in_bundle;
            rep.lock_alarms.extend(t.lock_alarms.iter().copied());
            if !t.route.is_empty() && (rep.route.is_empty() || t.route.len() < rep.route.len()) {
                rep.route = t.route.clone();
            }
            paths.push(t.instance_path.clone());
        } else {
            order.push(key.clone());
            groups.insert(key, (t.clone(), vec![t.instance_path.clone()]));
        }
    }

    order
        .into_iter()
        .filter_map(|k| groups.remove(&k))
        .collect()
}

fn verify_manifest_matches_lockfile(pkg_bytes: &[u8], lock_bytes: &[u8]) -> Result<(), String> {
    let pkg_val: Value = serde_json::from_slice(crate::archive::strip_utf8_bom(pkg_bytes))
        .map_err(|e| format!("invalid package.json: {e}"))?;
    let lock_val: Value = serde_json::from_slice(lock_bytes)
        .map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let Some(pkg_obj) = pkg_val.as_object() else {
        return Err("package.json is not a JSON object".into());
    };
    let Some(lock_packages) = lock_val.get("packages").and_then(|v| v.as_object()) else {
        return Err("package-lock.json missing packages map".into());
    };
    let lock_root = lock_packages.get("").and_then(|v| v.as_object());

    for sec in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(pkg_sec) = pkg_obj.get(sec).and_then(|v| v.as_object()) else {
            continue;
        };
        for (dep_name, pkg_spec) in pkg_sec {
            let lock_spec = lock_root
                .and_then(|r| r.get(sec))
                .and_then(|s| s.as_object())
                .and_then(|m| m.get(dep_name));
            let has_node_modules = lock_packages.contains_key(&format!("node_modules/{dep_name}"));
            if lock_spec != Some(pkg_spec) && !has_node_modules {
                return Err(format!(
                    "package.json {sec}.{dep_name} is not synchronized with package-lock.json"
                ));
            }
            if lock_spec.is_some() && lock_spec != Some(pkg_spec) {
                return Err(format!(
                    "package.json {sec}.{dep_name} spec differs from package-lock.json root record"
                ));
            }
        }
    }
    Ok(())
}

fn parse_root_deps(pkg_bytes: Option<&[u8]>, lock_bytes: Option<&[u8]>) -> RootDeps {
    let mut root = RootDeps::default();
    let val = pkg_bytes
        .and_then(|b| serde_json::from_slice::<Value>(crate::archive::strip_utf8_bom(b)).ok())
        .or_else(|| {
            lock_bytes
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .and_then(|v| v.pointer("/packages/").cloned())
        });
    if let Some(Value::Object(obj)) = val {
        collect_edge_map(&obj, "dependencies", EdgeKind::Prod, &mut root.all_direct);
        collect_edge_map(&obj, "optionalDependencies", EdgeKind::Optional, &mut root.all_direct);
        collect_edge_map(&obj, "peerDependencies", EdgeKind::Peer, &mut root.all_direct);
        collect_edge_map(&obj, "devDependencies", EdgeKind::Dev, &mut root.all_direct);
    }
    // Include workspace root definitions from the lockfile so workspace direct deps trigger S5 and get routes.
    if let Some(lb) = lock_bytes {
        if let Ok(lock_val) = serde_json::from_slice::<Value>(lb) {
            if let Some(packages) = lock_val.get("packages").and_then(|v| v.as_object()) {
                let mut ws_dirs = BTreeSet::new();
                for entry in packages.values() {
                    if let Some(obj) = entry.as_object() {
                        if obj.get("link").and_then(|v| v.as_bool()) == Some(true) {
                            if let Some(target) = obj.get("resolved").and_then(|v| v.as_str()) {
                                let clean = target.trim_start_matches("./").trim_end_matches('/');
                                if !clean.is_empty() && !clean.starts_with("node_modules/") {
                                    ws_dirs.insert(clean.to_string());
                                }
                            }
                        }
                    }
                }
                for dir in ws_dirs {
                    if let Some(obj) = packages.get(&dir).and_then(|v| v.as_object()) {
                        collect_edge_map(obj, "dependencies", EdgeKind::Prod, &mut root.all_direct);
                        collect_edge_map(
                            obj,
                            "optionalDependencies",
                            EdgeKind::Optional,
                            &mut root.all_direct,
                        );
                        collect_edge_map(obj, "peerDependencies", EdgeKind::Peer, &mut root.all_direct);
                        collect_edge_map(obj, "devDependencies", EdgeKind::Dev, &mut root.all_direct);
                    }
                }
            }
        }
    }
    root
}

fn parse_root_dep_specs(
    pkg_bytes: Option<&[u8]>,
    lock_bytes: Option<&[u8]>,
) -> BTreeMap<String, String> {
    let mut specs = BTreeMap::new();
    let val = pkg_bytes
        .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        .or_else(|| {
            lock_bytes
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .and_then(|v| v.pointer("/packages/").cloned())
        });
    if let Some(Value::Object(obj)) = val {
        for sec in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "devDependencies",
        ] {
            if let Some(map) = obj.get(sec).and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        specs.insert(k.clone(), s.to_string());
                    }
                }
            }
        }
    }
    specs
}

fn collect_edge_map(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    kind: EdgeKind,
    out: &mut BTreeMap<String, EdgeKind>,
) {
    if let Some(map) = obj.get(key).and_then(|v| v.as_object()) {
        for dep_name in map.keys() {
            out.entry(dep_name.clone()).or_insert(kind);
        }
    }
}

fn compute_shortest_routes(
    root: &RootDeps,
    packages: &BTreeMap<&str, &LockPackage>,
) -> BTreeMap<String, Vec<RouteEdge>> {
    let mut routes: BTreeMap<String, Vec<RouteEdge>> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for (dep_name, &edge_kind) in &root.all_direct {
        let inst = format!("node_modules/{dep_name}");
        if packages.contains_key(inst.as_str()) && !routes.contains_key(&inst) {
            routes.insert(
                inst.clone(),
                vec![RouteEdge {
                    from: "root".to_string(),
                    to: dep_name.clone(),
                    kind: edge_kind,
                }],
            );
            queue.push_back(inst);
        }
    }

    while let Some(curr_inst) = queue.pop_front() {
        let Some(&pkg) = packages.get(curr_inst.as_str()) else {
            continue;
        };
        let curr_route = routes.get(&curr_inst).cloned().unwrap_or_default();
        for (dep_name, &edge_kind) in &pkg.dependencies {
            if let Some(target_inst) = resolve_node_modules_path(&curr_inst, dep_name, packages) {
                if !routes.contains_key(&target_inst) {
                    let mut next_route = curr_route.clone();
                    next_route.push(RouteEdge {
                        from: pkg.name.clone(),
                        to: dep_name.clone(),
                        kind: edge_kind,
                    });
                    routes.insert(target_inst.clone(), next_route);
                    queue.push_back(target_inst);
                }
            }
        }
    }

    routes
}

/// Walks up npm's nested `node_modules` hierarchy from `from_inst` to resolve `dep_name`.
fn resolve_node_modules_path(
    from_inst: &str,
    dep_name: &str,
    packages: &BTreeMap<&str, &LockPackage>,
) -> Option<String> {
    let mut prefix = from_inst;
    loop {
        let candidate = if prefix.is_empty() {
            format!("node_modules/{dep_name}")
        } else {
            format!("{prefix}/node_modules/{dep_name}")
        };
        if packages.contains_key(candidate.as_str()) {
            return Some(candidate);
        }
        if prefix.is_empty() {
            return None;
        }
        prefix = match prefix.rfind("/node_modules/") {
            Some(idx) => &prefix[..idx],
            None => "",
        };
    }
}

pub fn infer_name_from_instance_path(path: &str) -> Option<String> {
    let rest = match path.rfind("node_modules/") {
        Some(idx) => &path[idx + "node_modules/".len()..],
        None => path,
    };
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

fn classify_resolved(resolved: Option<&str>, in_bundle: bool) -> (SourceKind, Option<String>) {
    if in_bundle && resolved.is_none() {
        return (SourceKind::Bundled, None);
    }
    let Some(r) = resolved else {
        return (SourceKind::Unknown, None);
    };
    if r.starts_with("git+")
        || r.starts_with("git://")
        || r.starts_with("github:")
        || r.starts_with("ssh://")
    {
        return (SourceKind::Git, None);
    }
    if r.starts_with("file:") {
        return (SourceKind::File, None);
    }
    if let Some(after_scheme) = r.strip_prefix("https://") {
        let host = after_scheme
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if r.contains("/-/") && r.ends_with(".tgz") {
            return (SourceKind::Registry, Some(host));
        }
        return (SourceKind::Url, Some(host));
    }
    if let Some(after_scheme) = r.strip_prefix("http://") {
        let host = after_scheme
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        // Plaintext http:// is never a trusted registry source.
        return (SourceKind::Url, Some(host));
    }
    (SourceKind::Unknown, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha512_sri;

    #[test]
    fn diffs_lockfiles_routes_direct_and_alarms() {
        let sri_a1 = sha512_sri(b"a-1.0.0");
        let sri_a2 = sha512_sri(b"a-1.0.1");
        let sri_b1 = sha512_sri(b"b-1.0.0");
        let sri_b1_tampered = sha512_sri(b"b-1.0.0-evil");
        let sri_c1 = sha512_sri(b"c-2.0.0");

        let base_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "pkg-a": "^1.0.0" } },
                "node_modules/pkg-a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz",
                    "integrity": sri_a1,
                    "dependencies": { "pkg-b": "^1.0.0" }
                },
                "node_modules/pkg-b": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg-b/-/pkg-b-1.0.0.tgz",
                    "integrity": sri_b1
                }
            }
        });

        let head_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "pkg-a": "^1.0.1", "pkg-c": "^2.0.0" } },
                "node_modules/pkg-a": {
                    "version": "1.0.1",
                    "resolved": "https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.1.tgz",
                    "integrity": sri_a2,
                    "dependencies": { "pkg-b": "^1.0.0" }
                },
                "node_modules/pkg-b": {
                    "version": "1.0.0",
                    "resolved": "https://evil.registry.invalid/pkg-b/-/pkg-b-1.0.0.tgz",
                    "integrity": sri_b1_tampered
                },
                "node_modules/pkg-c": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/pkg-c/-/pkg-c-2.0.0.tgz",
                    "integrity": sri_c1
                }
            }
        });

        let diff = diff_lockfiles(
            &serde_json::to_vec(&base_lock).unwrap(),
            &serde_json::to_vec(&head_lock).unwrap(),
            None,
            None,
        )
        .unwrap();

        assert_eq!(diff.transitions.len(), 3);
        let tb = diff.transitions.iter().find(|t| t.name == "pkg-b").unwrap();
        assert!(tb.lock_alarms.contains(&LockAlarm::SameVersionBytesChanged));
        assert!(tb.lock_alarms.contains(&LockAlarm::RegistryHostChanged));
        assert_eq!(tb.route.len(), 2);
        assert_eq!(tb.route[0].from, "root");
        assert_eq!(tb.route[0].to, "pkg-a");
        assert_eq!(tb.route[1].to, "pkg-b");

        let tc = diff.transitions.iter().find(|t| t.name == "pkg-c").unwrap();
        assert!(tc.is_new_direct);
        assert!(tc.lock_alarms.is_empty());
    }

    #[test]
    fn blocks_forged_top_level_in_bundle_dedup_smuggling_and_http_registry() {
        let base_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": { "": {} }
        });
        let head_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/top-forged": {
                    "version": "1.0.0",
                    "inBundle": true
                },
                "node_modules/parent/node_modules/victim": {
                    "version": "1.0.0",
                    "inBundle": true
                },
                "node_modules/victim": {
                    "version": "1.0.0",
                    "resolved": "http://evil.invalid/victim/-/victim-1.0.0.tgz"
                }
            }
        });

        let diff = diff_lockfiles(
            &serde_json::to_vec(&base_lock).unwrap(),
            &serde_json::to_vec(&head_lock).unwrap(),
            None,
            None,
        )
        .unwrap();

        let forged = diff
            .transitions
            .iter()
            .find(|t| t.instance_path == "node_modules/top-forged")
            .unwrap();
        assert!(!forged.in_bundle);
        assert!(forged.lock_alarms.contains(&LockAlarm::IntegrityMissing));
        assert!(forged.lock_alarms.contains(&LockAlarm::SourceKindChanged));

        // Deduplication must NOT collapse nested inBundle into top-level evil resolved URL!
        let unique = deduplicate_transitions(&diff.transitions);
        let victim_groups: Vec<_> = unique
            .iter()
            .filter(|(t, _)| t.name == "victim")
            .collect();
        assert_eq!(victim_groups.len(), 2);
        let evil = victim_groups
            .iter()
            .find(|(t, _)| t.new_resolved.is_some())
            .unwrap()
            .0
            .clone();
        assert!(!evil.in_bundle);
        assert!(evil.lock_alarms.contains(&LockAlarm::SourceKindChanged));
        assert!(evil.lock_alarms.contains(&LockAlarm::RegistryHostChanged));
    }

    #[test]
    fn handles_workspaces_without_leaking_local_dirs_and_catches_manifest_desync() {
        let sri_a = sha512_sri(b"a-1.0.0");
        let base_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": { "": {} }
        });
        let head_lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "workspaces": ["packages/*"], "dependencies": { "ext": "^1.0.0" } },
                "packages/sub": { "name": "@ws/sub", "version": "1.0.0", "dependencies": { "ext": "^1.0.0" } },
                "node_modules/@ws/sub": { "resolved": "packages/sub", "link": true },
                "node_modules/ext": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/ext/-/ext-1.0.0.tgz",
                    "integrity": sri_a
                }
            }
        });
        let head_pkg = serde_json::json!({
            "name": "root",
            "dependencies": { "ext": "^1.0.0" }
        });
        let diff = diff_lockfiles(
            &serde_json::to_vec(&base_lock).unwrap(),
            &serde_json::to_vec(&head_lock).unwrap(),
            None,
            Some(&serde_json::to_vec(&head_pkg).unwrap()),
        )
        .unwrap();
        assert_eq!(diff.transitions.len(), 1);
        assert_eq!(diff.transitions[0].name, "ext");

        // Desynchronized package.json adding an unlisted dep must error!
        let desync_pkg = serde_json::json!({
            "name": "root",
            "dependencies": { "ext": "^1.0.0", "sneaky": "1.0.0" }
        });
        assert!(diff_lockfiles(
            &serde_json::to_vec(&base_lock).unwrap(),
            &serde_json::to_vec(&head_lock).unwrap(),
            None,
            Some(&serde_json::to_vec(&desync_pkg).unwrap()),
        )
        .is_err());
    }
}
