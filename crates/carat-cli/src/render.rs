use carat_core::lockfile::RouteEdge;
use carat_core::model::{Decision, FileRole, OriginClass, ResidualDiff, TransitionLedger, Verdict};
use carat_core::reader::ReadingRecord;

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

    for item in items
        .iter()
        .filter(|i| i.decision.verdict == Verdict::Stop && i.approved_by.is_none())
    {
        out.push_str(&render_explain_markdown(item));
        out.push('\n');
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
