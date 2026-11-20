use assay_core::model::{Decision, FileRole, OriginClass, TransitionLedger, Verdict};

pub fn render_explain_markdown(ledger: &TransitionLedger, decision: &Decision) -> String {
    let mut out = String::new();
    let badge = match decision.verdict {
        Verdict::Explained => "OK  ",
        Verdict::Read => "READ",
        Verdict::Stop => "STOP",
    };

    let ref_ver = ledger
        .reference
        .as_ref()
        .map(|r| r.version.as_str())
        .unwrap_or("(none)");
    out.push_str(&format!(
        "{badge}  {} {} -> {}\n",
        ledger.name, ref_ver, ledger.new.version
    ));

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

    // Balance sheet table
    let total_files: u64 = ledger.totals.values().map(|t| t.files).sum();
    let total_bytes: u64 = ledger.totals.values().map(|t| t.bytes).sum();
    let carried = ledger.totals.get(&OriginClass::Carried).cloned().unwrap_or_default();
    let changed_files = total_files.saturating_sub(carried.files);
    let changed_bytes = total_bytes.saturating_sub(carried.bytes);
    let unexplained = ledger
        .totals
        .get(&OriginClass::Unexplained)
        .cloned()
        .unwrap_or_default();

    let explained_changed_bytes = changed_bytes.saturating_sub(unexplained.bytes);
    let explained_pct = if changed_bytes == 0 {
        100.0
    } else {
        (explained_changed_bytes as f64 / changed_bytes as f64) * 100.0
    };

    out.push_str(&format!(
        "      balance: {changed_files} changed file(s) ({}), {:.1}% explained",
        fmt_bytes(changed_bytes),
        explained_pct
    ));
    if carried.files > 0 {
        out.push_str(&format!(
            " | {} carried ({})",
            carried.files,
            fmt_bytes(carried.bytes)
        ));
    }
    if !ledger.removed_files.is_empty() {
        out.push_str(&format!(" | {} removed", ledger.removed_files.len()));
    }
    out.push('\n');

    // Per-class breakdown for non-carried files
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
                        " (exec/other: {}, d.ts/map/doc: {})",
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

    // List top unexplained executable files (up to 8)
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
        for f in unexplained_exec.iter().take(8) {
            let diffs = if f.significant_manifest_diffs.is_empty() {
                String::new()
            } else {
                format!(" [diffs: {}]", f.significant_manifest_diffs.join(", "))
            };
            out.push_str(&format!(
                "        * {} ({}){}\n",
                f.path,
                fmt_bytes(f.bytes),
                diffs
            ));
        }
        if unexplained_exec.len() > 8 {
            out.push_str(&format!(
                "        * ... and {} more\n",
                unexplained_exec.len() - 8
            ));
        }
    }

    // Breaks & flags
    if !ledger.breaks.is_empty() {
        out.push_str("      breaks (stop):\n");
        for b in &ledger.breaks {
            let note = ledger
                .break_notes
                .get(b)
                .map(|s| format!(" — {s}"))
                .unwrap_or_default();
            out.push_str(&format!("        ! {b:?}{note}\n"));
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
            out.push_str(&format!("        ~ {f:?}{note}\n"));
        }
    }

    // Reach
    if !ledger.new_reach.is_empty() {
        let toks: Vec<String> = ledger
            .new_reach
            .iter()
            .map(|t| {
                let mut s = format!("{t:?}");
                if t.is_high() {
                    s.push_str("[HIGH]");
                }
                if ledger.new_reach_in_unexplained.contains(t) {
                    s.push_str("(unexplained)");
                }
                s
            })
            .collect();
        out.push_str(&format!("      new reach: {}\n", toks.join(", ")));
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

    // Stop rules
    if !decision.stop_reasons.is_empty() {
        out.push_str("      stop reasons:\n");
        for r in &decision.stop_reasons {
            out.push_str(&format!("        - {r}\n"));
        }
    }

    out.push_str(&format!(
        "      subject: {} | ledger: {}\n",
        &ledger.subject[..16],
        &decision.ledger_id[..16]
    ));
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
