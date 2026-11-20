use assay_core::canonical::to_canonical_json;
use assay_core::model::ReadingOutcome;
use assay_core::packet::ReadingPacket;
use assay_core::reader::{
    READER_SYSTEM_PROMPT, ReadingRecord, instruction_hash, reader_output_json_schema,
    validate_reading_output,
};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ReaderExecConfig {
    pub command: Option<String>,
    pub model: String,
    pub effort: String,
    pub timeout_secs: u64,
}

impl Default for ReaderExecConfig {
    fn default() -> Self {
        Self {
            command: None,
            model: "claude-opus-5-5".to_string(),
            effort: "high".to_string(),
            timeout_secs: 90,
        }
    }
}

/// Runs the configured reader (built-in Anthropic or external subprocess).
/// Splits large multi-unit packets into bounded batches so each request stays within token limits.
pub fn run_reading(
    packet: &ReadingPacket,
    ledger_id: &str,
    cfg: &ReaderExecConfig,
) -> ReadingRecord {
    if packet.units.is_empty() {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Invalid,
            "reading packet contained zero units",
        );
    }
    if packet.units.iter().any(|u| u.unread) {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unread,
            "at least one unexplained unit exceeded hard cap or was binary",
        );
    }

    // Batch units so no single model call exceeds ~28 KiB of diff lines.
    let batches = batch_packet_units(packet, 28_000);
    if batches.len() == 1 {
        return run_single_pass(packet, ledger_id, cfg);
    }

    let mut all_findings = Vec::new();
    let mut summaries = Vec::new();
    let mut dropped_total = 0usize;
    let mut total_units_read = 0usize;

    for batch_pkt in batches {
        let rec = run_single_pass(&batch_pkt, ledger_id, cfg);
        match rec.outcome {
            ReadingOutcome::Passed => {
                total_units_read += rec.units_read;
                if !rec.summary.is_empty() {
                    summaries.push(rec.summary);
                }
            }
            ReadingOutcome::Concern => {
                total_units_read += rec.units_read;
                all_findings.extend(rec.findings);
                dropped_total += rec.dropped_findings;
                if !rec.summary.is_empty() {
                    summaries.push(rec.summary);
                }
            }
            other => {
                return ReadingRecord {
                    packet_hash: packet.packet_hash.clone(),
                    outcome: other,
                    ..rec
                };
            }
        }
    }

    let combined_summary = summaries
        .join(" ")
        .chars()
        .take(600)
        .collect::<String>();
    let outcome = if dropped_total > 0 {
        ReadingOutcome::Invalid
    } else if all_findings.is_empty() {
        ReadingOutcome::Passed
    } else {
        ReadingOutcome::Concern
    };

    ReadingRecord {
        kind: "reading".to_string(),
        schema: 2,
        ledger_id: ledger_id.to_string(),
        packet_hash: packet.packet_hash.clone(),
        model: cfg.model.clone(),
        instruction_hash: instruction_hash(),
        units_read: total_units_read,
        findings: all_findings,
        dropped_findings: dropped_total,
        summary: combined_summary,
        outcome,
        error_detail: None,
    }
}

fn batch_packet_units(packet: &ReadingPacket, max_bytes: usize) -> Vec<ReadingPacket> {
    let mut batches = Vec::new();
    let mut cur_units = Vec::new();
    let mut cur_bytes = 0usize;

    for u in &packet.units {
        let u_bytes: usize = u.lines.iter().map(|l| l.len() + 1).sum();
        if !cur_units.is_empty() && cur_bytes + u_bytes > max_bytes {
            let mut p = packet.clone();
            p.units = std::mem::take(&mut cur_units);
            batches.push(p);
            cur_bytes = 0;
        }
        cur_bytes += u_bytes;
        cur_units.push(u.clone());
    }
    if !cur_units.is_empty() {
        let mut p = packet.clone();
        p.units = cur_units;
        batches.push(p);
    }
    batches
}

fn run_single_pass(
    packet: &ReadingPacket,
    ledger_id: &str,
    cfg: &ReaderExecConfig,
) -> ReadingRecord {
    if let Some(ref cmd_str) = cfg.command {
        run_subprocess_reader(cmd_str, packet, ledger_id, &cfg.model)
    } else {
        run_builtin_anthropic_reader(packet, ledger_id, cfg)
    }
}

fn run_subprocess_reader(
    cmd_str: &str,
    packet: &ReadingPacket,
    ledger_id: &str,
    model: &str,
) -> ReadingRecord {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    let Some((prog, args)) = parts.split_first() else {
        return make_status_record(
            packet,
            ledger_id,
            model,
            ReadingOutcome::Unavailable,
            "empty reader.command",
        );
    };

    let Ok(packet_json) = to_canonical_json(packet) else {
        return make_status_record(
            packet,
            ledger_id,
            model,
            ReadingOutcome::Invalid,
            "failed serializing reading packet",
        );
    };

    // Scrub inherited environment so secrets (e.g. ANTHROPIC_API_KEY, GITHUB_TOKEN) never leak
    // to external `reader.command` subprocesses.
    let mut cmd = Command::new(prog);
    cmd.args(args).env_clear();
    for var in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    let mut child = match cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return make_status_record(
                packet,
                ledger_id,
                model,
                ReadingOutcome::Unavailable,
                &format!("failed spawning reader '{cmd_str}': {e}"),
            );
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(packet_json.as_bytes());
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return make_status_record(
                packet,
                ledger_id,
                model,
                ReadingOutcome::Unavailable,
                &format!("reader process error: {e}"),
            );
        }
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return make_status_record(
            packet,
            ledger_id,
            model,
            ReadingOutcome::Unavailable,
            &format!("reader exited with {}: {}", out.status, stderr.trim()),
        );
    }

    let raw_stdout = String::from_utf8_lossy(&out.stdout);
    validate_reading_output(packet, raw_stdout.trim(), ledger_id, model)
}

fn run_builtin_anthropic_reader(
    packet: &ReadingPacket,
    ledger_id: &str,
    cfg: &ReaderExecConfig,
) -> ReadingRecord {
    let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") else {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unavailable,
            "ANTHROPIC_API_KEY not set (set it or configure reader.command in assay.toml)",
        );
    };
    if api_key.trim().is_empty() {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unavailable,
            "ANTHROPIC_API_KEY is empty",
        );
    }

    let user_prompt = format_packet_prompt(packet);
    let body = json!({
        "model": cfg.model,
        "max_tokens": 16384,
        "system": [
            {
                "type": "text",
                "text": READER_SYSTEM_PROMPT,
                "cache_control": { "type": "ephemeral" }
            }
        ],
        "output_config": {
            "effort": cfg.effort,
            "format": {
                "type": "json_schema",
                "schema": reader_output_json_schema()
            }
        },
        "messages": [
            {
                "role": "user",
                "content": user_prompt
            }
        ]
    });

    // Write API key header to a 0600 temp curl config file (NEVER pass secret on argv where `ps` sees it!).
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let hdr_path = std::env::temp_dir().join(format!("assay-curl-hdr-{}-{nonce}", std::process::id()));
    let hdr_content = format!(
        "header = \"x-api-key: {}\"\nheader = \"anthropic-version: 2023-06-01\"\nheader = \"Content-Type: application/json\"\n",
        api_key.trim().replace('"', "")
    );
    if let Err(e) = write_private_file(&hdr_path, hdr_content.as_bytes()) {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unavailable,
            &format!("failed creating private curl header config: {e}"),
        );
    }

    let spawn_res = Command::new("curl")
        .args([
            "-q",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-time",
            &cfg.timeout_secs.to_string(),
            "-X",
            "POST",
            "-K",
            &hdr_path.display().to_string(),
            "--data-binary",
            "@-",
            "--",
            "https://api.anthropic.com/v1/messages",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_file(&hdr_path);
            return make_status_record(
                packet,
                ledger_id,
                &cfg.model,
                ReadingOutcome::Unavailable,
                &format!("failed spawning curl for Anthropic API: {e}"),
            );
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.to_string().as_bytes());
    }
    let out = child.wait_with_output();
    let _ = fs::remove_file(&hdr_path);

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return make_status_record(
                packet,
                ledger_id,
                &cfg.model,
                ReadingOutcome::Unavailable,
                &format!("curl wait error: {e}"),
            );
        }
    };

    let Ok(resp) = serde_json::from_slice::<Value>(&out.stdout) else {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unavailable,
            &format!(
                "non-JSON response from Anthropic API: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        );
    };

    if let Some(err_msg) = resp.pointer("/error/message").and_then(|v| v.as_str()) {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unavailable,
            &format!("Anthropic API error: {err_msg}"),
        );
    }

    let stop_reason = resp
        .get("stop_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if stop_reason == "refusal" {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Refused,
            "reader_refused: model API refused content",
        );
    }
    if stop_reason == "max_tokens" {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Invalid,
            "reader stopped at max_tokens",
        );
    }

    let text = resp
        .get("content")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("text"))
                .and_then(|c| c.get("text").and_then(|t| t.as_str()))
        });

    match text {
        Some(raw_json) => validate_reading_output(packet, raw_json, ledger_id, &cfg.model),
        None => make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Invalid,
            "Anthropic API response contained no text block",
        ),
    }
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

fn format_packet_prompt(packet: &ReadingPacket) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Package: {} ({} -> {}, step: {:?})\n",
        packet.header.name,
        packet.header.from_version.as_deref().unwrap_or("none"),
        packet.header.to_version,
        packet.header.step_kind
    ));
    if !packet.stated_change.commit_subjects.is_empty() {
        s.push_str("\nCommit subjects:\n");
        for sub in &packet.stated_change.commit_subjects {
            s.push_str(&format!("- {sub}\n"));
        }
    }
    if !packet.facts.breaks.is_empty()
        || !packet.facts.flags.is_empty()
        || !packet.facts.new_reach.is_empty()
    {
        s.push_str(&format!(
            "\nFacts: breaks={:?} flags={:?} new_reach={:?} new_hostnames={:?}\n",
            packet.facts.breaks,
            packet.facts.flags,
            packet.facts.new_reach,
            packet.facts.new_hostnames
        ));
    }
    if let Some(ref sd) = packet.source_diff {
        s.push_str("\nAnchored source diff context:\n```diff\n");
        s.push_str(sd);
        s.push_str("\n```\n");
    }
    for u in &packet.units {
        s.push_str(&format!(
            "\n=== UNIT: {} (lines 1..={}) ===\n",
            u.unit_id, u.line_count
        ));
        s.push_str(&u.numbered_text());
    }
    s
}

fn make_status_record(
    packet: &ReadingPacket,
    ledger_id: &str,
    model: &str,
    outcome: ReadingOutcome,
    detail: &str,
) -> ReadingRecord {
    ReadingRecord {
        kind: "reading".to_string(),
        schema: 2,
        ledger_id: ledger_id.to_string(),
        packet_hash: packet.packet_hash.clone(),
        model: model.to_string(),
        instruction_hash: instruction_hash(),
        units_read: 0,
        findings: Vec::new(),
        dropped_findings: 0,
        summary: String::new(),
        outcome,
        error_detail: Some(detail.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assay_core::packet::{PacketFacts, PacketHeader, ReadingUnit, StatedChange, StepKind};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn mock_subprocess_reader_end_to_end() {
        let pkt = ReadingPacket {
            schema: 1,
            header: PacketHeader {
                name: "demo".into(),
                from_version: Some("1.0.0".into()),
                to_version: "1.0.1".into(),
                step_kind: StepKind::Patch,
            },
            stated_change: StatedChange {
                changelog_diff: None,
                commit_subjects: vec!["fix: bump version".into()],
            },
            facts: PacketFacts {
                totals: BTreeMap::new(),
                breaks: BTreeSet::new(),
                flags: BTreeSet::new(),
                new_reach: BTreeSet::new(),
                new_hostnames: BTreeSet::new(),
                unexplained_code_bytes: 20,
                unexplained_non_exec_bytes: 0,
                skipped_non_exec_files: vec![],
            },
            units: vec![ReadingUnit {
                unit_id: "package/version.js".into(),
                path: "package/version.js".into(),
                is_new_file: false,
                is_minified_split: false,
                chunk_index: 1,
                chunk_total: 1,
                unread: false,
                line_count: 1,
                lines: vec!["+export const v = '1.0.1';".into()],
            }],
            source_diff: None,
            packet_hash: "pkt1".into(),
        };

        let tmp = std::env::temp_dir().join(format!("assay-mock-reader-{}.py", std::process::id()));
        fs::write(
            &tmp,
            "import sys, json\njson.load(sys.stdin)\nprint(json.dumps({'findings':[],'summary':'Matches version bump.'}))\n",
        )
        .unwrap();

        let cfg = ReaderExecConfig {
            command: Some(format!("python3 {}", tmp.display())),
            model: "mock-reader".into(),
            effort: "low".into(),
            timeout_secs: 10,
        };

        let rec = run_reading(&pkt, "ledger-xyz", &cfg);
        assert_eq!(rec.outcome, ReadingOutcome::Passed);
        assert_eq!(rec.units_read, 1);
        let _ = fs::remove_file(&tmp);
    }
}
