use assay_core::canonical::to_canonical_json;
use assay_core::model::ReadingOutcome;
use assay_core::packet::{ReadingPacket, reverse_packet_units};
use assay_core::reader::{
    READER_SYSTEM_PROMPT, ReadingRecord, instruction_hash, reader_output_json_schema,
    validate_reading_output,
};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct ReaderExecConfig {
    pub command: Option<String>,
    pub model: String,
    pub effort: String,
    pub readings: u8,
    pub timeout_secs: u64,
}

impl Default for ReaderExecConfig {
    fn default() -> Self {
        Self {
            command: None,
            model: "claude-opus-5-5".to_string(),
            effort: "high".to_string(),
            readings: 1,
            timeout_secs: 90,
        }
    }
}

/// Runs one (or two, when `cfg.readings >= 2`) reading passes and returns the validated `ReadingRecord`.
pub fn run_reading(
    packet: &ReadingPacket,
    ledger_id: &str,
    cfg: &ReaderExecConfig,
) -> ReadingRecord {
    if packet.units.iter().any(|u| u.unread) {
        return make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Unread,
            "at least one unexplained unit exceeded hard cap or was binary",
        );
    }

    let first = run_single_pass(packet, ledger_id, cfg);
    if cfg.readings < 2 || first.outcome != ReadingOutcome::Passed {
        return first;
    }

    // Second independent pass with reversed unit order; both passes must pass.
    match reverse_packet_units(packet) {
        Ok(rev_pkt) => {
            let second = run_single_pass(&rev_pkt, ledger_id, cfg);
            if second.outcome == ReadingOutcome::Passed {
                first
            } else {
                second
            }
        }
        Err(e) => make_status_record(
            packet,
            ledger_id,
            &cfg.model,
            ReadingOutcome::Invalid,
            &format!("failed reversing packet for second pass: {e}"),
        ),
    }
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

    let mut child = match Command::new(prog)
        .args(args)
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
        "max_tokens": 4096,
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

    let mut child = match Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-time",
            &cfg.timeout_secs.to_string(),
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            "anthropic-version: 2023-06-01",
            "-H",
            &format!("x-api-key: {api_key}"),
            "--data-binary",
            "@-",
            "https://api.anthropic.com/v1/messages",
        ])
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
                &cfg.model,
                ReadingOutcome::Unavailable,
                &format!("failed spawning curl for Anthropic API: {e}"),
            );
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.to_string().as_bytes());
    }
    let out = match child.wait_with_output() {
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

    // SPEC 7.6: Always inspect stop_reason before reading content.
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
    if let Some(ref cl) = packet.stated_change.changelog_diff {
        s.push_str("\nChangelog diff:\n");
        s.push_str(cl);
        s.push('\n');
    }
    if !packet.facts.breaks.is_empty() || !packet.facts.flags.is_empty() || !packet.facts.new_reach.is_empty() {
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
        schema: 1,
        ledger_id: ledger_id.to_string(),
        packet_hash: packet.packet_hash.clone(),
        model: model.to_string(),
        instruction_hash: instruction_hash(),
        units: Vec::new(),
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

        // Use python3 one-liner as a mock subprocess reader honouring stdin->stdout JSON contract
        let tmp = std::env::temp_dir().join(format!("assay-mock-reader-{}.py", std::process::id()));
        std::fs::write(
            &tmp,
            "import sys, json\np = json.load(sys.stdin)\nprint(json.dumps({'units':[{'unit_id':u['unit_id'],'fits_stated_change':'yes'} for u in p['units']],'findings':[],'summary':'Matches version bump.'}))\n",
        )
        .unwrap();

        let cfg = ReaderExecConfig {
            command: Some(format!("python3 {}", tmp.display())),
            model: "mock-reader".into(),
            effort: "low".into(),
            readings: 2,
            timeout_secs: 10,
        };

        let rec = run_reading(&pkt, "ledger-xyz", &cfg);
        assert_eq!(rec.outcome, ReadingOutcome::Passed);
        assert_eq!(rec.units.len(), 1);
        let _ = std::fs::remove_file(&tmp);
    }
}
