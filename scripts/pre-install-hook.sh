#!/usr/bin/env bash
# Coding-agent PreToolUse hook for Bash / run_command tool calls.
# Supports both Claude Code (tool_input.command + exit 2) and Antigravity
# (toolCall.args.CommandLine + JSON {"decision": "allow"|"deny"} on stdout).
#
# Blocks raw `npm install` / `npm i` / `npm add` / `npm update` calls (including wrappers and aliases)
# so agents MUST use Carat's zero-TOCTOU single-resolution installer (`carat add <pkg> --install`)
# or `npm ci --ignore-scripts` on a Carat-verified lockfile.
#
# Compatible with stock macOS /bin/bash 3.2 AND bash 5+.
set -euo pipefail

exec python3 -c '
import json
import os
import re
import shlex
import sys

NPM_MUTATING = {
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
    "add", "update", "up", "upgrade", "udpate", "install-test", "it",
}
FLAGS_WITH_VAL = {"--prefix", "--registry", "--workspace", "-w", "--tag", "--userconfig", "--cache", "-C"}
CMD_SEPARATORS = {";", "&&", "||", "|", "&", "\n"}


def respond(is_agy, allow, message=""):
    if is_agy:
        payload = {"decision": "allow"} if allow else {"decision": "deny", "reason": message}
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.exit(0)
    if allow:
        sys.exit(0)
    sys.stderr.write(message + "\n")
    sys.exit(2)


def split_shell_segments(cmd):
    lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";&|\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    segments = []
    cur = []
    for tok in lexer:
        if tok in CMD_SEPARATORS or (tok and all(c in ";&|\n" for c in tok)):
            if cur:
                segments.append(cur)
                cur = []
        else:
            cur.append(tok)
    if cur:
        segments.append(cur)
    return segments


raw = sys.stdin.read()
if not raw.strip():
    sys.exit(0)

try:
    data = json.loads(raw)
except Exception as e:
    sys.stderr.write(f"BLOCKED by Carat hook: invalid JSON payload: {e}\n")
    sys.exit(2)

if not isinstance(data, dict):
    sys.stderr.write("BLOCKED by Carat hook: hook payload must be a JSON object.\n")
    sys.exit(2)

tool_call = data.get("toolCall")
is_agy = isinstance(tool_call, dict)

if is_agy:
    args = tool_call.get("args") if isinstance(tool_call.get("args"), dict) else {}
    cmd = args.get("CommandLine") or args.get("command") or ""
else:
    tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
    cmd = tool_input.get("command") or data.get("command") or ""

if not isinstance(cmd, str) or not cmd.strip():
    respond(is_agy, True)

blocked = []
try:
    segments = split_shell_segments(cmd)
except ValueError:
    if re.search(r"(?:^|[^A-Za-z0-9_-])npm(?:\b|$)", cmd):
        blocked.append("unparseable shell command")
    segments = []

for tokens in segments:
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("env", "command", "nohup", "sudo"):
            idx += 1
            continue
        if "=" in tok and not tok.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(tokens):
        continue

    prog = os.path.basename(tokens[idx])
    if prog != "npm":
        continue

    sub_idx = idx + 1
    skip_next = False
    subcmd = None
    while sub_idx < len(tokens):
        tok = tokens[sub_idx]
        if skip_next:
            skip_next = False
            sub_idx += 1
            continue
        if tok in FLAGS_WITH_VAL:
            skip_next = True
            sub_idx += 1
            continue
        if tok.startswith("-"):
            sub_idx += 1
            continue
        subcmd = tok
        break

    if subcmd in NPM_MUTATING:
        pkgs = []
        is_dev = False
        skip_next = False
        for tok in tokens[sub_idx + 1:]:
            if skip_next:
                skip_next = False
                continue
            if tok in FLAGS_WITH_VAL:
                skip_next = True
                continue
            if tok in ("-D", "--save-dev"):
                is_dev = True
                continue
            if tok.startswith("-"):
                continue
            pkgs.append(tok)
        if pkgs:
            prefix = "-D " if is_dev else ""
            blocked.append(prefix + " ".join(pkgs))
        else:
            blocked.append(f"npm {subcmd}")

if not blocked:
    respond(is_agy, True)

lines = [
    "BLOCKED by Carat pre-install hook: direct '\''npm install'\'' / '\''npm add'\'' / '\''npm update'\'' is disabled to prevent re-resolution TOCTOU and lifecycle-script execution.",
    "Use Carat as the installer instead:",
]
for target in blocked:
    if target.startswith("npm ") or target == "unparseable shell command":
        lines.append("  carat check --base <old-lock> --head <new-lock> --json && npm ci --ignore-scripts")
    else:
        lines.append(f"  carat add {target} --install --json")
lines.append("Do NOT bypass this hook or run '\''carat approve'\''. Escalate any stop verdict to the human.")

respond(is_agy, False, "\n".join(lines))
'
