#!/usr/bin/env python3
"""Regression tests for scripts/pre-install-hook.sh across Claude Code and Antigravity payloads."""
import json
import pathlib
import subprocess

HOOK = str(pathlib.Path(__file__).resolve().parent / "pre-install-hook.sh")


def run(payload: str):
    p = subprocess.run([HOOK], input=payload, text=True, capture_output=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


# 1. Claude Code: block npm install
rc, out, err = run(json.dumps({"tool_input": {"command": "npm install zod"}}))
assert rc == 2 and "carat add zod --install --json" in err, (rc, out, err)

# 2. Claude Code: block npm install -D / --save-dev and preserve -D flag
rc, out, err = run(json.dumps({"tool_input": {"command": "npm install -D vite typescript"}}))
assert rc == 2 and "carat add -D vite typescript --install --json" in err, (rc, out, err)

rc, out, err = run(json.dumps({"tool_input": {"command": "npm i --save-dev @types/node"}}))
assert rc == 2 and "carat add -D @types/node --install --json" in err, (rc, out, err)

# 3. Claude Code: block env wrapper
rc, out, err = run(json.dumps({"tool_input": {"command": "echo hi && env NODE_ENV=dev npm i lodash@4.17.21"}}))
assert rc == 2 and "carat add lodash@4.17.21 --install --json" in err, (rc, out, err)

# 4. Claude Code: allow npm ci & npm test
rc, out, err = run(json.dumps({"tool_input": {"command": "npm ci --ignore-scripts && npm test"}}))
assert rc == 0 and out == "" and err == "", (rc, out, err)

# 5. Claude Code: allow quoted semicolon in python3 -c
rc, out, err = run(json.dumps({"tool_input": {"command": "python3 -c 'a = \"foo; bar\"; print(a)'"}}))
assert rc == 0 and out == "" and err == "", (rc, out, err)

# 6. Antigravity: block npm install -D with JSON deny stdout
rc, out, err = run(json.dumps({
    "hookEventName": "PreToolUse",
    "toolCall": {"id": "1", "name": "run_command", "args": {"CommandLine": "npm install -D vite react"}},
}))
assert rc == 0, (rc, out, err)
d = json.loads(out)
assert d["decision"] == "deny" and "carat add -D vite react --install --json" in d["reason"], d

# 7. Antigravity: allow npm run build
rc, out, err = run(json.dumps({
    "hookEventName": "PreToolUse",
    "toolCall": {"id": "2", "name": "run_command", "args": {"CommandLine": "npm run build"}},
}))
assert rc == 0 and json.loads(out) == {"decision": "allow"}, (rc, out, err)

# 8. Antigravity: allow heredoc with apostrophe
rc, out, err = run(json.dumps({
    "hookEventName": "PreToolUse",
    "toolCall": {"id": "3", "name": "run_command", "args": {"CommandLine": "cat <<'EOF'\nit's fine; really\nEOF"}},
}))
assert rc == 0 and json.loads(out) == {"decision": "allow"}, (rc, out, err)

# 9. Antigravity: fail-closed on unparseable command containing npm
rc, out, err = run(json.dumps({
    "hookEventName": "PreToolUse",
    "toolCall": {"id": "4", "name": "run_command", "args": {"CommandLine": "npm install 'unclosed"}},
}))
assert rc == 0 and json.loads(out)["decision"] == "deny", (rc, out, err)

print("ALL 9 PRE-INSTALL HOOK TESTS PASSED")
