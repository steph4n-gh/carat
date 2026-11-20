use serde_json::{Value, json};
use std::io::{BufRead, Write};

pub trait McpDispatcher {
    fn call_tool(&self, name: &str, arguments: &Value) -> Result<Value, String>;
}

/// Runs Carat's JSON-RPC 2.0 stdio MCP server.
/// Agents receive verdicts, routes, and inline residual diffs; no approval tool is ever exposed.
pub fn run_mcp_server<D: McpDispatcher>(dispatcher: &D) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line_res in stdin.lock().lines() {
        let line = line_res.map_err(|e| format!("mcp stdin read error: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = handle_jsonrpc_line(trimmed, dispatcher) {
            writeln!(out, "{resp}").map_err(|e| format!("mcp stdout write error: {e}"))?;
            out.flush().map_err(|e| format!("mcp stdout flush error: {e}"))?;
        }
    }
    Ok(())
}

pub fn handle_jsonrpc_line<D: McpDispatcher>(line: &str, dispatcher: &D) -> Option<String> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            let err = json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32700, "message": format!("Parse error: {e}") }
            });
            return Some(err.to_string());
        }
    };

    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

    if id.is_none() || method == "notifications/initialized" {
        return None;
    }
    let id = id.unwrap();

    let response = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "carat",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "ping" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": mcp_tools_schema()
            }
        }),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            if !matches!(tool_name, "carat_explain" | "carat_check" | "carat_add") {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32602,
                        "message": format!("Unknown or disallowed tool: {tool_name}")
                    }
                })
            } else {
                match dispatcher.call_tool(tool_name, &args) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                                }
                            ],
                            "isError": false
                        }
                    }),
                    Err(err_msg) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": err_msg
                                }
                            ],
                            "isError": true
                        }
                    }),
                }
            }
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {other}")
            }
        }),
    };

    Some(response.to_string())
}

pub fn mcp_tools_schema() -> Value {
    json!([
        {
            "name": "carat_explain",
            "description": "Compute a byte-level balance sheet and inline residual diffs for one npm package transition (<name>@<from>..<to>). Never approves stops.",
            "inputSchema": {
                "type": "object",
                "required": ["spec"],
                "properties": {
                    "spec": { "type": "string", "description": "Transition spec like vite@8.3.7..8.3.8" },
                    "read": { "type": "boolean", "description": "Run the configured reader on unexplained code diffs (default: false)" }
                }
            }
        },
        {
            "name": "carat_check",
            "description": "Check all package transitions between a base and head package-lock.json (lockfile v3). Returns per-transition verdicts, routes, residual diffs, and stop reasons. Never approves stops.",
            "inputSchema": {
                "type": "object",
                "required": ["base_lock", "head_lock"],
                "properties": {
                    "base_lock": { "type": "string", "description": "Path to base package-lock.json" },
                    "head_lock": { "type": "string", "description": "Path to head package-lock.json" },
                    "base_pkg": { "type": "string", "description": "Optional path to base package.json" },
                    "head_pkg": { "type": "string", "description": "Optional path to head package.json" },
                    "read": { "type": "boolean", "description": "Run the configured reader on unexplained code diffs" }
                }
            }
        },
        {
            "name": "carat_add",
            "description": "Resolve and check an npm dependency in an isolated temp directory with --ignore-scripts. If install=true and EVERY transition passes, atomically writes the exact checked lockfile and runs `npm ci --ignore-scripts` (zero re-resolution). Stops require human approval.",
            "inputSchema": {
                "type": "object",
                "required": ["package"],
                "properties": {
                    "package": { "type": "string", "description": "Package specifier like zod or zod@4.6.7" },
                    "dev": { "type": "boolean", "description": "Save to devDependencies (--save-dev, default: false)" },
                    "project_dir": { "type": "string", "description": "Project directory containing package.json / package-lock.json (default: current directory)" },
                    "read": { "type": "boolean", "description": "Run the configured reader on unexplained code diffs" },
                    "install": { "type": "boolean", "description": "When true and all transitions pass, write the exact checked lockfile and run npm ci --ignore-scripts (default: false)" }
                }
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDisp;
    impl McpDispatcher for MockDisp {
        fn call_tool(&self, name: &str, arguments: &Value) -> Result<Value, String> {
            Ok(json!({"tool": name, "args": arguments, "verdict": "explained"}))
        }
    }

    #[test]
    fn mcp_lists_only_non_approval_tools_and_dispatches() {
        let disp = MockDisp;
        let init_resp: Value = serde_json::from_str(
            &handle_jsonrpc_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &disp).unwrap(),
        )
        .unwrap();
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "carat");

        let list_resp: Value = serde_json::from_str(
            &handle_jsonrpc_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &disp).unwrap(),
        )
        .unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["carat_explain", "carat_check", "carat_add"]);
        assert!(!names.iter().any(|n| n.contains("approve")));

        let bad_resp: Value = serde_json::from_str(
            &handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"carat_approve","arguments":{}}}"#,
                &disp,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(bad_resp.get("error").is_some());

        let ok_resp: Value = serde_json::from_str(
            &handle_jsonrpc_line(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"carat_explain","arguments":{"spec":"chalk@6.0.0..6.0.1"}}}"#,
                &disp,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(ok_resp["result"]["isError"], false);
    }
}
