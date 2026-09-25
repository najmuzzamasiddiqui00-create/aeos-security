import sys
import json
import os

# Add root directory to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from aeos_core.scanner import SecurityScanner
from aeos_core.remediation import RemediationEngine
from aeos_core.report_generator import ReportGenerator

SERVER_NAME = "aeos-security-mcp"
SERVER_VERSION = "2.4.0"

TOOLS = [
    {
        "name": "aeos_scan_repo",
        "description": "Scans a local repository for hardcoded secrets (API keys, DB URIs), vulnerable dependencies (CVEs), and license risks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the repository or project directory."
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "aeos_remediate_code",
        "description": "Generates safe unified diff patches for vulnerable dependencies and unprotected .env files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the repository."
                },
                "max_fixes": {
                    "type": "integer",
                    "description": "Max number of issues to auto-patch (defaults to 2 for free tier)."
                },
                "apply_to_disk": {
                    "type": "boolean",
                    "description": "Whether to write the patches directly to files on disk."
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "aeos_generate_compliance_report",
        "description": "Generates an auditable compliance certificate or GitHub PR markdown review for the repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the repository."
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "html", "json"],
                    "description": "Desired report format."
                }
            },
            "required": ["path"]
        }
    }
]

def handle_rpc_message(msg: dict) -> dict:
    method = msg.get("method")
    msg_id = msg.get("id")

    # Handle notifications (no id)
    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS
            }
        }

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name == "aeos_scan_repo":
            target = args.get("path", ".")
            scanner = SecurityScanner(target)
            results = scanner.scan()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(results, indent=2)
                        }
                    ]
                }
            }

        elif tool_name == "aeos_remediate_code":
            target = args.get("path", ".")
            max_fixes = args.get("max_fixes", 2)
            apply_to_disk = args.get("apply_to_disk", False)

            scanner = SecurityScanner(target)
            scan_results = scanner.scan()
            engine = RemediationEngine(target)
            patch_results = engine.generate_patches(scan_results, max_fixes=max_fixes)

            if apply_to_disk:
                engine.apply_patches(patch_results)

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "patches_count": patch_results["patches_count"],
                                "remaining_unpatched": patch_results["remaining_unpatched"],
                                "unified_diff": patch_results["unified_diff"]
                            }, indent=2)
                        }
                    ]
                }
            }

        elif tool_name == "aeos_generate_compliance_report":
            target = args.get("path", ".")
            fmt = args.get("format", "markdown")
            scanner = SecurityScanner(target)
            scan_results = scanner.scan()
            engine = RemediationEngine(target)
            patch_results = engine.generate_patches(scan_results, max_fixes=2)
            reporter = ReportGenerator(scan_results, patch_results)

            if fmt == "html":
                content = reporter.generate_html_certificate()
            elif fmt == "json":
                content = json.dumps(reporter.generate_json_report(), indent=2)
            else:
                content = reporter.generate_pr_markdown()

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": content
                        }
                    ]
                }
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method or tool '{tool_name}' not found."
                }
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": -32601,
            "message": f"Unhandled method '{method}'"
        }
    }

def main():
    """
    Standard stdio loop for Model Context Protocol (MCP).
    """
    # Set binary mode / unbuffered standard I/O
    stdin = sys.stdin
    stdout = sys.stdout

    while True:
        try:
            line = stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            msg = json.loads(line)
            response = handle_rpc_message(msg)
            if response:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": str(e)}
            }
            stdout.write(json.dumps(err_resp) + "\n")
            stdout.flush()

if __name__ == "__main__":
    main()
