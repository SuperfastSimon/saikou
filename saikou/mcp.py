"""Minimal read-only MCP (Model Context Protocol) JSON-RPC 2.0 server over stdio (stdlib only).

Exposes Saikou's verification checks to AI coding agents (Claude Code, Cursor, Codex, etc.)
so they can verify a proposed fix before opening a pull request. Strictly read-only: never
reads or writes the file system and never runs git.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional, TextIO

from . import service
from .engine import __version__
from .service import ServiceError

PROTOCOL_VERSION = "2024-11-05"
MAX_LINE_BYTES = 2_000_000

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "saikou_verify",
        "description": "Verify one before/after code pair to catch fake security fixes "
                       "(new suppressions, unwired guards, surviving sinks, elisions, API breaks).",
        "inputSchema": {
            "type": "object",
            "required": ["after"],
            "properties": {
                "path": {"type": "string"},
                "before": {"type": "string"},
                "after": {"type": "string"},
                "language": {"type": "string"},
                "mode": {"type": "string", "enum": ["verify", "gate"]},
                "claimed_threats": {"type": "array", "items": {"type": "string"}},
                "strict_api": {"type": "boolean"},
                "must_preserve": {"type": "array", "items": {"type": "string"}},
                "warn_only": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "saikou_verify_batch",
        "description": "Verify multiple before/after file pairs in one call.",
        "inputSchema": {
            "type": "object",
            "required": ["files"],
            "properties": {
                "mode": {"type": "string", "enum": ["verify", "gate"]},
                "files": {"type": "array", "items": {"type": "object"}},
                "claimed_threats": {"type": "array", "items": {"type": "string"}},
                "strict_api": {"type": "boolean"},
            },
        },
    },
    {
        "name": "saikou_checks",
        "description": "List all Saikou checks, provenance definitions, verification tiers, and limits.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _ok(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(raw: str) -> Optional[Dict[str, Any]]:
    """Process one JSON-RPC 2.0 request line. Returns None for notifications."""
    if len(raw.encode("utf-8", "replace")) > MAX_LINE_BYTES:
        return _err(None, -32600, f"Request exceeds {MAX_LINE_BYTES} bytes.")
    try:
        msg = json.loads(raw)
    except (ValueError, RecursionError):
        return _err(None, -32700, "Parse error: invalid JSON.")
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid JSON-RPC request.")

    if "id" not in msg:
        return None             # a notification (no id) never gets a reply, JSON-RPC 2.0 section 4.1
    req_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "saikou", "version": __version__},
        })
    if method == "tools/list":
        return _ok(req_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments")
        if not isinstance(name, str) or (args is not None and not isinstance(args, dict)):
            return _err(req_id, -32602, "Invalid params: expected tool name and object arguments.")
        args = args or {}
        try:
            if name == "saikou_verify":
                data = service.verify(args)
            elif name == "saikou_verify_batch":
                data = service.verify_batch(args)
            elif name == "saikou_checks":
                data = service.checks()
            else:
                return _err(req_id, -32602, f"Unknown tool: {name}")
        except ServiceError as exc:
            return _ok(req_id, {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(exc.as_dict())}],
            })
        return _ok(req_id, {
            "isError": False,
            "content": [{"type": "text", "text": json.dumps(data)}],
        })
    return _err(req_id, -32601, f"Method not found: {method}")


def serve_stdio(stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None) -> int:
    """Serve newline-delimited JSON-RPC 2.0 MCP requests until EOF."""
    inp = stdin or sys.stdin
    out = stdout or sys.stdout
    for line in inp:
        stripped = line.strip()
        if not stripped:
            continue
        reply = handle_request(stripped)
        if reply is not None:
            out.write(json.dumps(reply) + "\n")
            out.flush()
    return 0
