"""Optional tree-sitter AST backend for JavaScript and TypeScript (`pip install saikou[treesitter]`).

The core engine remains standard-library only. When `tree-sitter` and the matching grammar
package are installed, extra JS/TS guard checks run on a syntax tree. The tier stays
`structural`: parts of these checks still match text inside tree nodes. When absent, callers
fall back cleanly to the built-in structural checks without error.
"""

from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .engine import _JS_ASYNC_GUARD, _JS_GUARD_CALL, Finding, Severity

_GRAMMAR_MODULES: Dict[str, Tuple[str, str]] = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
}


def _load_parser(language: str) -> Optional[Any]:
    spec = _GRAMMAR_MODULES.get(language)
    if spec is None:
        return None
    try:
        ts = importlib.import_module("tree_sitter")
        gram = importlib.import_module(spec[0])
        lang_fn = getattr(gram, spec[1], None)
        if lang_fn is None:
            return None
        lang_obj = ts.Language(lang_fn())
        parser = ts.Parser(lang_obj)
        return parser
    except (ImportError, AttributeError, TypeError, ValueError):
        return None


def available(language: str) -> bool:
    """True when tree-sitter and the grammar for `language` are installed."""
    return _load_parser(language) is not None


def _node_text(node: Any) -> str:
    raw = getattr(node, "text", b"")
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _walk(node: Any) -> List[Any]:
    out: List[Any] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        out.append(cur)
        children = getattr(cur, "children", ()) or ()
        for child in reversed(children):
            stack.append(child)
    return out


def _condition(stmt_text: str) -> str:
    """The parenthesised condition of an if/while statement, without its body.

    `if (x) return save();` has no brace, so cutting at the first `{` would read the body as
    the condition; match the parentheses instead. Used only when the node has no `condition`
    field (test stubs). Unbalanced text gives "" (no finding), never the body."""
    start = stmt_text.find("(")
    if start < 0:
        return ""
    depth = 0
    for i in range(start, len(stmt_text)):
        ch = stmt_text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return stmt_text[start:i + 1]
    return ""


def js_ts_ast_checks(code: str, language: str, *,
                     parser_override: Optional[Any] = None) -> Tuple[List[Finding], bool]:
    """Run AST-backed JS/TS guard checks when tree-sitter is available.

    Returns (findings, used_ast). When `used_ast` is False, the caller should run the
    built-in structural checks and keep the tier at `structural`.
    """
    parser = parser_override if parser_override is not None else _load_parser(language)
    if parser is None:
        return [], False
    try:
        tree = parser.parse(code.encode("utf-8", "replace"))
        root = tree.root_node
    except Exception:
        return [], False

    nodes = _walk(root)
    findings: List[Finding] = []

    # 1. Unwired guards: variable_declarator assigning a guard call whose identifier is never read.
    assigned: Dict[str, Tuple[int, str]] = {}
    id_counts: Dict[str, int] = {}
    async_fns: Set[str] = set()

    for node in nodes:
        ntype = getattr(node, "type", "")
        text = _node_text(node)
        line = (getattr(node, "start_point", (0, 0))[0] or 0) + 1

        if ntype == "identifier":
            id_counts[text] = id_counts.get(text, 0) + 1
        elif ntype == "variable_declarator":
            children = list(getattr(node, "children", ()) or ())
            if len(children) >= 2 and getattr(children[0], "type", "") == "identifier":
                var_name = _node_text(children[0])
                rhs_node = children[-1]
                rhs_text = _node_text(rhs_node)
                if getattr(rhs_node, "type", "") in ("call_expression", "await_expression"):
                    m = re.search(r"([A-Za-z_$][\w$.]*)\s*\(", rhs_text)
                    if m and _JS_GUARD_CALL.match(m.group(1) + "("):
                        assigned[var_name] = (line, m.group(1))
        elif ntype in ("function_declaration", "method_definition") and text.lstrip().startswith("async "):
            m = re.search(r"async\s+(?:function\s+)?([A-Za-z_$][\w$]*)", text)
            if m:
                async_fns.add(m.group(1))

    # Count identifier occurrences outside declaration target across source tokens
    for var_name, (line, call_name) in assigned.items():
        if id_counts.get(var_name, 0) <= 1:
            # Verify against source text so fake/minimal trees still respect real usage
            uses = len(re.findall(r"(?<![\w$.])" + re.escape(var_name) + r"(?![\w$])", code))
            if uses <= 1:
                findings.append(Finding(
                    "js_guard_computed_but_unused", Severity.HARD_FAIL,
                    f"{var_name!r} is produced by a validation/sanitisation call ({call_name}) "
                    f"and never read again (tree-sitter). The guard is decorative.", line))

    # 2. Async guard used in boolean condition without await, and floated .catch() guards.
    for node in nodes:
        ntype = getattr(node, "type", "")
        text = _node_text(node)
        line = (getattr(node, "start_point", (0, 0))[0] or 0) + 1
        if ntype in ("if_statement", "while_statement") and async_fns:
            field = getattr(node, "child_by_field_name", None)
            cond_node = field("condition") if callable(field) else None
            cond = _node_text(cond_node) if cond_node is not None else _condition(text)
            if "await " not in cond:
                for fn_name in async_fns:
                    # own function or this.method(); not other.method() of the same name
                    if re.search(r"(?:(?<![\w$.])|(?<=this\.))" + re.escape(fn_name) + r"\s*\(", cond):
                        findings.append(Finding(
                            "js_async_guard_in_boolean", Severity.HARD_FAIL,
                            f"{fn_name!r} is defined async and used in a boolean condition "
                            f"without `await` (tree-sitter).", line))
        elif ntype == "expression_statement":
            m = re.match(r"^\s*([A-Za-z_$][\w$.]*)\s*\([^;\n]*\)\s*\.\s*catch\s*\(", text)
            if m and _JS_ASYNC_GUARD.search(m.group(1)):
                findings.append(Finding(
                    "js_floating_guard_promise", Severity.HARD_FAIL,
                    f"{m.group(1)!r} is an async guard whose Promise is floated with `.catch(...)` "
                    f"(tree-sitter).", line))

    return findings, True
