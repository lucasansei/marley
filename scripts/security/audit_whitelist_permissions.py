#!/usr/bin/env python3
"""Audit Frappe whitelisted functions missing explicit permission checks.

This script scans Python files using AST and reports functions decorated with
`@frappe.whitelist(...)` that do not contain explicit in-function permission
checks such as:
- `frappe.has_permission(...)`
- `frappe.only_for(...)`
- `<obj>.has_permission(...)`

Outputs:
- JSON file with full findings
- Markdown report with counts and prioritized findings
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class Finding:
    """Represents one whitelisted function permission finding."""

    file: str
    line: int
    function: str
    allow_guest: bool
    has_explicit_permission_check: bool
    risk: str


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for audit script."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan (default: current directory).",
    )
    parser.add_argument(
        "--json-output",
        default="security/issue-943/whitelist_audit.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--md-output",
        default="security/issue-943/whitelist_audit.md",
        help="Output Markdown path.",
    )
    return parser.parse_args()


def decorator_is_whitelist(decorator: ast.expr) -> tuple[bool, bool]:
    """Return whether a decorator is frappe.whitelist and if allow_guest is set."""

    allow_guest = False

    if isinstance(decorator, ast.Call):
        func = decorator.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "frappe"
            and func.attr == "whitelist"
        ):
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "allow_guest"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    allow_guest = True
            return True, allow_guest

    if (
        isinstance(decorator, ast.Attribute)
        and isinstance(decorator.value, ast.Name)
        and decorator.value.id == "frappe"
        and decorator.attr == "whitelist"
    ):
        return True, False

    return False, False


def has_explicit_permission_check(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if function body contains explicit permission gating calls."""

    for node in ast.walk(function_node):
        if not isinstance(node, ast.Call):
            continue

        fn = node.func

        if (
            isinstance(fn, ast.Attribute)
            and isinstance(fn.value, ast.Name)
            and fn.value.id == "frappe"
            and fn.attr in {"has_permission", "only_for"}
        ):
            return True

        if isinstance(fn, ast.Attribute) and fn.attr == "has_permission":
            return True

    return False


def iter_python_files(root: Path) -> Iterable[Path]:
    """Yield Python files under root excluding hidden and virtual directories."""

    excluded_parts = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
        "env",
        "venv",
        "__pycache__",
    }
    for path in root.rglob("*.py"):
        if any(part in excluded_parts for part in path.parts):
            continue
        yield path


def collect_findings(root: Path) -> list[Finding]:
    """Collect all whitelisted function findings under root."""

    findings: list[Finding] = []

    for file_path in iter_python_files(root):
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (UnicodeDecodeError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_whitelist = False
            allow_guest = False
            for decorator in node.decorator_list:
                decorator_matches, decorator_allow_guest = decorator_is_whitelist(decorator)
                if decorator_matches:
                    is_whitelist = True
                    allow_guest = allow_guest or decorator_allow_guest

            if not is_whitelist:
                continue

            guarded = has_explicit_permission_check(node)
            risk = "high" if allow_guest and not guarded else "medium" if not guarded else "low"
            findings.append(
                Finding(
                    file=str(file_path.relative_to(root)),
                    line=node.lineno,
                    function=node.name,
                    allow_guest=allow_guest,
                    has_explicit_permission_check=guarded,
                    risk=risk,
                )
            )

    findings.sort(key=lambda item: (item.has_explicit_permission_check, item.risk, item.file, item.line))
    return findings


def write_outputs(findings: list[Finding], json_output: Path, md_output: Path) -> None:
    """Write JSON and Markdown outputs."""

    json_output.parent.mkdir(parents=True, exist_ok=True)
    md_output.parent.mkdir(parents=True, exist_ok=True)

    json_output.write_text(
        json.dumps([asdict(item) for item in findings], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    total = len(findings)
    unguarded = [item for item in findings if not item.has_explicit_permission_check]
    high = [item for item in unguarded if item.risk == "high"]
    medium = [item for item in unguarded if item.risk == "medium"]

    lines = [
        "# Issue #943 - Whitelist Permission Audit",
        "",
        f"- Total `@frappe.whitelist` functions: {total}",
        f"- Unguarded functions: {len(unguarded)}",
        f"- High risk (allow_guest + unguarded): {len(high)}",
        f"- Medium risk (authenticated + unguarded): {len(medium)}",
        "",
        "## High risk findings",
    ]

    if high:
        for item in high:
            lines.append(f"- `{item.file}:{item.line}` `{item.function}`")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Top medium risk findings (first 100)")

    if medium:
        for item in medium[:100]:
            lines.append(f"- `{item.file}:{item.line}` `{item.function}`")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Notes")
    lines.append("- Heuristic audit via AST. Manual review is required before patch merge.")
    lines.append("- Calls to permission wrappers not using `has_permission` naming may need manual validation.")

    md_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    """Run audit and write outputs."""

    args = parse_args()
    root = Path(args.root).resolve()
    findings = collect_findings(root)
    write_outputs(findings, root / args.json_output, root / args.md_output)
    print(f"[ok] Findings: {len(findings)}")
    print(f"[ok] JSON: {args.json_output}")
    print(f"[ok] Markdown: {args.md_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
