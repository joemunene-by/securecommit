"""Output formatters: console (Rich), JSON, SARIF, Markdown."""

from __future__ import annotations

import json
from typing import Any

from securecommit.models import ScanResult, Severity

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return result.to_json()


# ---------------------------------------------------------------------------
# Markdown (for PR comments)
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "! ",
    Severity.MEDIUM: "~ ",
    Severity.LOW: "- ",
    Severity.INFO: "i ",
}


def format_markdown(result: ScanResult) -> str:
    """Format scan results as Markdown suitable for a PR comment."""
    if not result.findings:
        return "## SecureCommit Scan\n\nNo security issues found.\n"

    lines = [
        "## SecureCommit Scan",
        "",
        f"**{result.stats.findings_total}** finding(s) across "
        f"**{result.stats.files_scanned}** file(s) scanned.",
        "",
    ]
    by_sev = sorted(
        result.findings,
        key=lambda f: list(Severity).index(f.severity),
        reverse=True,
    )
    for f in by_sev:
        lines.append(
            f"### [{f.severity.value.upper()}] {f.title} (`{f.rule_id}`)\n"
        )
        lines.append(f"**File:** `{f.file_path}` (line {f.line_number})\n")
        lines.append(f"```\n{f.snippet}\n```\n")
        lines.append(f"> {f.description}\n")
        lines.append(f"**Remediation:** {f.remediation}\n")
        lines.append("---\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Console (Rich)
# ---------------------------------------------------------------------------


def format_console(result: ScanResult) -> str:
    """Format scan results for Rich console output (returns Rich-markup string)."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text

        console = Console(record=True, width=120)

        if not result.findings:
            console.print("\n[bold green]SecureCommit: No security issues found.[/]\n")
            return console.export_text()

        severity_color = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }

        table = Table(
            title="SecureCommit Scan Results",
            show_lines=True,
            expand=True,
        )
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Rule", width=10)
        table.add_column("Title", width=30)
        table.add_column("File", width=30)
        table.add_column("Line", width=6, justify="right")
        table.add_column("Snippet", width=40)

        for f in sorted(
            result.findings,
            key=lambda x: list(Severity).index(x.severity),
            reverse=True,
        ):
            sev_text = Text(f.severity.value.upper())
            sev_text.stylize(severity_color.get(f.severity, ""))
            table.add_row(
                sev_text,
                f.rule_id,
                f.title,
                f.file_path,
                str(f.line_number),
                f.snippet[:80],
            )

        console.print()
        console.print(table)
        console.print(
            f"\n[bold]{result.stats.findings_total}[/] finding(s) | "
            f"[bold]{result.stats.files_scanned}[/] file(s) scanned | "
            f"Status: {'[bold green]PASSED[/]' if result.passed else '[bold red]FAILED[/]'}\n"
        )
        return console.export_text()
    except ImportError:
        # Fallback if Rich is not installed
        return _format_plain(result)


def _format_plain(result: ScanResult) -> str:
    """Plain-text fallback."""
    if not result.findings:
        return "SecureCommit: No security issues found.\n"
    lines = ["SecureCommit Scan Results", "=" * 60]
    for f in result.findings:
        lines.append(
            f"[{f.severity.value.upper()}] {f.rule_id}: {f.title}"
        )
        lines.append(f"  File: {f.file_path}:{f.line_number}")
        lines.append(f"  Snippet: {f.snippet[:80]}")
        lines.append(f"  Remediation: {f.remediation}")
        lines.append("")
    lines.append(
        f"{result.stats.findings_total} finding(s) | "
        f"{result.stats.files_scanned} file(s) | "
        f"{'PASSED' if result.passed else 'FAILED'}"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SARIF (GitHub Code Scanning)
# ---------------------------------------------------------------------------


def format_sarif(result: ScanResult) -> str:
    """Format results as SARIF v2.1.0 JSON for GitHub code scanning integration."""
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results_list: list[dict[str, Any]] = []

    for finding in result.findings:
        # Register rule if not already seen
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append({
                "id": finding.rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": "https://github.com/joemunene/securecommit",
                "help": {
                    "text": finding.remediation,
                    "markdown": f"**Remediation:** {finding.remediation}",
                },
                "defaultConfiguration": {
                    "level": _sarif_level(finding.severity),
                },
                "properties": {
                    "tags": ["security"],
                    "precision": "high" if finding.severity >= Severity.HIGH else "medium",
                },
            })

        results_list.append({
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _sarif_level(finding.severity),
            "message": {
                "text": f"{finding.title}: {finding.description}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "endLine": finding.end_line or finding.line_number,
                            "snippet": {"text": finding.snippet},
                        },
                    },
                }
            ],
            "fixes": [
                {
                    "description": {"text": finding.remediation},
                }
            ],
        })

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureCommit",
                        "informationUri": "https://github.com/joemunene/securecommit",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results_list,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: Severity) -> str:
    """Map Severity to SARIF level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    return mapping.get(severity, "warning")
