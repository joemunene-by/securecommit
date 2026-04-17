"""Typer CLI for SecureCommit."""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from securecommit.config import Config
from securecommit.formatter import format_console, format_json, format_markdown, format_sarif
from securecommit.models import ScanResult, Severity
from securecommit.scanner import Scanner

app = typer.Typer(
    name="securecommit",
    help="Pre-commit security hooks and code review tool.",
    add_completion=False,
)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


def _output(result: ScanResult, fmt: OutputFormat) -> str:
    match fmt:
        case OutputFormat.console:
            return format_console(result)
        case OutputFormat.json:
            return format_json(result)
        case OutputFormat.sarif:
            return format_sarif(result)
        case OutputFormat.markdown:
            return format_markdown(result)


@app.command()
def scan(
    path: Path = typer.Argument(
        ..., help="File or directory to scan.", exists=True,
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to .securecommit.yaml config file.",
    ),
    fmt: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="Output format.",
    ),
    severity: str = typer.Option(
        "high", "--severity", "-s",
        help="Minimum severity to report (info, low, medium, high, critical).",
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file instead of stdout.",
    ),
) -> None:
    """Scan a file or directory for security issues."""
    cfg = Config.load(config)
    cfg.severity_threshold = Severity(severity.lower())
    scanner = Scanner(config=cfg)

    if path.is_file():
        result = scanner.scan_file(path)
    else:
        result = scanner.scan_directory(path)

    text = _output(result, fmt)
    if output_file:
        output_file.write_text(text)
        typer.echo(f"Results written to {output_file}")
    else:
        typer.echo(text)

    if not result.passed:
        raise typer.Exit(code=1)


@app.command()
def hook() -> None:
    """Run as a pre-commit hook (scans staged files)."""
    from securecommit.hooks.pre_commit import run_pre_commit_hook

    passed = run_pre_commit_hook()
    if not passed:
        raise typer.Exit(code=1)


@app.command()
def review(
    diff_file: Optional[Path] = typer.Option(
        None, "--diff", "-d",
        help="Path to a diff file. If omitted, reads from stdin.",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to .securecommit.yaml config file.",
    ),
    fmt: OutputFormat = typer.Option(
        OutputFormat.markdown, "--format", "-f", help="Output format.",
    ),
) -> None:
    """Review a diff for security issues (for CI/GitHub Action use)."""
    if diff_file:
        diff_text = diff_file.read_text()
    else:
        diff_text = sys.stdin.read()

    cfg = Config.load(config)
    scanner = Scanner(config=cfg)
    result = scanner.scan_diff(diff_text)

    text = _output(result, fmt)
    typer.echo(text)

    if not result.passed:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show the SecureCommit version."""
    from securecommit import __version__

    typer.echo(f"securecommit {__version__}")
