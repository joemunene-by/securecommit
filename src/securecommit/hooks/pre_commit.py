"""Pre-commit hook entry point: scans staged files and blocks on HIGH/CRITICAL."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from securecommit.config import Config
from securecommit.formatter import format_console
from securecommit.models import ScanResult
from securecommit.scanner import Scanner


def get_staged_files() -> list[str]:
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def get_staged_content(filepath: str) -> str | None:
    """Get the staged (index) version of a file."""
    try:
        result = subprocess.run(
            ["git", "show", f":{filepath}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def run_pre_commit_hook(config_path: Path | None = None) -> bool:
    """Run the pre-commit hook. Returns True if passed, False if blocked.

    Scans staged files and blocks the commit if any HIGH or CRITICAL
    findings are detected.
    """
    config = Config.load(config_path)
    scanner = Scanner(config=config)

    staged_files = get_staged_files()
    if not staged_files:
        return True

    combined = ScanResult()
    combined.stats.detectors_run = [d.name for d in scanner.detectors]

    for filepath in staged_files:
        if config.is_file_allowlisted(filepath):
            continue

        content = get_staged_content(filepath)
        if content is None:
            continue

        file_result = scanner.scan_text(content, filename=filepath)
        combined.stats.files_scanned += 1
        for finding in file_result.findings:
            combined.add_finding(finding)

    combined.evaluate(config.severity_threshold)

    if combined.findings:
        output = format_console(combined)
        print(output, file=sys.stderr)

    if not combined.passed:
        print(
            "\nCommit blocked by SecureCommit. "
            "Fix the issues above or use 'git commit --no-verify' to bypass.",
            file=sys.stderr,
        )
        return False

    if not combined.findings:
        print("SecureCommit: all clear.", file=sys.stderr)
    return True
