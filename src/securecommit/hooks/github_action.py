"""GitHub Action logic: fetch PR diff, scan, and post review comments."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from securecommit.config import Config
from securecommit.formatter import format_markdown, format_sarif
from securecommit.scanner import Scanner


def get_pr_diff() -> str | None:
    """Get PR diff using GitHub event data and git."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).exists():
        return None

    with open(event_path) as f:
        event = json.load(f)

    base_ref = event.get("pull_request", {}).get("base", {}).get("sha")
    head_ref = event.get("pull_request", {}).get("head", {}).get("sha")

    if not base_ref or not head_ref:
        return None

    try:
        # Fetch the base so the diff works in shallow clones
        subprocess.run(
            ["git", "fetch", "origin", base_ref],
            capture_output=True,
            check=False,
        )
        result = subprocess.run(
            ["git", "diff", base_ref, head_ref],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def post_pr_comment(body: str) -> None:
    """Post a comment on the PR using the GitHub API via gh CLI."""
    pr_number = os.environ.get("PR_NUMBER")
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")

    if not all([pr_number, repo, token]):
        print("Missing PR_NUMBER, GITHUB_REPOSITORY, or GITHUB_TOKEN.", file=sys.stderr)
        return

    try:
        subprocess.run(
            [
                "gh",
                "pr",
                "comment",
                pr_number,
                "--repo",
                repo,
                "--body",
                body,
            ],
            check=True,
            env={**os.environ, "GH_TOKEN": token},
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Failed to post PR comment: {e}", file=sys.stderr)


def run_github_action(
    config_path: Path | None = None,
    sarif_output: Path | None = None,
) -> bool:
    """Main entry point for the GitHub Action.

    Returns True if passed, False if failed.
    """
    config = Config.load(config_path)
    scanner = Scanner(config=config)

    diff_text = get_pr_diff()
    if diff_text is None:
        # Fallback: scan the workspace
        workspace = os.environ.get("GITHUB_WORKSPACE", ".")
        result = scanner.scan_directory(workspace)
    else:
        result = scanner.scan_diff(diff_text)

    # Write SARIF for code scanning
    if sarif_output:
        sarif_output.write_text(format_sarif(result))
        print(f"SARIF output written to {sarif_output}")

    # Post markdown comment on the PR
    if result.findings:
        md = format_markdown(result)
        post_pr_comment(md)

    # Set GitHub Action output
    _set_action_output("findings_count", str(result.stats.findings_total))
    _set_action_output("passed", str(result.passed).lower())

    if not result.passed:
        print(
            f"SecureCommit: {result.stats.findings_total} issue(s) found. "
            "See PR comment for details.",
            file=sys.stderr,
        )
    else:
        print("SecureCommit: scan passed.")

    return result.passed


def _set_action_output(name: str, value: str) -> None:
    """Set a GitHub Action output variable."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
