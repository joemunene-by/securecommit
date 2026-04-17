"""Integration tests for the Scanner orchestrator."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from securecommit.config import Config
from securecommit.formatter import format_json, format_markdown, format_sarif
from securecommit.models import Severity
from securecommit.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    config = Config(
        severity_threshold=Severity.HIGH,
        detectors_secrets=True,
        detectors_patterns=True,
        detectors_entropy=True,
    )
    return Scanner(config=config)


@pytest.fixture
def scanner_low_threshold() -> Scanner:
    config = Config(severity_threshold=Severity.LOW)
    return Scanner(config=config)


class TestScanText:
    def test_scan_vulnerable_text(
        self, scanner: Scanner, vulnerable_file_content: str
    ) -> None:
        result = scanner.scan_text(vulnerable_file_content, "vuln.py")
        assert result.stats.findings_total > 0
        assert result.stats.files_scanned == 1
        assert not result.passed  # should fail with HIGH+ findings

    def test_clean_text_passes(self, scanner: Scanner) -> None:
        content = textwrap.dedent("""\
            import os

            name = os.environ.get("NAME", "world")
            print(f"Hello, {name}!")
        """)
        result = scanner.scan_text(content, "clean.py")
        assert result.stats.findings_total == 0
        assert result.passed

    def test_findings_have_metadata(
        self, scanner: Scanner, vulnerable_file_content: str
    ) -> None:
        result = scanner.scan_text(vulnerable_file_content, "vuln.py")
        for f in result.findings:
            assert f.line_number > 0
            assert f.snippet != ""
            assert f.remediation != ""
            assert f.detector in ("secrets", "patterns", "entropy")
            assert f.file_path == "vuln.py"


class TestScanFile:
    def test_scan_example_file(self, scanner: Scanner, tmp_path: Path) -> None:
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'password = "hunter2"\n'
        )
        result = scanner.scan_file(vuln_file)
        assert result.stats.findings_total >= 2
        assert not result.passed

    def test_skip_binary_file(self, scanner: Scanner, tmp_path: Path) -> None:
        bin_file = tmp_path / "image.png"
        bin_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = scanner.scan_file(bin_file)
        assert result.stats.files_scanned == 0


class TestScanDirectory:
    def test_scan_directory_finds_issues(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text('password = "secret123"\n')
        (tmp_path / "config.py").write_text(
            'DB = "postgres://admin:pass@localhost/db"\n'
        )
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = scanner.scan_directory(tmp_path)
        assert result.stats.files_scanned == 3
        assert result.stats.findings_total >= 2

    def test_excludes_dirs(self, scanner: Scanner, tmp_path: Path) -> None:
        node_dir = tmp_path / "node_modules"
        node_dir.mkdir()
        (node_dir / "bad.py").write_text('password = "leaked"\n')
        result = scanner.scan_directory(tmp_path)
        # node_modules should be excluded
        assert result.stats.files_scanned == 0


class TestScanDiff:
    def test_scan_diff_detects_added_secret(self, scanner: Scanner) -> None:
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -1,3 +1,5 @@
             import os
            +AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
            +password = "hunter2"

             def main():
        """)
        result = scanner.scan_diff(diff)
        assert result.stats.findings_total >= 1

    def test_diff_ignores_removed_lines(self, scanner: Scanner) -> None:
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -1,3 +1,2 @@
             import os
            -AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

        """)
        result = scanner.scan_diff(diff)
        # Removed lines should NOT trigger findings
        aws_findings = [f for f in result.findings if f.rule_id == "SC-S001"]
        assert len(aws_findings) == 0


class TestScanResult:
    def test_severity_evaluation(self, scanner: Scanner) -> None:
        content = 'password = "test123"'
        result = scanner.scan_text(content, "test.py")
        # With HIGH threshold, hardcoded password (HIGH) should block
        assert not result.passed

    def test_low_severity_passes_high_threshold(self, scanner: Scanner) -> None:
        # TLS verify=False is MEDIUM, should pass HIGH threshold
        content = "requests.get(url, verify=False)"
        result = scanner.scan_text(content, "http.py")
        assert result.passed  # MEDIUM < HIGH threshold


class TestOutputFormats:
    def test_json_output(self, scanner: Scanner, vulnerable_file_content: str) -> None:
        result = scanner.scan_text(vulnerable_file_content, "vuln.py")
        output = format_json(result)
        data = json.loads(output)
        assert "findings" in data
        assert "stats" in data
        assert isinstance(data["findings"], list)

    def test_sarif_output_valid(
        self, scanner: Scanner, vulnerable_file_content: str
    ) -> None:
        result = scanner.scan_text(vulnerable_file_content, "vuln.py")
        output = format_sarif(result)
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecureCommit"
        assert len(run["results"]) > 0
        # Validate each result has required SARIF fields
        for r in run["results"]:
            assert "ruleId" in r
            assert "level" in r
            assert "message" in r
            assert "locations" in r
            loc = r["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "region" in loc
            assert loc["region"]["startLine"] > 0

    def test_markdown_output(
        self, scanner: Scanner, vulnerable_file_content: str
    ) -> None:
        result = scanner.scan_text(vulnerable_file_content, "vuln.py")
        output = format_markdown(result)
        assert "## SecureCommit Scan" in output
        assert "finding(s)" in output

    def test_markdown_clean(self, scanner: Scanner) -> None:
        result = scanner.scan_text("x = 1\n", "clean.py")
        output = format_markdown(result)
        assert "No security issues found" in output


class TestCustomPatterns:
    def test_custom_pattern_detection(self) -> None:
        from securecommit.config import CustomPattern

        config = Config(
            custom_patterns=[
                CustomPattern(
                    name="internal_token",
                    pattern="INTERNAL_[A-Z0-9]{32}",
                    severity=Severity.CRITICAL,
                    description="Internal token found",
                )
            ]
        )
        scanner = Scanner(config=config)
        content = 'TOKEN = "INTERNAL_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"'
        result = scanner.scan_text(content, "app.py")
        assert any("internal_token" in f.title.lower() or "custom" in f.rule_id.lower()
                    for f in result.findings)
