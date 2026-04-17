"""Scanner orchestrator — runs all detectors and aggregates findings."""

from __future__ import annotations

import os
import re
from pathlib import Path

from securecommit.config import Config
from securecommit.detectors.allowlist import AllowlistManager
from securecommit.detectors.base import BaseDetector
from securecommit.detectors.entropy import EntropyDetector
from securecommit.detectors.patterns import SecurityPatternDetector
from securecommit.detectors.secrets import SecretDetector, SecretPattern
from securecommit.models import Finding, ScanResult, Severity

# Binary / large file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".sqlite", ".db",
}


class Scanner:
    """Orchestrate security scanning across files and directories."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.load()
        self.detectors: list[BaseDetector] = self._build_detectors()
        self.allowlist = AllowlistManager.find_and_load()

    def _build_detectors(self) -> list[BaseDetector]:
        detectors: list[BaseDetector] = []
        if self.config.detectors_secrets:
            extra: list[SecretPattern] = []
            for cp in self.config.custom_patterns:
                extra.append(
                    SecretPattern(
                        name=cp.name,
                        rule_id=f"SC-C{len(extra)+1:03d}",
                        regex=re.compile(cp.pattern),
                        severity=cp.severity,
                        description=cp.description or f"Custom pattern: {cp.name}",
                        remediation="Review and remediate according to your organization's policy.",
                    )
                )
            detectors.append(SecretDetector(extra_patterns=extra if extra else None))
        if self.config.detectors_patterns:
            detectors.append(SecurityPatternDetector())
        if self.config.detectors_entropy:
            detectors.append(EntropyDetector(threshold=self.config.entropy_threshold))
        return detectors

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_text(self, content: str, filename: str = "<unknown>") -> ScanResult:
        """Scan a single text blob."""
        result = ScanResult()
        for detector in self.detectors:
            for finding in detector.scan(content, filename):
                if not self._is_suppressed(finding):
                    result.add_finding(finding)
        result.stats.files_scanned = 1
        result.stats.detectors_run = [d.name for d in self.detectors]
        result.evaluate(self.config.severity_threshold)
        return result

    def scan_file(self, filepath: str | Path) -> ScanResult:
        """Scan a single file."""
        filepath = Path(filepath)
        result = ScanResult()
        if not self._should_scan(filepath):
            return result
        try:
            content = filepath.read_text(errors="replace")
        except (OSError, PermissionError):
            return result
        for detector in self.detectors:
            for finding in detector.scan(content, str(filepath)):
                if not self._is_suppressed(finding):
                    result.add_finding(finding)
        result.stats.files_scanned = 1
        result.stats.detectors_run = [d.name for d in self.detectors]
        result.evaluate(self.config.severity_threshold)
        return result

    def scan_directory(self, directory: str | Path) -> ScanResult:
        """Recursively scan a directory."""
        directory = Path(directory)
        result = ScanResult()
        result.stats.detectors_run = [d.name for d in self.detectors]

        for root, dirs, files in os.walk(directory):
            root_path = Path(root)
            # Prune excluded directories (in-place)
            dirs[:] = [
                d for d in dirs
                if not self.config.is_dir_excluded(str(root_path / d))
            ]
            for fname in files:
                fpath = root_path / fname
                if not self._should_scan(fpath):
                    continue
                try:
                    content = fpath.read_text(errors="replace")
                except (OSError, PermissionError):
                    continue
                result.stats.files_scanned += 1
                for detector in self.detectors:
                    for finding in detector.scan(content, str(fpath)):
                        if not self._is_suppressed(finding):
                            result.add_finding(finding)

        result.evaluate(self.config.severity_threshold)
        return result

    def scan_diff(self, diff_text: str) -> ScanResult:
        """Scan a unified diff (e.g., from git diff or PR diff).

        Only added lines (starting with +) are checked.
        """
        result = ScanResult()
        result.stats.detectors_run = [d.name for d in self.detectors]

        current_file: str = "<unknown>"
        line_number = 0

        for raw_line in diff_text.splitlines():
            # Track file header
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:]
                continue
            if raw_line.startswith("@@ "):
                # Parse hunk header for line number
                m = re.search(r"\+(\d+)", raw_line)
                if m:
                    line_number = int(m.group(1)) - 1
                continue
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                line_number += 1
                added_line = raw_line[1:]
                for detector in self.detectors:
                    for finding in detector.scan(added_line, current_file):
                        finding.line_number = line_number
                        if not self._is_suppressed(finding):
                            result.add_finding(finding)
            elif not raw_line.startswith("-"):
                line_number += 1

        result.stats.files_scanned = 1  # diff counted as one unit
        result.evaluate(self.config.severity_threshold)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_scan(self, filepath: Path) -> bool:
        """Decide whether to scan a file."""
        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            return False
        if self.config.is_file_allowlisted(str(filepath)):
            return False
        try:
            size_kb = filepath.stat().st_size / 1024
            if size_kb > self.config.max_file_size_kb:
                return False
        except OSError:
            return False
        return True

    def _is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding should be suppressed via allowlist."""
        if self.allowlist.is_rule_suppressed(finding.rule_id):
            return True
        if self.allowlist.is_line_ignored(finding.snippet):
            return True
        return False
