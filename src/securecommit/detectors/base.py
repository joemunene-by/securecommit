"""Base detector abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod

from securecommit.models import Finding


class BaseDetector(ABC):
    """Abstract base class for all security detectors."""

    name: str = "base"

    @abstractmethod
    def scan(self, content: str, filename: str = "<unknown>") -> list[Finding]:
        """Scan content and return a list of findings.

        Args:
            content: The file content to scan.
            filename: The name/path of the file being scanned.

        Returns:
            A list of Finding objects for any issues detected.
        """
        ...

    def scan_line(self, line: str, line_number: int, filename: str) -> list[Finding]:
        """Scan a single line. Override for line-based detectors."""
        return []
