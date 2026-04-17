"""Allowlist manager for suppressing known false positives."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

ALLOWLIST_FILENAME = ".securecommit-allowlist"
INLINE_IGNORE = "securecommit:ignore"


class AllowlistManager:
    """Manage allowlisted findings and files."""

    def __init__(self, allowlist_file: Path | None = None) -> None:
        self._file_patterns: list[str] = []
        self._rule_suppressions: list[str] = []
        self._hash_allowlist: set[str] = set()
        if allowlist_file and allowlist_file.exists():
            self._load(allowlist_file)

    def _load(self, path: Path) -> None:
        """Load allowlist entries from file.

        Format (one entry per line):
            # comment
            file:test_*.py
            rule:SC-S001
            hash:<sha256 of snippet>
        """
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("file:"):
                    self._file_patterns.append(line[5:].strip())
                elif line.startswith("rule:"):
                    self._rule_suppressions.append(line[5:].strip())
                elif line.startswith("hash:"):
                    self._hash_allowlist.add(line[5:].strip())

    def is_line_ignored(self, line: str) -> bool:
        """Check if a source line has an inline ignore comment."""
        return INLINE_IGNORE in line

    def is_file_allowlisted(self, filepath: str) -> bool:
        """Check if a file matches any allowlist file pattern."""
        name = Path(filepath).name
        return any(
            fnmatch(name, pat) or fnmatch(filepath, pat)
            for pat in self._file_patterns
        )

    def is_rule_suppressed(self, rule_id: str) -> bool:
        """Check if a rule ID is globally suppressed."""
        return rule_id in self._rule_suppressions

    def is_hash_allowed(self, snippet_hash: str) -> bool:
        """Check if a specific finding hash is allowlisted."""
        return snippet_hash in self._hash_allowlist

    @classmethod
    def find_and_load(cls, start_dir: Path | None = None) -> AllowlistManager:
        """Walk up directories to find a .securecommit-allowlist file."""
        if start_dir is None:
            start_dir = Path.cwd()
        for parent in [start_dir, *start_dir.parents]:
            candidate = parent / ALLOWLIST_FILENAME
            if candidate.exists():
                return cls(allowlist_file=candidate)
        return cls()
