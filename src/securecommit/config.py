"""Configuration management for SecureCommit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from securecommit.models import Severity

DEFAULT_CONFIG_FILENAME = ".securecommit.yaml"


@dataclass
class CustomPattern:
    """A user-defined pattern rule."""

    name: str
    pattern: str
    severity: Severity = Severity.HIGH
    description: str = ""


@dataclass
class Config:
    """SecureCommit configuration."""

    severity_threshold: Severity = Severity.HIGH
    detectors_secrets: bool = True
    detectors_patterns: bool = True
    detectors_entropy: bool = True
    allowlist_patterns: list[str] = field(default_factory=list)
    custom_patterns: list[CustomPattern] = field(default_factory=list)
    max_file_size_kb: int = 500
    entropy_threshold: float = 4.5
    exclude_dirs: list[str] = field(
        default_factory=lambda: [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            "dist",
            "build",
        ]
    )

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load configuration from a YAML file."""
        if path is None:
            path = _find_config_file()
        if path is None or not path.exists():
            return cls()
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Config:
        cfg = cls()
        if "severity_threshold" in data:
            cfg.severity_threshold = Severity(data["severity_threshold"].lower())
        detectors = data.get("detectors", {})
        if isinstance(detectors, dict):
            cfg.detectors_secrets = detectors.get("secrets", True)
            cfg.detectors_patterns = detectors.get("patterns", True)
            cfg.detectors_entropy = detectors.get("entropy", True)
        cfg.allowlist_patterns = data.get("allowlist", [])
        for cp in data.get("custom_patterns", []):
            cfg.custom_patterns.append(
                CustomPattern(
                    name=cp["name"],
                    pattern=cp["pattern"],
                    severity=Severity(cp.get("severity", "high").lower()),
                    description=cp.get("description", ""),
                )
            )
        if "max_file_size_kb" in data:
            cfg.max_file_size_kb = int(data["max_file_size_kb"])
        if "entropy_threshold" in data:
            cfg.entropy_threshold = float(data["entropy_threshold"])
        if "exclude_dirs" in data:
            cfg.exclude_dirs = data["exclude_dirs"]
        return cfg

    def is_file_allowlisted(self, filepath: str) -> bool:
        """Check if a file matches any allowlist pattern."""
        from fnmatch import fnmatch

        filename = Path(filepath).name
        for pattern in self.allowlist_patterns:
            if fnmatch(filename, pattern) or fnmatch(filepath, pattern):
                return True
        return False

    def is_dir_excluded(self, dirpath: str) -> bool:
        """Check if a directory should be excluded."""
        parts = Path(dirpath).parts
        return any(excl in parts for excl in self.exclude_dirs)


def _find_config_file() -> Path | None:
    """Walk up from cwd to find a .securecommit.yaml."""
    current = Path.cwd()
    for parent in [current, *current.parents]:
        candidate = parent / DEFAULT_CONFIG_FILENAME
        if candidate.exists():
            return candidate
    return None
