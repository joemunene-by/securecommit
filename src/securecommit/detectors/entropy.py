"""Shannon entropy calculator for detecting high-entropy strings (likely secrets)."""

from __future__ import annotations

import math
import re
import string

from securecommit.detectors.base import BaseDetector
from securecommit.models import Finding, Severity

# Minimum length for a string to be considered for entropy analysis
MIN_TOKEN_LENGTH = 16
# Maximum length to avoid scanning huge blobs
MAX_TOKEN_LENGTH = 256

# Characters typical in secrets/tokens
SECRET_CHARSET = string.ascii_letters + string.digits + "+/=-_"

# Regex to extract candidate tokens: quoted strings and assignments
TOKEN_PATTERNS = [
    re.compile(r"""['"]([A-Za-z0-9+/=\-_]{16,256})['"]"""),
    re.compile(r"""=\s*['"]?([A-Za-z0-9+/=\-_]{16,256})['"]?"""),
]

# Context keywords that raise suspicion
CONTEXT_KEYWORDS = [
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "api_key",
    "apikey",
    "auth",
    "private",
    "access_key",
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy (>4.5) often indicates random/secret data.
    English text typically has entropy around 3.5-4.0.
    Random base64 strings have entropy around 5.5-6.0.
    """
    if not data:
        return 0.0
    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def has_context_keyword(line: str) -> bool:
    """Check if a line contains keywords suggesting a secret assignment."""
    lower = line.lower()
    return any(kw in lower for kw in CONTEXT_KEYWORDS)


class EntropyDetector(BaseDetector):
    """Detect high-entropy strings that may be secrets."""

    name = "entropy"

    def __init__(self, threshold: float = 4.5) -> None:
        self.threshold = threshold

    def scan(self, content: str, filename: str = "<unknown>") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            if _is_ignore_commented(line):
                continue
            for pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    token = match.group(1)
                    if len(token) < MIN_TOKEN_LENGTH or len(token) > MAX_TOKEN_LENGTH:
                        continue
                    ent = shannon_entropy(token)
                    if ent >= self.threshold and has_context_keyword(line):
                        findings.append(
                            Finding(
                                detector=self.name,
                                rule_id="SC-E001",
                                title="High-entropy string detected",
                                description=(
                                    f"A string with Shannon entropy {ent:.2f} "
                                    f"(threshold {self.threshold}) was found near a "
                                    f"secret-related keyword. This may be a hardcoded secret."
                                ),
                                severity=Severity.HIGH,
                                file_path=filename,
                                line_number=line_num,
                                snippet=line.strip(),
                                remediation=(
                                    "Move this value to an environment variable or a "
                                    "secrets manager. Never commit secrets to source control."
                                ),
                                metadata={"entropy": round(ent, 2), "token_length": len(token)},
                            )
                        )
        return findings


def _is_ignore_commented(line: str) -> bool:
    """Check for securecommit:ignore inline comment."""
    return "securecommit:ignore" in line
