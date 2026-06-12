"""Security anti-pattern detection for code-level vulnerabilities."""

from __future__ import annotations

import re
from dataclasses import dataclass

from securecommit.detectors.base import BaseDetector
from securecommit.models import Finding, Severity


@dataclass(frozen=True)
class CodePattern:
    """A code-level security anti-pattern."""

    name: str
    rule_id: str
    regex: re.Pattern[str]
    severity: Severity
    description: str
    remediation: str
    languages: tuple[str, ...] = ("*",)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

CODE_PATTERNS: list[CodePattern] = [
    # SQL injection
    CodePattern(
        name="SQL Injection (f-string in query)",
        rule_id="SC-P001",
        regex=re.compile(
            r"""(?:execute|cursor\.execute|query|raw)\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\{"""
        ),
        severity=Severity.HIGH,
        description="Possible SQL injection via f-string formatting in a query.",
        remediation="Use parameterized queries (e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))).",
        languages=("py", "python"),
    ),
    CodePattern(
        name="SQL Injection (string concatenation with +)",
        rule_id="SC-P002",
        regex=re.compile(r"""(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\+\s*\w+"""),
        severity=Severity.HIGH,
        description="SQL query built via string concatenation with +.",
        remediation="Use parameterized queries or an ORM instead of string concatenation.",
    ),
    # XSS
    CodePattern(
        name="XSS via innerHTML",
        rule_id="SC-P003",
        regex=re.compile(r"""\.innerHTML\s*=\s*(?!['"]<[^>]+>['"]\s*;)"""),
        severity=Severity.HIGH,
        description="Direct assignment to innerHTML can lead to Cross-Site Scripting (XSS).",
        remediation="Use textContent, or sanitize input with a library like DOMPurify before assigning to innerHTML.",
        languages=("js", "ts", "jsx", "tsx"),
    ),
    CodePattern(
        name="XSS via dangerouslySetInnerHTML",
        rule_id="SC-P004",
        regex=re.compile(r"dangerouslySetInnerHTML"),
        severity=Severity.MEDIUM,
        description="Usage of dangerouslySetInnerHTML in React can lead to XSS if input is not sanitized.",
        remediation="Sanitize user input with DOMPurify before passing to dangerouslySetInnerHTML.",
        languages=("js", "ts", "jsx", "tsx"),
    ),
    # Command injection
    CodePattern(
        name="Command Injection via os.system",
        rule_id="SC-P005",
        regex=re.compile(r"\bos\.system\s*\("),
        severity=Severity.CRITICAL,
        description="os.system() executes commands in a shell and is vulnerable to command injection.",
        remediation="Use subprocess.run() with a list of arguments and shell=False (the default).",
        languages=("py", "python"),
    ),
    CodePattern(
        name="Command Injection via subprocess shell=True",
        rule_id="SC-P006",
        regex=re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
        severity=Severity.HIGH,
        description="Using shell=True in subprocess allows shell injection if input is not sanitized.",
        remediation="Pass a list of arguments to subprocess and avoid shell=True.",
        languages=("py", "python"),
    ),
    CodePattern(
        name="Command Injection via exec/eval",
        rule_id="SC-P007",
        regex=re.compile(r"\b(?:exec|eval)\s*\("),
        severity=Severity.HIGH,
        description="exec() or eval() can execute arbitrary code and should be avoided with untrusted input.",
        remediation="Avoid exec/eval. Use ast.literal_eval for safe parsing of literals.",
        languages=("py", "python"),
    ),
    # Insecure deserialization
    CodePattern(
        name="Insecure Deserialization (pickle)",
        rule_id="SC-P008",
        regex=re.compile(r"\bpickle\.loads?\s*\("),
        severity=Severity.CRITICAL,
        description="pickle.load/loads can execute arbitrary code during deserialization.",
        remediation="Use JSON or a safe serialization format. Never unpickle untrusted data.",
        languages=("py", "python"),
    ),
    CodePattern(
        name="Insecure YAML Loading",
        rule_id="SC-P009",
        regex=re.compile(r"\byaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)"),
        severity=Severity.HIGH,
        description="yaml.load() without SafeLoader can execute arbitrary Python objects.",
        remediation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
        languages=("py", "python"),
    ),
    # Hardcoded credentials
    CodePattern(
        name="Hardcoded Password",
        rule_id="SC-P010",
        regex=re.compile(
            r"""(?i)(?:password|passwd|pwd|secret_key|secret)\s*=\s*['"][^'"]{4,}['"]"""
        ),
        severity=Severity.HIGH,
        description="A password or secret appears to be hardcoded in source code.",
        remediation="Use environment variables or a secrets manager for credentials.",
    ),
    # Insecure crypto
    CodePattern(
        name="Insecure Hash (MD5)",
        rule_id="SC-P011",
        regex=re.compile(r"\b(?:hashlib\.md5|MD5\.new|md5\s*\()\b"),
        severity=Severity.MEDIUM,
        description="MD5 is cryptographically broken and should not be used for security purposes.",
        remediation="Use SHA-256 or better. For passwords, use bcrypt, scrypt, or argon2.",
    ),
    CodePattern(
        name="Insecure Hash (SHA1 for passwords)",
        rule_id="SC-P012",
        regex=re.compile(r"(?i)\b(?:hashlib\.sha1|SHA1\.new)\b"),
        severity=Severity.MEDIUM,
        description="SHA-1 is deprecated for cryptographic use.",
        remediation="Use SHA-256 or better. For passwords, use bcrypt, scrypt, or argon2.",
    ),
    CodePattern(
        name="ECB Mode Usage",
        rule_id="SC-P013",
        regex=re.compile(r"(?i)\bECB\b|MODE_ECB"),
        severity=Severity.HIGH,
        description="ECB mode does not provide semantic security and leaks patterns in ciphertext.",
        remediation="Use AES-GCM or AES-CBC with proper IV handling.",
    ),
    # Path traversal
    CodePattern(
        name="Path Traversal",
        rule_id="SC-P014",
        regex=re.compile(r"""open\s*\([^)]*(?:request\.|input\(|argv|args\.|params\[)"""),
        severity=Severity.HIGH,
        description="File open with user-controlled input may allow path traversal attacks.",
        remediation="Validate and sanitize file paths. Use os.path.realpath() and check against an allowed base directory.",
        languages=("py", "python"),
    ),
    # SSRF
    CodePattern(
        name="SSRF Indicator",
        rule_id="SC-P015",
        regex=re.compile(
            r"""(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\([^)]*(?:request\.|input\(|argv|args\.|params\[|user)"""
        ),
        severity=Severity.HIGH,
        description="HTTP request with potentially user-controlled URL may allow Server-Side Request Forgery.",
        remediation="Validate and restrict URLs to allowed domains/IPs. Block internal/private IP ranges.",
        languages=("py", "python"),
    ),
    # Disabled TLS verification
    CodePattern(
        name="TLS Verification Disabled",
        rule_id="SC-P016",
        regex=re.compile(r"""verify\s*=\s*False"""),
        severity=Severity.MEDIUM,
        description="TLS certificate verification is disabled, enabling man-in-the-middle attacks.",
        remediation="Set verify=True (the default) and ensure proper CA certificates are installed.",
    ),
]


class SecurityPatternDetector(BaseDetector):
    """Detect code-level security anti-patterns."""

    name = "patterns"

    def __init__(self, extra_patterns: list[CodePattern] | None = None) -> None:
        self.patterns = list(CODE_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)

    def scan(self, content: str, filename: str = "<unknown>") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            if "securecommit:ignore" in line:
                continue
            for cp in self.patterns:
                if cp.regex.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            rule_id=cp.rule_id,
                            title=cp.name,
                            description=cp.description,
                            severity=cp.severity,
                            file_path=filename,
                            line_number=line_num,
                            snippet=line.strip(),
                            remediation=cp.remediation,
                        )
                    )
        return findings
