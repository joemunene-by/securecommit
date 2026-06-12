"""Secret detection via regex and entropy analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass

from securecommit.detectors.base import BaseDetector
from securecommit.models import Finding, Severity


@dataclass(frozen=True)
class SecretPattern:
    """A single secret-matching pattern."""

    name: str
    rule_id: str
    regex: re.Pattern[str]
    severity: Severity
    description: str
    remediation: str


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern(
        name="AWS Access Key ID",
        rule_id="SC-S001",
        regex=re.compile(r"(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"),
        severity=Severity.CRITICAL,
        description="AWS Access Key IDs begin with 'AKIA' followed by 16 alphanumeric characters.",
        remediation="Rotate the key immediately via the AWS IAM console and use environment variables or AWS Secrets Manager.",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        rule_id="SC-S002",
        regex=re.compile(
            r"""(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        severity=Severity.CRITICAL,
        description="AWS Secret Access Keys are 40-character base64 strings.",
        remediation="Rotate the key immediately and store it in a secrets manager.",
    ),
    # GCP
    SecretPattern(
        name="GCP Service Account Key",
        rule_id="SC-S003",
        regex=re.compile(r'"type"\s*:\s*"service_account"'),
        severity=Severity.CRITICAL,
        description="GCP service account JSON key file detected.",
        remediation="Remove the key file from the repository and use Workload Identity or environment-based credentials.",
    ),
    # Azure
    SecretPattern(
        name="Azure Secret / Connection String",
        rule_id="SC-S004",
        regex=re.compile(
            r"""(?i)(?:AccountKey|SharedAccessKey|client_secret)\s*[=:]\s*["']?([A-Za-z0-9+/=]{32,})["']?"""
        ),
        severity=Severity.HIGH,
        description="Azure shared access key or client secret detected.",
        remediation="Rotate the secret and use Azure Key Vault for storage.",
    ),
    # GitHub token
    SecretPattern(
        name="GitHub Personal Access Token",
        rule_id="SC-S005",
        regex=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Tokens start with 'ghp_'.",
        remediation="Revoke the token at https://github.com/settings/tokens and use fine-grained tokens scoped to specific repos.",
    ),
    # GitLab token
    SecretPattern(
        name="GitLab Personal Access Token",
        rule_id="SC-S006",
        regex=re.compile(r"\b(glpat-[A-Za-z0-9\-]{20,})\b"),
        severity=Severity.CRITICAL,
        description="GitLab Personal Access Tokens start with 'glpat-'.",
        remediation="Revoke the token in GitLab settings and use project/group tokens with minimal scope.",
    ),
    # Generic API key
    SecretPattern(
        name="Generic API Key Assignment",
        rule_id="SC-S007",
        regex=re.compile(
            r"""(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*['"]([A-Za-z0-9+/=\-_]{16,})['"]"""
        ),
        severity=Severity.HIGH,
        description="A value assigned to an API key/token/secret variable was detected.",
        remediation="Move the value to an environment variable or secrets manager.",
    ),
    # Private keys
    SecretPattern(
        name="Private Key",
        rule_id="SC-S008",
        regex=re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="A PEM-encoded private key was found in the source.",
        remediation="Remove the key, generate a new one, and store it in a secure vault.",
    ),
    # Database connection strings
    SecretPattern(
        name="Database Connection String",
        rule_id="SC-S009",
        regex=re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]{8,}"),
        severity=Severity.HIGH,
        description="A database connection string with potential credentials was detected.",
        remediation="Use environment variables for connection strings. Never embed credentials in code.",
    ),
    # JWT tokens
    SecretPattern(
        name="JWT Token",
        rule_id="SC-S010",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.MEDIUM,
        description="A JSON Web Token was detected. JWTs may contain sensitive claims.",
        remediation="Do not hardcode JWTs. Generate them at runtime and transmit securely.",
    ),
    # Slack webhook
    SecretPattern(
        name="Slack Webhook URL",
        rule_id="SC-S011",
        regex=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        severity=Severity.HIGH,
        description="A Slack incoming webhook URL was detected.",
        remediation="Rotate the webhook in Slack settings and use environment variables.",
    ),
    # Stripe keys
    SecretPattern(
        name="Stripe Secret Key",
        rule_id="SC-S012",
        regex=re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"),
        severity=Severity.CRITICAL,
        description="Stripe live secret key detected.",
        remediation="Rotate the key in the Stripe dashboard and use restricted keys where possible.",
    ),
    SecretPattern(
        name="Stripe Publishable Key (Live)",
        rule_id="SC-S013",
        regex=re.compile(r"\b(pk_live_[A-Za-z0-9]{24,})\b"),
        severity=Severity.LOW,
        description="Stripe live publishable key detected (lower risk but should not be in code).",
        remediation="Load the key from environment configuration.",
    ),
    # Twilio
    SecretPattern(
        name="Twilio Auth Token",
        rule_id="SC-S014",
        regex=re.compile(r"""(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*['"]([a-f0-9]{32})['"]"""),
        severity=Severity.HIGH,
        description="Twilio authentication token detected.",
        remediation="Rotate the token in the Twilio console and use environment variables.",
    ),
    # SendGrid
    SecretPattern(
        name="SendGrid API Key",
        rule_id="SC-S015",
        regex=re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
        severity=Severity.HIGH,
        description="SendGrid API key detected.",
        remediation="Rotate the key in the SendGrid dashboard and use environment variables.",
    ),
    # Password in URL
    SecretPattern(
        name="Password in URL",
        rule_id="SC-S016",
        regex=re.compile(r"://[^/\s:]+:[^/\s@]+@[^/\s]+"),
        severity=Severity.HIGH,
        description="Credentials embedded in a URL were detected.",
        remediation="Remove credentials from URLs and use environment-based authentication.",
    ),
]


class SecretDetector(BaseDetector):
    """Detect secrets, API keys, and credentials via pattern matching."""

    name = "secrets"

    def __init__(self, extra_patterns: list[SecretPattern] | None = None) -> None:
        self.patterns = list(SECRET_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)

    def scan(self, content: str, filename: str = "<unknown>") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            if "securecommit:ignore" in line:
                continue
            for sp in self.patterns:
                match = sp.regex.search(line)
                if match:
                    findings.append(
                        Finding(
                            detector=self.name,
                            rule_id=sp.rule_id,
                            title=sp.name,
                            description=sp.description,
                            severity=sp.severity,
                            file_path=filename,
                            line_number=line_num,
                            snippet=line.strip(),
                            remediation=sp.remediation,
                            metadata={"matched": match.group(0)[:60]},
                        )
                    )
        return findings
