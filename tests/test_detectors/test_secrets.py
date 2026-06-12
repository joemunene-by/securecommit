"""Tests for the SecretDetector — 15 tests covering all secret patterns."""

from __future__ import annotations

import pytest

from securecommit.detectors.secrets import SecretDetector
from securecommit.models import Severity


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


class TestAWSKeys:
    def test_detects_aws_access_key(self, detector: SecretDetector, aws_key_snippet: str) -> None:
        findings = detector.scan(aws_key_snippet, "config.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "SC-S001"
        assert f.severity == Severity.CRITICAL
        assert f.line_number == 1
        assert "AKIA" in f.snippet

    def test_detects_aws_secret_key(
        self, detector: SecretDetector, aws_secret_snippet: str
    ) -> None:
        findings = detector.scan(aws_secret_snippet, "config.py")
        assert len(findings) >= 1
        assert any(f.rule_id == "SC-S002" for f in findings)

    def test_no_false_positive_on_partial_akia(self, detector: SecretDetector) -> None:
        # Only 10 chars after AKIA — not a full key
        findings = detector.scan('key = "AKIA1234567890"', "test.py")
        assert not any(f.rule_id == "SC-S001" for f in findings)


class TestGitTokens:
    def test_detects_github_token(
        self, detector: SecretDetector, github_token_snippet: str
    ) -> None:
        findings = detector.scan(github_token_snippet, "env.py")
        assert len(findings) >= 1
        match = [f for f in findings if f.rule_id == "SC-S005"]
        assert len(match) == 1
        assert match[0].severity == Severity.CRITICAL

    def test_detects_gitlab_token(
        self, detector: SecretDetector, gitlab_token_snippet: str
    ) -> None:
        findings = detector.scan(gitlab_token_snippet, "env.py")
        assert any(f.rule_id == "SC-S006" for f in findings)


class TestPrivateKeys:
    def test_detects_rsa_private_key(
        self, detector: SecretDetector, private_key_snippet: str
    ) -> None:
        findings = detector.scan(private_key_snippet, "key.pem")
        assert len(findings) >= 1
        assert findings[0].rule_id == "SC-S008"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_ec_private_key(self, detector: SecretDetector) -> None:
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = detector.scan(content, "key.pem")
        assert any(f.rule_id == "SC-S008" for f in findings)


class TestDatabaseStrings:
    def test_detects_postgres_url(
        self, detector: SecretDetector, db_connection_snippet: str
    ) -> None:
        findings = detector.scan(db_connection_snippet, "settings.py")
        assert any(f.rule_id == "SC-S009" for f in findings)

    def test_detects_mongodb_url(self, detector: SecretDetector) -> None:
        content = 'MONGO_URI = "mongodb+srv://user:pass@cluster.example.net/db"'
        findings = detector.scan(content, "config.py")
        assert any(f.rule_id == "SC-S009" for f in findings)

    def test_detects_redis_url(self, detector: SecretDetector) -> None:
        content = 'REDIS_URL = "redis://default:secret@redis.example.com:6379"'
        findings = detector.scan(content, "config.py")
        assert any(f.rule_id == "SC-S009" for f in findings)


class TestJWTTokens:
    def test_detects_jwt(self, detector: SecretDetector, jwt_snippet: str) -> None:
        findings = detector.scan(jwt_snippet, "auth.py")
        assert any(f.rule_id == "SC-S010" for f in findings)


class TestWebhooksAndKeys:
    def test_detects_slack_webhook(
        self, detector: SecretDetector, slack_webhook_snippet: str
    ) -> None:
        findings = detector.scan(slack_webhook_snippet, "notify.py")
        assert any(f.rule_id == "SC-S011" for f in findings)

    def test_detects_stripe_key(self, detector: SecretDetector, stripe_key_snippet: str) -> None:
        findings = detector.scan(stripe_key_snippet, "billing.py")
        assert any(f.rule_id == "SC-S012" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_sendgrid_key(
        self, detector: SecretDetector, sendgrid_key_snippet: str
    ) -> None:
        findings = detector.scan(sendgrid_key_snippet, "email.py")
        assert any(f.rule_id == "SC-S015" for f in findings)


class TestHighEntropy:
    def test_detects_generic_api_key(
        self, detector: SecretDetector, generic_api_key_snippet: str
    ) -> None:
        findings = detector.scan(generic_api_key_snippet, "app.py")
        # Should match generic API key pattern SC-S007
        assert any(f.rule_id == "SC-S007" for f in findings)


class TestFalsePositives:
    def test_ignores_securecommit_ignore_comment(self, detector: SecretDetector) -> None:
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # securecommit:ignore'
        findings = detector.scan(content, "test.py")
        assert len(findings) == 0

    def test_clean_code_produces_no_findings(self, detector: SecretDetector) -> None:
        content = """\
import os

DATABASE_URL = os.environ["DATABASE_URL"]
api_key = os.getenv("API_KEY")

def connect():
    pass
"""
        findings = detector.scan(content, "clean.py")
        assert len(findings) == 0


class TestFindingMetadata:
    def test_finding_has_line_number_and_snippet(
        self, detector: SecretDetector, aws_key_snippet: str
    ) -> None:
        findings = detector.scan(aws_key_snippet, "config.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.line_number == 1
        assert f.snippet != ""
        assert f.file_path == "config.py"
        assert f.remediation != ""
