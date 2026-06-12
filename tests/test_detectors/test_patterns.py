"""Tests for SecurityPatternDetector — 14 tests covering code anti-patterns."""

from __future__ import annotations

import pytest

from securecommit.detectors.patterns import SecurityPatternDetector
from securecommit.models import Severity


@pytest.fixture
def detector() -> SecurityPatternDetector:
    return SecurityPatternDetector()


class TestSQLInjection:
    def test_detects_string_concat_sql(
        self, detector: SecurityPatternDetector, sql_injection_concat: str
    ) -> None:
        findings = detector.scan(sql_injection_concat, "app.py")
        assert any(f.rule_id == "SC-P002" for f in findings)

    def test_detects_fstring_sql(
        self, detector: SecurityPatternDetector, sql_injection_fstring: str
    ) -> None:
        findings = detector.scan(sql_injection_fstring, "app.py")
        assert any(f.rule_id in ("SC-P001", "SC-P002") for f in findings)


class TestXSS:
    def test_detects_innerhtml(self, detector: SecurityPatternDetector, xss_innerhtml: str) -> None:
        findings = detector.scan(xss_innerhtml, "app.js")
        assert any(f.rule_id == "SC-P003" for f in findings)

    def test_detects_dangerously_set_innerhtml(
        self, detector: SecurityPatternDetector, xss_dangerously: str
    ) -> None:
        findings = detector.scan(xss_dangerously, "component.tsx")
        assert any(f.rule_id == "SC-P004" for f in findings)


class TestCommandInjection:
    def test_detects_os_system(
        self, detector: SecurityPatternDetector, command_injection_os: str
    ) -> None:
        findings = detector.scan(command_injection_os, "util.py")
        assert any(f.rule_id == "SC-P005" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_subprocess_shell_true(
        self, detector: SecurityPatternDetector, command_injection_subprocess: str
    ) -> None:
        findings = detector.scan(command_injection_subprocess, "util.py")
        assert any(f.rule_id == "SC-P006" for f in findings)

    def test_detects_eval(self, detector: SecurityPatternDetector, eval_snippet: str) -> None:
        findings = detector.scan(eval_snippet, "calc.py")
        assert any(f.rule_id == "SC-P007" for f in findings)


class TestInsecureDeserialization:
    def test_detects_pickle_loads(
        self, detector: SecurityPatternDetector, pickle_loads_snippet: str
    ) -> None:
        findings = detector.scan(pickle_loads_snippet, "data.py")
        assert any(f.rule_id == "SC-P008" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_unsafe_yaml(
        self, detector: SecurityPatternDetector, yaml_unsafe_snippet: str
    ) -> None:
        findings = detector.scan(yaml_unsafe_snippet, "config.py")
        assert any(f.rule_id == "SC-P009" for f in findings)


class TestHardcodedCredentials:
    def test_detects_hardcoded_password(
        self, detector: SecurityPatternDetector, hardcoded_password_snippet: str
    ) -> None:
        findings = detector.scan(hardcoded_password_snippet, "settings.py")
        assert any(f.rule_id == "SC-P010" for f in findings)

    def test_detects_hardcoded_secret_key(self, detector: SecurityPatternDetector) -> None:
        content = 'secret_key = "my-super-secret-value-123"'
        findings = detector.scan(content, "config.py")
        assert any(f.rule_id == "SC-P010" for f in findings)


class TestInsecureCrypto:
    def test_detects_md5(self, detector: SecurityPatternDetector, md5_hash_snippet: str) -> None:
        findings = detector.scan(md5_hash_snippet, "auth.py")
        assert any(f.rule_id == "SC-P011" for f in findings)

    def test_detects_ecb_mode(self, detector: SecurityPatternDetector) -> None:
        content = "cipher = AES.new(key, AES.MODE_ECB)"
        findings = detector.scan(content, "crypto.py")
        assert any(f.rule_id == "SC-P013" for f in findings)


class TestSafeCodePassesClean:
    def test_safe_sql_no_finding(
        self, detector: SecurityPatternDetector, safe_sql_snippet: str
    ) -> None:
        findings = detector.scan(safe_sql_snippet, "app.py")
        # Parameterized query should not trigger SQL injection
        sql_findings = [f for f in findings if f.rule_id in ("SC-P001", "SC-P002")]
        assert len(sql_findings) == 0

    def test_safe_yaml_no_finding(
        self, detector: SecurityPatternDetector, safe_yaml_snippet: str
    ) -> None:
        findings = detector.scan(safe_yaml_snippet, "config.py")
        yaml_findings = [f for f in findings if f.rule_id == "SC-P009"]
        assert len(yaml_findings) == 0

    def test_env_password_no_finding(
        self, detector: SecurityPatternDetector, safe_password_env: str
    ) -> None:
        findings = detector.scan(safe_password_env, "settings.py")
        pw_findings = [f for f in findings if f.rule_id == "SC-P010"]
        assert len(pw_findings) == 0

    def test_securecommit_ignore(self, detector: SecurityPatternDetector) -> None:
        content = 'os.system("echo hello")  # securecommit:ignore'
        findings = detector.scan(content, "util.py")
        assert len(findings) == 0
