"""SecureCommit — pre-commit security hooks and code review tool."""

__version__ = "0.1.0"

from securecommit.detectors.patterns import SecurityPatternDetector as PatternAnalyzer
from securecommit.detectors.secrets import SecretDetector
from securecommit.scanner import Scanner

__all__ = ["Scanner", "SecretDetector", "PatternAnalyzer"]
