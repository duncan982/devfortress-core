"""DevFortress SDK — Agent Output Exfiltration Detector.

Port of the Node SDK's ``agent-output-exfiltration-detector.ts``.

Monitors AI agent outputs for potential data exfiltration patterns.
Detects when agent responses contain sensitive data that shouldn't be
included in outputs (PII, credentials, internal system info).

Patent Pending.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional

ThreatType = Literal[
    "pii-leak", "credential-leak", "system-info-leak", "high-entropy-secret", "oversized-output", "none"
]
Recommendation = Literal["block", "redact", "warn", "allow"]
OutputType = Literal["text", "json", "code", "file"]
DestinationType = Literal["user", "api", "file", "log"]

DEFAULT_SENSITIVE_PATTERNS = [
    # Credit cards
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    # SSN
    r"\b\d{3}-\d{2}-\d{4}\b",
    # Email addresses in unexpected contexts
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b",
    # API keys / tokens (high entropy strings)
    r"(?:api[_-]?key|token|secret|password|credential)[\s:=]+[\"']?[A-Za-z0-9+/=_-]{20,}[\"']?",
    # AWS keys
    r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    # Private keys
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    # Internal IPs
    r"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b",
]


@dataclass
class AgentOutput:
    agent_id: str
    output_content: str
    output_type: OutputType
    destination_type: DestinationType
    timestamp: float


@dataclass
class ExfiltrationResult:
    detected: bool
    threat_type: ThreatType
    confidence: float
    matched_patterns: List[str]
    recommendation: Recommendation
    redacted_output: Optional[str] = None


def _feature_disabled() -> bool:
    return os.environ.get("FEATURE_PLATFORM_INTEL") == "false"


class AgentOutputExfiltrationDetector:
    def __init__(
        self,
        *,
        sensitive_patterns: Optional[List[str]] = None,
        max_output_size_bytes: int = 1_048_576,
        entropy_detection: bool = True,
        entropy_threshold: float = 4.5,
    ):
        self._sensitive_patterns = sensitive_patterns or DEFAULT_SENSITIVE_PATTERNS
        self._max_output_size_bytes = max_output_size_bytes
        self._entropy_detection = entropy_detection
        self._entropy_threshold = entropy_threshold
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self._sensitive_patterns]

    def analyze(self, output: AgentOutput) -> ExfiltrationResult:
        if _feature_disabled():
            return ExfiltrationResult(
                detected=False, threat_type="none", confidence=0, matched_patterns=[], recommendation="allow"
            )

        if len(output.output_content.encode("utf-8")) > self._max_output_size_bytes:
            return ExfiltrationResult(
                detected=True, threat_type="oversized-output", confidence=0.7,
                matched_patterns=[], recommendation="warn",
            )

        matched_patterns: List[str] = []
        for i, pattern in enumerate(self._compiled_patterns):
            if pattern.search(output.output_content):
                matched_patterns.append(self._sensitive_patterns[i])

        if matched_patterns:
            if any("PRIVATE KEY" in p or "AKIA" in p for p in matched_patterns):
                threat_type: ThreatType = "credential-leak"
            elif any("SSN" in p or "credit" in p for p in matched_patterns):
                threat_type = "pii-leak"
            else:
                threat_type = "system-info-leak"

            return ExfiltrationResult(
                detected=True,
                threat_type=threat_type,
                confidence=min(1, 0.5 + len(matched_patterns) * 0.15),
                matched_patterns=matched_patterns,
                recommendation="block" if threat_type == "credential-leak" else "redact",
                redacted_output=self._redact(output.output_content),
            )

        if self._entropy_detection:
            high_entropy_segments = self._find_high_entropy_segments(output.output_content)
            if high_entropy_segments:
                return ExfiltrationResult(
                    detected=True, threat_type="high-entropy-secret", confidence=0.6,
                    matched_patterns=high_entropy_segments, recommendation="warn",
                )

        return ExfiltrationResult(
            detected=False, threat_type="none", confidence=0, matched_patterns=[], recommendation="allow"
        )

    def _redact(self, content: str) -> str:
        redacted = content
        for pattern in self._compiled_patterns:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted

    def _find_high_entropy_segments(self, content: str) -> List[str]:
        segments: List[str] = []
        for candidate in re.findall(r"[A-Za-z0-9+/=_-]{32,}", content):
            if self._shannon_entropy(candidate) > self._entropy_threshold:
                segments.append(candidate[:20] + "...")
        return segments

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        freq: dict = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        total = 0.0
        for count in freq.values():
            p = count / length
            total += p * math.log2(p)
        return -total
