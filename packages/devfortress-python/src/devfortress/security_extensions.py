"""Minimal port of the Node SDK's ``security-extensions.ts``.

Only ``PromptInjectionFilter`` is ported here. The rest of
``security-extensions.ts`` is unrelated to this package's agent-security
pillars and is out of scope for this port.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional

Sensitivity = Literal["low", "medium", "high"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Known indirect prompt injection patterns (name, pattern, weight) — same
# set and weights as Node's PromptInjectionFilter.INJECTION_PATTERNS.
_INJECTION_PATTERNS = [
    (r"ignore\s+(previous|above|all|prior)\s+(instructions?|context|rules?)", "instruction_override", 40),
    (r"you\s+are\s+now\s+(a|an|the)", "role_assignment", 35),
    (r"system\s*:\s*|\[SYSTEM\]|<\|system\|>", "system_prompt_injection", 45),
    (r"forget\s+(everything|all|what)", "memory_wipe", 40),
    (r"do\s+not\s+(follow|obey|listen)", "disobedience_injection", 35),
    (r"act\s+as\s+(if|though)|pretend\s+(to\s+be|you)", "persona_injection", 30),
    (r"<script>|javascript:|onerror=|onload=", "xss_in_data", 50),
    (r"\bexec\s*\(|eval\s*\(|__import__", "code_execution", 50),
    (r"translate.*to.*base64|encode.*payload", "encoding_evasion", 25),
    (r"reveal\s+(your|the)\s+(system|secret|api|key|password)", "secret_extraction", 45),
]


@dataclass
class PromptInjectionResult:
    safe: bool
    confidence: float
    severity: Severity
    detected_patterns: List[str]
    reason: str


class PromptInjectionFilter:
    def __init__(
        self,
        *,
        sensitivity: Sensitivity = "medium",
        custom_patterns: Optional[List[str]] = None,
        max_scan_length: int = 100_000,
        debug: bool = False,
    ):
        self._sensitivity = sensitivity
        self._max_scan_length = max_scan_length
        self._debug = debug

        self._patterns = [
            (re.compile(p, re.IGNORECASE), name, weight) for p, name, weight in _INJECTION_PATTERNS
        ]
        for i, pattern in enumerate(custom_patterns or []):
            self._patterns.append((re.compile(pattern, re.IGNORECASE), f"custom_{i}", 30))

    def scan(self, content: str) -> PromptInjectionResult:
        text = content[: self._max_scan_length]
        detected_patterns: List[str] = []
        total_weight = 0

        for regex, name, weight in self._patterns:
            if regex.search(text):
                detected_patterns.append(name)
                total_weight += weight

        sensitivity_multiplier = {"high": 1.5, "low": 0.7}.get(self._sensitivity, 1.0)
        score = min(100, round(total_weight * sensitivity_multiplier))
        confidence = min(0.99, 0.5 + len(detected_patterns) * 0.15) if detected_patterns else 0.1

        if score >= 70:
            severity: Severity = "CRITICAL"
        elif score >= 45:
            severity = "HIGH"
        elif score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return PromptInjectionResult(
            safe=score < 30,
            confidence=confidence,
            severity=severity,
            detected_patterns=detected_patterns,
            reason=(
                f"Prompt injection detected: {', '.join(detected_patterns)} (score={score})"
                if detected_patterns
                else "Content appears safe"
            ),
        )

    def scan_agent_input(self, content: str) -> PromptInjectionResult:
        return self.scan(content)
