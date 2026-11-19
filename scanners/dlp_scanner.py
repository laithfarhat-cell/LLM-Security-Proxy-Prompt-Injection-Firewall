from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def _luhn_valid(number_str: str) -> bool:
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


DLP_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PRIVATE_KEY"),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "API_KEY"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS_KEY"),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "GITHUB_TOKEN"),
    (
        "bearer_jwt",
        re.compile(r"\bBearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "BEARER_TOKEN",
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "CREDIT_CARD",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "EMAIL",
    ),
    (
        "phone",
        re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"),
        "PHONE",
    ),
    (
        "ipv4",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "IP_ADDR",
    ),
]


class PseudonymizationVault:
    """Session-scoped reversible vault mapping placeholders back to original values."""

    def __init__(self) -> None:
        self._value_to_placeholder: Dict[str, str] = {}
        self._placeholder_to_value: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    def get_or_create(self, label: str, original_value: str) -> str:
        if original_value in self._value_to_placeholder:
            return self._value_to_placeholder[original_value]
        idx = self._counters.get(label, 0) + 1
        self._counters[label] = idx
        placeholder = f"<{label}_{idx}>"
        self._value_to_placeholder[original_value] = placeholder
        self._placeholder_to_value[placeholder] = original_value
        return placeholder

    def rehydrate(self, text: str) -> str:
        result = text
        for placeholder, original in self._placeholder_to_value.items():
            if placeholder in result:
                result = result.replace(placeholder, original)
        return result


@dataclass
class DLPScanResult:
    sanitized_text: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0


class DLPScanner:
    def __init__(
        self,
        enabled_rules: Optional[Dict[str, bool]] = None,
        entropy_threshold: float = 4.5,
    ) -> None:
        self.enabled_rules = enabled_rules or {}
        self.entropy_threshold = entropy_threshold

    def _is_rule_enabled(self, rule_name: str) -> bool:
        return self.enabled_rules.get(rule_name, True)

    def scan_and_redact(
        self, text: str, vault: Optional[PseudonymizationVault] = None
    ) -> DLPScanResult:
        t0 = time.perf_counter()
        if not text:
            return DLPScanResult(sanitized_text=text, findings=[], latency_ms=0.0)

        active_vault = vault or PseudonymizationVault()
        findings: List[Dict[str, Any]] = []
        sanitized = text

        for rule_name, pattern, label in DLP_PATTERNS:
            if not self._is_rule_enabled(rule_name):
                continue

            def _replace(match: re.Match[str]) -> str:
                val = match.group(0)
                if rule_name == "credit_card" and not _luhn_valid(val):
                    return val
                placeholder = active_vault.get_or_create(label, val)
                findings.append({"rule": rule_name, "placeholder": placeholder})
                return placeholder

            sanitized = pattern.sub(_replace, sanitized)

        t1 = time.perf_counter()
        return DLPScanResult(
            sanitized_text=sanitized,
            findings=findings,
            latency_ms=round((t1 - t0) * 1000, 3),
        )
