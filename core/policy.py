from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class EnforcementMode(str, Enum):
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    AUDIT_ONLY = "AUDIT_ONLY"


class CanaryConfig(BaseModel):
    enabled: bool = True
    prefix: str = "CANARY-"


class InjectionFirewallConfig(BaseModel):
    mode: EnforcementMode = EnforcementMode.BLOCK
    risk_threshold: float = 0.65
    semantic_weight: float = 0.55
    lexical_weight: float = 0.45
    embedding_model: str = "all-MiniLM-L6-v2"
    corpus_path: str = "data/attack_corpus.json"
    canary: CanaryConfig = Field(default_factory=CanaryConfig)


class DLPRuleConfig(BaseModel):
    enabled: bool = True
    severity: str = "medium"
    action: EnforcementMode = EnforcementMode.REDACT


class DLPConfig(BaseModel):
    mode: EnforcementMode = EnforcementMode.REDACT
    rehydrate_egress: bool = True
    scan_egress: bool = True
    entropy_threshold: float = 4.5
    rules: Dict[str, DLPRuleConfig] = Field(default_factory=dict)


class ProxyConfig(BaseModel):
    upstream_url: str = "http://localhost:8001/v1/chat/completions"
    timeout_seconds: float = 60.0
    stream_inspection_window_chars: int = 256


class TelemetryConfig(BaseModel):
    log_file: str = "firewall_events.json"
    service_name: str = "llm-security-proxy"
    environment: str = "production"


class PolicyConfig(BaseModel):
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    injection_firewall: InjectionFirewallConfig = Field(default_factory=InjectionFirewallConfig)
    dlp: DLPConfig = Field(default_factory=DLPConfig)


class PolicyDecision(BaseModel):
    action: str  # "ALLOW", "BLOCK", "REDACT", "AUDIT"
    blocked: bool = False
    reason: Optional[str] = None
    risk_score: float = 0.0
    categories: List[str] = Field(default_factory=list)


class PolicyEngine:
    def __init__(self, policy_path: str | Path = "policies.yaml") -> None:
        self.policy_path = Path(policy_path)
        self.config = self._load_policy(self.policy_path)

    @staticmethod
    def _load_policy(path: Path) -> PolicyConfig:
        if not path.exists():
            return PolicyConfig()
        with path.open("r", encoding="utf-8") as f:
            raw: Dict[str, Any] = yaml.safe_load(f) or {}
        return PolicyConfig(**raw)

    def evaluate_injection(self, risk_score: float, categories: List[str]) -> PolicyDecision:
        threshold = self.config.injection_firewall.risk_threshold
        mode = self.config.injection_firewall.mode

        if risk_score < threshold:
            return PolicyDecision(
                action="ALLOW",
                blocked=False,
                risk_score=risk_score,
                categories=categories,
            )

        if mode == EnforcementMode.BLOCK:
            return PolicyDecision(
                action="BLOCK",
                blocked=True,
                reason=f"Prompt injection/jailbreak detected (risk_score={risk_score:.2f} >= {threshold:.2f})",
                risk_score=risk_score,
                categories=categories,
            )
        if mode == EnforcementMode.REDACT:
            return PolicyDecision(
                action="REDACT",
                blocked=False,
                reason=f"Prompt sanitized due to injection risk (risk_score={risk_score:.2f})",
                risk_score=risk_score,
                categories=categories,
            )
        return PolicyDecision(
            action="AUDIT",
            blocked=False,
            reason=f"Audit-only injection alert (risk_score={risk_score:.2f})",
            risk_score=risk_score,
            categories=categories,
        )

    def evaluate_dlp(self, findings: List[Dict[str, Any]]) -> PolicyDecision:
        if not findings:
            return PolicyDecision(action="ALLOW", blocked=False, risk_score=0.0)

        mode = self.config.dlp.mode
        categories = sorted({f["rule"] for f in findings})
        block_triggered = any(
            self.config.dlp.rules.get(f["rule"], DLPRuleConfig()).action == EnforcementMode.BLOCK
            for f in findings
        )

        if mode == EnforcementMode.BLOCK or block_triggered:
            return PolicyDecision(
                action="BLOCK",
                blocked=True,
                reason=f"Sensitive data / secret policy violation: {', '.join(categories)}",
                risk_score=1.0,
                categories=categories,
            )
        if mode == EnforcementMode.REDACT:
            return PolicyDecision(
                action="REDACT",
                blocked=False,
                reason=f"Redacted sensitive entities: {', '.join(categories)}",
                risk_score=0.5,
                categories=categories,
            )
        return PolicyDecision(
            action="AUDIT",
            blocked=False,
            reason=f"Audit-only DLP alert: {', '.join(categories)}",
            risk_score=0.5,
            categories=categories,
        )
