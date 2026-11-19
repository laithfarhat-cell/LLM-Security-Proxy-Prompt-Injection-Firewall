from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class TelemetryLogger:
    """Streams Elastic Common Schema (ECS) JSON security events to disk."""

    def __init__(
        self,
        log_file: str | Path = "firewall_events.json",
        service_name: str = "llm-security-proxy",
        environment: str = "production",
    ) -> None:
        self.log_file = Path(log_file)
        self.service_name = service_name
        self.environment = environment
        self._lock = threading.Lock()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        *,
        event_action: str,
        outcome: str,
        client_id: str,
        attack_category: Optional[str] = None,
        risk_score: float = 0.0,
        matched_rules: Optional[List[str]] = None,
        latency_breakdown_ms: Optional[Dict[str, float]] = None,
        direction: str = "ingress",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "ecs": {"version": "8.11.0"},
            "service": {
                "name": self.service_name,
                "environment": self.environment,
            },
            "event": {
                "kind": "alert" if outcome in ("blocked", "redacted") else "event",
                "category": ["intrusion_detection", "network"],
                "action": event_action,
                "outcome": outcome,
                "duration": round(sum((latency_breakdown_ms or {}).values()), 3),
            },
            "client": {"id": client_id},
            "threat": {
                "framework": "OWASP LLM Top 10",
                "tactic": {"name": attack_category or "none"},
                "indicator": {"confidence": round(risk_score, 4)},
            },
            "firewall": {
                "direction": direction,
                "risk_score": round(risk_score, 4),
                "matched_rules": matched_rules or [],
                "latency_ms": latency_breakdown_ms or {},
            },
        }
        if extra:
            event["firewall"]["details"] = extra

        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        return event
