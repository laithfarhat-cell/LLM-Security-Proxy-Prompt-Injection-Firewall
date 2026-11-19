from __future__ import annotations

import os
from fastapi import FastAPI

from core.policy import PolicyEngine
from core.telemetry import TelemetryLogger
from proxy.router import create_router
from scanners.dlp_scanner import DLPScanner
from scanners.injection_firewall import InjectionFirewall


def create_app(policy_path: str = "policies.yaml") -> FastAPI:
    policy_engine = PolicyEngine(policy_path)
    cfg = policy_engine.config

    if os.getenv("UPSTREAM_URL"):
        cfg.proxy.upstream_url = os.environ["UPSTREAM_URL"]

    injection_firewall = InjectionFirewall(
        corpus_path=cfg.injection_firewall.corpus_path,
        model_name=cfg.injection_firewall.embedding_model,
        lexical_weight=cfg.injection_firewall.lexical_weight,
        semantic_weight=cfg.injection_firewall.semantic_weight,
        canary_prefix=cfg.injection_firewall.canary.prefix,
    )

    enabled_dlp_rules = {name: rule.enabled for name, rule in cfg.dlp.rules.items()}
    dlp_scanner = DLPScanner(
        enabled_rules=enabled_dlp_rules,
        entropy_threshold=cfg.dlp.entropy_threshold,
    )

    telemetry = TelemetryLogger(
        log_file=cfg.telemetry.log_file,
        service_name=cfg.telemetry.service_name,
        environment=cfg.telemetry.environment,
    )

    app = FastAPI(
        title="LLM Security Proxy & Prompt Injection Firewall",
        version="1.0.0",
        description="Low-latency OpenAI-compatible reverse proxy with multi-stage prompt injection & DLP protection.",
    )
    app.include_router(
        create_router(
            policy_engine=policy_engine,
            injection_firewall=injection_firewall,
            dlp_scanner=dlp_scanner,
            telemetry=telemetry,
        )
    )
    return app


app = create_app()
