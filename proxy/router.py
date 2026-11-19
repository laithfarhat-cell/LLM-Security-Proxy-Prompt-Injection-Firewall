from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

from core.policy import PolicyEngine
from core.telemetry import TelemetryLogger
from scanners.dlp_scanner import DLPScanner, PseudonymizationVault
from scanners.injection_firewall import InjectionFirewall


def create_router(
    policy_engine: PolicyEngine,
    injection_firewall: InjectionFirewall,
    dlp_scanner: DLPScanner,
    telemetry: TelemetryLogger,
) -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": policy_engine.config.telemetry.service_name,
            "injection_mode": policy_engine.config.injection_firewall.mode.value,
            "dlp_mode": policy_engine.config.dlp.mode.value,
            "corpus_patterns": len(injection_firewall.corpus_entries),
        }

    @router.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        x_client_id: Optional[str] = Header(default="anonymous"),
    ) -> Any:
        t_start = time.perf_counter()
        payload: Dict[str, Any] = await request.json()
        messages: List[Dict[str, Any]] = payload.get("messages", [])
        stream: bool = bool(payload.get("stream", False))
        client_id = x_client_id or "anonymous"

        vault = PseudonymizationVault()
        max_risk = 0.0
        all_categories: List[str] = []
        all_rules: List[str] = []
        inj_latency = 0.0
        dlp_latency = 0.0
        decision_label = "ALLOW"

        # 1. Ingress Inspection (User & Tool messages)
        sanitized_messages: List[Dict[str, Any]] = []
        for msg in messages:
            new_msg = dict(msg)
            content = msg.get("content")
            if isinstance(content, str) and msg.get("role") in ("user", "tool"):
                inj_res = injection_firewall.scan_prompt(content)
                inj_latency += inj_res.latency_ms
                if inj_res.risk_score > max_risk:
                    max_risk = inj_res.risk_score
                all_categories.extend(inj_res.categories)
                all_rules.extend(inj_res.matched_rules)

                inj_decision = policy_engine.evaluate_injection(
                    inj_res.risk_score, inj_res.categories
                )
                if inj_decision.blocked:
                    total_ms = round((time.perf_counter() - t_start) * 1000, 3)
                    telemetry.log_event(
                        event_action="block",
                        outcome="blocked",
                        client_id=client_id,
                        attack_category=(inj_res.categories[0] if inj_res.categories else "injection"),
                        risk_score=inj_res.risk_score,
                        matched_rules=inj_res.matched_rules,
                        latency_breakdown_ms={"injection_ms": inj_latency, "total_ms": total_ms},
                        direction="ingress",
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": {
                                "message": inj_decision.reason,
                                "type": "firewall_policy_violation",
                                "code": "prompt_injection_blocked",
                            }
                        },
                        headers={
                            "X-Firewall-Decision": "BLOCK",
                            "X-Firewall-Risk-Score": str(round(inj_res.risk_score, 4)),
                            "X-Firewall-Latency-Ms": str(total_ms),
                        },
                    )
                if inj_decision.action in ("REDACT", "AUDIT"):
                    decision_label = inj_decision.action

                # DLP Ingress Scan
                dlp_res = dlp_scanner.scan_and_redact(content, vault=vault)
                dlp_latency += dlp_res.latency_ms
                if dlp_res.findings:
                    dlp_decision = policy_engine.evaluate_dlp(dlp_res.findings)
                    all_rules.extend([f["rule"] for f in dlp_res.findings])
                    if dlp_decision.blocked:
                        total_ms = round((time.perf_counter() - t_start) * 1000, 3)
                        telemetry.log_event(
                            event_action="block",
                            outcome="blocked",
                            client_id=client_id,
                            attack_category="dlp_violation",
                            risk_score=1.0,
                            matched_rules=all_rules,
                            latency_breakdown_ms={
                                "injection_ms": inj_latency,
                                "dlp_ms": dlp_latency,
                                "total_ms": total_ms,
                            },
                            direction="ingress",
                        )
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": {
                                    "message": dlp_decision.reason,
                                    "type": "firewall_policy_violation",
                                    "code": "dlp_policy_blocked",
                                }
                            },
                            headers={
                                "X-Firewall-Decision": "BLOCK",
                                "X-Firewall-Risk-Score": "1.0",
                                "X-Firewall-Latency-Ms": str(total_ms),
                            },
                        )
                    if dlp_decision.action == "REDACT":
                        new_msg["content"] = dlp_res.sanitized_text
                        decision_label = "REDACT"
                    elif dlp_decision.action == "AUDIT" and decision_label == "ALLOW":
                        decision_label = "AUDIT"

            sanitized_messages.append(new_msg)

        # 2. Canary Token Injection
        canary_token: Optional[str] = None
        if policy_engine.config.injection_firewall.canary.enabled:
            sanitized_messages, canary_token = injection_firewall.inject_canary(sanitized_messages)

        upstream_payload = dict(payload)
        upstream_payload["messages"] = sanitized_messages
        upstream_url = policy_engine.config.proxy.upstream_url
        timeout = policy_engine.config.proxy.timeout_seconds

        # 3. Forward to Upstream (Streaming vs Standard JSON)
        if stream:
            return await _handle_streaming(
                upstream_url=upstream_url,
                upstream_payload=upstream_payload,
                timeout=timeout,
                canary_token=canary_token,
                vault=vault,
                policy_engine=policy_engine,
                injection_firewall=injection_firewall,
                dlp_scanner=dlp_scanner,
                telemetry=telemetry,
                client_id=client_id,
                decision_label=decision_label,
                max_risk=max_risk,
                t_start=t_start,
            )

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(upstream_url, json=upstream_payload)
            resp_data = resp.json()

        # 4. Egress Inspection & Re-Hydration (JSON)
        for choice in resp_data.get("choices", []):
            msg_obj = choice.get("message", {})
            text = msg_obj.get("content")
            if isinstance(text, str):
                if injection_firewall.check_canary_leak(text, canary_token):
                    total_ms = round((time.perf_counter() - t_start) * 1000, 3)
                    telemetry.log_event(
                        event_action="block",
                        outcome="blocked",
                        client_id=client_id,
                        attack_category="system_prompt_leakage",
                        risk_score=1.0,
                        matched_rules=["canary_token_leak"],
                        latency_breakdown_ms={"total_ms": total_ms},
                        direction="egress",
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": {
                                "message": "Egress blocked: System prompt canary token leakage detected.",
                                "type": "firewall_policy_violation",
                                "code": "canary_leak_blocked",
                            }
                        },
                        headers={
                            "X-Firewall-Decision": "BLOCK",
                            "X-Firewall-Risk-Score": "1.0",
                            "X-Firewall-Latency-Ms": str(total_ms),
                        },
                    )
                if policy_engine.config.dlp.rehydrate_egress:
                    text = vault.rehydrate(text)
                msg_obj["content"] = text

        total_ms = round((time.perf_counter() - t_start) * 1000, 3)
        telemetry.log_event(
            event_action=decision_label.lower(),
            outcome="allowed" if decision_label == "ALLOW" else decision_label.lower(),
            client_id=client_id,
            attack_category=(all_categories[0] if all_categories else None),
            risk_score=max_risk,
            matched_rules=sorted(set(all_rules)),
            latency_breakdown_ms={
                "injection_ms": round(inj_latency, 3),
                "dlp_ms": round(dlp_latency, 3),
                "total_ms": total_ms,
            },
            direction="ingress",
        )

        return JSONResponse(
            status_code=resp.status_code,
            content=resp_data,
            headers={
                "X-Firewall-Decision": decision_label,
                "X-Firewall-Risk-Score": str(round(max_risk, 4)),
                "X-Firewall-Latency-Ms": str(total_ms),
            },
        )

    return router


async def _handle_streaming(
    *,
    upstream_url: str,
    upstream_payload: Dict[str, Any],
    timeout: float,
    canary_token: Optional[str],
    vault: PseudonymizationVault,
    policy_engine: PolicyEngine,
    injection_firewall: InjectionFirewall,
    dlp_scanner: DLPScanner,
    telemetry: TelemetryLogger,
    client_id: str,
    decision_label: str,
    max_risk: float,
    t_start: float,
) -> StreamingResponse:
    window_size = policy_engine.config.proxy.stream_inspection_window_chars

    async def event_generator() -> AsyncIterator[bytes]:
        sliding_buffer = ""
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", upstream_url, json=upstream_payload) as resp:
                async for line in resp.aiter_lines():
                    if not line:
                        yield b"\n"
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            yield b"data: [DONE]\n\n"
                            break
                        try:
                            chunk_json = json.loads(data_str)
                            for choice in chunk_json.get("choices", []):
                                delta = choice.get("delta", {})
                                token_text = delta.get("content")
                                if isinstance(token_text, str):
                                    sliding_buffer = (sliding_buffer + token_text)[-window_size:]
                                    if injection_firewall.check_canary_leak(
                                        sliding_buffer, canary_token
                                    ):
                                        telemetry.log_event(
                                            event_action="block",
                                            outcome="blocked",
                                            client_id=client_id,
                                            attack_category="system_prompt_leakage",
                                            risk_score=1.0,
                                            matched_rules=["canary_token_leak_stream"],
                                            direction="egress",
                                        )
                                        err_chunk = json.dumps(
                                            {
                                                "error": {
                                                    "message": "Stream terminated: canary leak detected.",
                                                    "code": "canary_leak_blocked",
                                                }
                                            }
                                        )
                                        yield f"data: {err_chunk}\n\n".encode("utf-8")
                                        return
                                    if policy_engine.config.dlp.rehydrate_egress:
                                        delta["content"] = vault.rehydrate(token_text)
                            yield f"data: {json.dumps(chunk_json)}\n\n".encode("utf-8")
                        except json.JSONDecodeError:
                            yield (line + "\n").encode("utf-8")
                    else:
                        yield (line + "\n").encode("utf-8")

    total_ms = round((time.perf_counter() - t_start) * 1000, 3)
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "X-Firewall-Decision": decision_label,
            "X-Firewall-Risk-Score": str(round(max_risk, 4)),
            "X-Firewall-Latency-Ms": str(total_ms),
        },
    )
