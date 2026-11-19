from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="Mock Upstream LLM Server")


@app.post("/v1/chat/completions")
async def mock_completions(request: Request) -> Any:
    payload: Dict[str, Any] = await request.json()
    messages = payload.get("messages", [])
    last_user = next(
        (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
        "Hello!",
    )
    reply = f"Mock LLM Echo: {last_user}"
    stream = bool(payload.get("stream", False))

    if not stream:
        return JSONResponse(
            {
                "id": "chatcmpl-mock-001",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": payload.get("model", "mock-gpt"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": reply},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    async def sse_gen() -> AsyncIterator[bytes]:
        for word in reply.split(" "):
            chunk = {
                "id": "chatcmpl-mock-001",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": word + " "}}],
            }
            yield f"data: {json.dumps(chunk)}\n\n".encode("utf-8")
        yield b"data: [DONE]\n\n"

    return StreamingResponse(sse_gen(), media_type="text/event-stream")
