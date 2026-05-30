"""
TAO Gateway — Dendrite Sidecar
Handles all Bittensor protocol work: wallet, Synapse signing, validator calls.
The Go gateway treats this as a dumb HTTP service.
"""

import os
import time
import logging
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import httpx
import uvicorn

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sidecar")

app = FastAPI(title="TAO Sidecar")

# ---------------------------------------------------------------------------
# Config — all overridable via env
# ---------------------------------------------------------------------------
CHUTES_API_URL = os.getenv("CHUTES_API_URL", "https://llm.chutes.ai/v1/chat/completions")
CHUTES_API_KEY = os.getenv("CHUTES_API_KEY", "")  # get from https://chutes.ai
DEFAULT_MODEL   = os.getenv("DEFAULT_MODEL", "unsloth/Llama-3.3-70B-Instruct")

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "subnet": "SN64-Chutes", "mode": _mode()}

def _mode():
    return "live" if CHUTES_API_KEY else "stub"

# ---------------------------------------------------------------------------
# Main query endpoint — called by Go gateway
# ---------------------------------------------------------------------------
@app.post("/query")
async def query(request: dict):
    """
    Accepts OpenAI-shaped JSON from the Go gateway, routes to Chutes SN64,
    returns an OpenAI-shaped response.

    Phase 1: uses Chutes REST API (no raw dendrite needed — Chutes exposes
    an OpenAI-compatible endpoint itself, which is why adapter complexity is Low).
    Phase 2: add raw bittensor dendrite for subnets without REST wrappers.
    """
    model = request.get("model", DEFAULT_MODEL)

    # Normalize model names — customers may send openai model names
    model = _normalize_model(model)

    payload = {**request, "model": model}

    if not CHUTES_API_KEY:
        # Stub mode — return a canned response so the gateway can be tested
        # without a real Chutes account
        log.warning("CHUTES_API_KEY not set — returning stub response")
        return _stub_response(request)

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                CHUTES_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {CHUTES_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
        resp.raise_for_status()
        data = resp.json()
        return JSONResponse(content=data, headers={"X-Routed-Subnet": "SN64-Chutes"})

    except httpx.HTTPStatusError as e:
        log.error("Chutes error %s: %s", e.response.status_code, e.response.text)
        raise HTTPException(status_code=502, detail="subnet error")
    except Exception as e:
        log.error("Unexpected sidecar error: %s", e)
        raise HTTPException(status_code=502, detail="sidecar error")


def _normalize_model(model: str) -> str:
    """Map common OpenAI model names to Chutes equivalents."""
    mapping = {
        "gpt-4o":           "unsloth/Llama-3.3-70B-Instruct",
        "gpt-4o-mini":      "unsloth/Llama-3.2-3B-Instruct",
        "gpt-4":            "unsloth/Llama-3.3-70B-Instruct",
        "gpt-3.5-turbo":    "unsloth/Llama-3.2-3B-Instruct",
    }
    return mapping.get(model, model)


def _stub_response(request: dict) -> dict:
    messages = request.get("messages", [])
    last = messages[-1]["content"] if messages else "(empty)"
    return {
        "id": "stub-0001",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "stub",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": f"[STUB — set CHUTES_API_KEY to route to SN64] Echo: {last}",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        "x_routed_subnet": "SN64-Chutes-stub",
    }


if __name__ == "__main__":
    port = int(os.getenv("SIDECAR_PORT", "8001"))
    log.info("Sidecar starting on port %d (mode=%s)", port, _mode())
    uvicorn.run(app, host="0.0.0.0", port=port)
