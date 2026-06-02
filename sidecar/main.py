"""
TAO Gateway — Dendrite Sidecar
Handles all Bittensor protocol work: wallet, Synapse signing, validator calls.
The Go gateway treats this as a dumb HTTP service.
"""

import os
import re
import time
import asyncio
import logging
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
import uvicorn

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sidecar")

app = FastAPI(title="TAO Sidecar")

# Persistent HTTP client — reuses connections and caches DNS across requests
_client: Optional[httpx.AsyncClient] = None

@app.on_event("startup")
async def startup():
    global _client
    _client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=5.0, pool=5.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )
    log.info("HTTP client initialised")

@app.on_event("shutdown")
async def shutdown():
    if _client:
        await _client.aclose()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CHUTES_API_URL = os.getenv("CHUTES_API_URL", "https://llm.chutes.ai/v1/chat/completions")
CHUTES_API_KEY = os.getenv("CHUTES_API_KEY", "")
DEFAULT_MODEL  = os.getenv("DEFAULT_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

# Fallback model chain — all on Chutes SN64, tried in order when primary fails.
# CRITICAL: fallbacks must be NON-REASONING, permanently-hot models. A reasoning
# model (e.g. Qwen3) silently burns output tokens on internal <think> compute,
# which we pay for at full output rates — a margin killer under heavy load.
FALLBACK_MODELS = [
    "deepseek-ai/DeepSeek-V3.2-TEE",          # primary — best quality
    "google/gemma-4-31B-turbo-TEE",           # hot, non-reasoning, $0.15/$0.42 per M
    "unsloth/Mistral-Nemo-Instruct-2407-TEE", # cheapest, non-reasoning, $0.02/$0.10 per M
    "moonshotai/Kimi-K2.6-TEE",               # last resort
]

# Retry config
MAX_RETRIES = 0        # no retries per model — move to next immediately on failure
RETRY_DELAY = 0.0     # no delay between models
FIRST_TIMEOUT = 20.0  # 20s — enough for Fly.io → Chutes under load
RETRY_TIMEOUT = 20.0  # same

# ---------------------------------------------------------------------------
# Tier-1 dynamic router (zero-cost heuristics)
# ---------------------------------------------------------------------------
# Where each complexity tier routes. Cheap, non-reasoning models for simple
# prompts; the strong reasoning model only when the prompt actually needs it.
ROUTE_MODELS = {
    "simple":  "unsloth/Mistral-Nemo-Instruct-2407-TEE",  # $0.02 / $0.10 per M
    "general": "google/gemma-4-31B-turbo-TEE",             # $0.15 / $0.42 per M
    "complex": "deepseek-ai/DeepSeek-V3.2-TEE",            # premium reasoning
}

# Prompt needs a strong reasoning/coding model.
_COMPLEX_RE = re.compile(
    r"```|"                                                       # code fences
    r"\b(def |function |class |import |SELECT |INSERT |UPDATE |DELETE |async |await )|"  # code
    r"\b(prove|derive|calculate|solve|theorem|integral|derivative|algorithm|optimi[sz]e)\b|"  # math/logic
    r"\b(step[\s-]?by[\s-]?step|reason through|think through|explain why|debug|refactor)\b|"   # reasoning asks
    r"[∫∑∏√≤≥≠πθ∂∇]|"                                             # math symbols
    r"\bO\([^)]*\)",                                               # big-O notation
    re.IGNORECASE,
)

# Prompt is trivially simple.
_SIMPLE_RE = re.compile(
    r"^\s*(hi|hello|hey|thanks|thank you|ok|okay|yes|no|sup|yo|cool|nice)\b|"
    r"\b(translate|capital of|what time|how do you spell|define|synonym|antonym|say hi)\b",
    re.IGNORECASE,
)


def _last_user_text(messages):
    """Extract the text of the most recent user message (handles multimodal)."""
    for m in reversed(messages or []):
        if m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, list):  # multimodal: list of parts
                return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
            return content or ""
    return ""


def _classify_prompt(messages) -> str:
    """Tier-1 heuristic classifier → 'simple' | 'general' | 'complex'."""
    text = _last_user_text(messages)
    length = len(text)

    # Long prompts or any complexity signal → complex
    if length > 1500 or _COMPLEX_RE.search(text):
        return "complex"
    # Short and clearly trivial → simple
    if length < 120 and _SIMPLE_RE.search(text):
        return "simple"
    return "general"

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "subnet": "SN64-Chutes", "mode": "live" if CHUTES_API_KEY else "stub"}

# ---------------------------------------------------------------------------
# Main query endpoint
# ---------------------------------------------------------------------------
@app.post("/query")
async def query(request: dict):
    if not CHUTES_API_KEY:
        log.warning("CHUTES_API_KEY not set — returning stub response")
        return _stub_response(request)

    # Pick the primary model. "auto" opts into the dynamic router (Tier 1
    # heuristics); any other name is honored / normalized as before.
    requested = request.get("model", DEFAULT_MODEL)
    if requested in ("auto", "tao-auto"):
        tier = _classify_prompt(request.get("messages", []))
        primary_model = ROUTE_MODELS[tier]
        log.info("Auto-router: prompt classified '%s' → %s", tier, primary_model)
    else:
        primary_model = _normalize_model(requested)

    # Build the model chain: primary first, then fallbacks (excluding primary).
    # The fallback chain is a reliability safety net, not a cost optimizer.
    model_chain = [primary_model] + [m for m in FALLBACK_MODELS if m != primary_model]

    # Streaming path — Server-Sent Events
    if request.get("stream"):
        return await _stream_query(request, model_chain)

    # Non-streaming path
    for model in model_chain:
        result = await _try_model(request, model)
        if result is not None:
            return result
        log.warning("Model %s failed — trying next in chain", model)

    log.error("All models in chain exhausted")
    raise HTTPException(status_code=502, detail="all subnets at capacity — please retry in a moment")


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
async def _stream_query(request: dict, model_chain: List[str]):
    """Open a streaming connection, peek the first chunk to confirm the model
    is alive, then forward the SSE stream through. Falls back across models
    until one starts streaming successfully."""

    # Ensure usage is included in the final SSE chunk (for billing)
    base = {**request, "stream": True, "stream_options": {"include_usage": True}}

    for model in model_chain:
        payload = {**base, "model": model}
        gen = _open_stream(payload, model)
        try:
            first_chunk = await gen.__anext__()   # peek — raises if model is down
        except StopAsyncIteration:
            log.warning("Model %s streamed nothing — trying next", model)
            continue
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            log.warning("Model %s stream failed (%s) — trying next", model, type(e).__name__)
            await _reset_client()
            continue
        except Exception as e:
            log.warning("Model %s stream error: %s — trying next", model, e)
            continue

        log.info("Streaming from model %s", model)

        async def body():
            yield first_chunk
            async for chunk in gen:
                yield chunk

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={"X-Routed-Subnet": f"SN64-Chutes/{model}"},
        )

    log.error("All models in chain exhausted (streaming)")
    raise HTTPException(status_code=502, detail="all subnets at capacity — please retry in a moment")


async def _open_stream(payload: dict, model: str):
    """Async generator yielding raw SSE bytes from Chutes. Raises if the
    upstream returns a non-200 status before any bytes are sent."""
    async with _client.stream(
        "POST",
        CHUTES_API_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {CHUTES_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=FIRST_TIMEOUT,
    ) as resp:
        if resp.status_code != 200:
            log.warning("Model %s stream returned status %s", model, resp.status_code)
            raise httpx.RemoteProtocolError(f"status {resp.status_code}")
        async for chunk in resp.aiter_bytes():
            yield chunk


async def _reset_client():
    """Recreate the HTTP client to clear stale connections."""
    global _client
    try:
        await _client.aclose()
    except Exception:
        pass
    _client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=FIRST_TIMEOUT, write=5.0, pool=5.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )

async def _try_model(request: dict, model: str) -> Optional[JSONResponse]:
    """Try a specific model with retries. Returns None if all attempts fail."""
    payload = {**request, "model": model}

    for attempt in range(MAX_RETRIES + 1):
        timeout = FIRST_TIMEOUT if attempt == 0 else RETRY_TIMEOUT
        try:
            resp = await _client.post(
                CHUTES_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {CHUTES_API_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )

            if resp.status_code == 429 or resp.status_code >= 500:
                # Capacity issue — retry after delay
                if attempt < MAX_RETRIES:
                    log.warning("Model %s returned %s (attempt %d/%d) — retrying in %.1fs",
                                model, resp.status_code, attempt + 1, MAX_RETRIES + 1, RETRY_DELAY)
                    await asyncio.sleep(RETRY_DELAY)
                    continue
                else:
                    log.warning("Model %s exhausted retries with status %s", model, resp.status_code)
                    return None

            resp.raise_for_status()
            data = resp.json()
            log.info("Model %s succeeded (attempt %d)", model, attempt + 1)
            return JSONResponse(content=data, headers={"X-Routed-Subnet": f"SN64-Chutes/{model}"})

        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
            log.warning("Model %s timed out — moving to next", model)
            await _reset_client()
            return None

        except Exception as e:
            log.warning("Model %s error: %s", model, e)
            await _reset_client()
            return None

    return None


def _normalize_model(model: str) -> str:
    """Map common OpenAI model names to Chutes equivalents."""
    mapping = {
        # Premium tier → best quality
        "gpt-4o":        "deepseek-ai/DeepSeek-V3.2-TEE",
        "gpt-4":         "deepseek-ai/DeepSeek-V3.2-TEE",
        "gpt-4-turbo":   "deepseek-ai/DeepSeek-V3.2-TEE",
        # Cheap tier → fast non-reasoning models (price-aligned)
        "gpt-4o-mini":   "google/gemma-4-31B-turbo-TEE",
        "gpt-3.5-turbo": "unsloth/Mistral-Nemo-Instruct-2407-TEE",
        # Friendly shorthands
        "deepseek":      "deepseek-ai/DeepSeek-V3.2-TEE",
        "gemma":         "google/gemma-4-31B-turbo-TEE",
        "mistral":       "unsloth/Mistral-Nemo-Instruct-2407-TEE",
        "qwen-coder":    "Qwen/Qwen2.5-Coder-32B-Instruct-TEE",
        "kimi":          "moonshotai/Kimi-K2.6-TEE",
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
                "content": f"[STUB — set CHUTES_API_KEY] Echo: {last}",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


if __name__ == "__main__":
    port = int(os.getenv("SIDECAR_PORT", "8001"))
    log.info("Sidecar starting on port %d", port)
    uvicorn.run(app, host="0.0.0.0", port=port)
