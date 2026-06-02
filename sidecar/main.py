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

# Groq — invisible last-resort backstop (centralized). Fires ONLY when every
# decentralized SN64 option is exhausted or the global budget is blown.
GROQ_API_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL     = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

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

# ── Failover budget ladder ────────────────────────────────────────────────────
# Two clocks: a per-attempt TTFT cap (abandon a stalling miner fast) and a
# global wall-clock budget across all decentralized attempts (the ripcord).
TTFT_CAP             = 5.0   # streaming: max seconds to first token per SN64 attempt
ATTEMPT_TIMEOUT      = 8.0   # non-streaming: max seconds per SN64 attempt
DECENTRALIZED_BUDGET = 12.0  # global seconds across SN64 before ripcord → Groq
STREAM_IDLE          = 15.0  # max seconds between chunks once a stream is flowing
GROQ_TIMEOUT         = 10.0  # backstop hard cap (Groq TTFT is typically <0.5s)

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
    is_stream = bool(request.get("stream"))

    # ── Phase 1: decentralized (SN64) — TTFT caps + global budget ───────────────
    if is_stream:
        result = await _route_streaming(request, model_chain)
    else:
        result = await _route_buffered(request, model_chain)
    if result is not None:
        return result

    # ── Phase 2: invisible centralized backstop (Groq) ──────────────────────────
    if GROQ_API_KEY:
        log.warning("SN64 exhausted/budget blown — failing over to Groq backstop")
        backstop = await _groq_backstop(request, is_stream)
        if backstop is not None:
            return backstop

    log.error("All providers exhausted (SN64 + Groq)")
    raise HTTPException(status_code=502, detail="all providers at capacity — please retry in a moment")


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
async def _route_streaming(request: dict, model_chain: List[str]):
    """Stream from SN64 with a per-attempt TTFT cap and a global wall-clock
    budget. Peeks the first chunk to confirm a miner is alive before committing
    to its lane. Returns None if all models fail or the budget is blown
    (caller then pulls the ripcord to Groq)."""
    base = {**request, "stream": True, "stream_options": {"include_usage": True}}
    phase_start = time.monotonic()

    for model in model_chain:
        elapsed = time.monotonic() - phase_start
        if elapsed > DECENTRALIZED_BUDGET:
            log.warning("Decentralized budget (%.0fs) blown after %.1fs — ripcord to Groq",
                        DECENTRALIZED_BUDGET, elapsed)
            return None

        payload = {**base, "model": model}
        gen = _open_stream(payload, model)
        try:
            # TTFT cap — abandon a stalling miner fast
            first_chunk = await asyncio.wait_for(gen.__anext__(), timeout=TTFT_CAP)
        except (asyncio.TimeoutError, StopAsyncIteration):
            log.warning("Model %s — no first token within %.0fs, next", model, TTFT_CAP)
            await _safe_aclose(gen)
            continue
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            log.warning("Model %s stream failed (%s) — next", model, type(e).__name__)
            await _safe_aclose(gen)
            await _reset_client()
            continue
        except Exception as e:
            log.warning("Model %s stream error: %s — next", model, e)
            await _safe_aclose(gen)
            continue

        log.info("Streaming from SN64 %s (TTFT %.1fs)", model, time.monotonic() - phase_start)

        async def body():
            yield first_chunk
            async for chunk in gen:
                yield chunk

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={"X-Routed-Subnet": f"SN64-Chutes/{model}"},
        )

    return None


async def _route_buffered(request: dict, model_chain: List[str]):
    """Non-streaming SN64 routing with per-attempt timeout and global budget."""
    phase_start = time.monotonic()
    for model in model_chain:
        elapsed = time.monotonic() - phase_start
        if elapsed > DECENTRALIZED_BUDGET:
            log.warning("Decentralized budget (%.0fs) blown after %.1fs — ripcord to Groq",
                        DECENTRALIZED_BUDGET, elapsed)
            return None
        result = await _try_model(request, model)
        if result is not None:
            return result
    return None


async def _open_stream(payload: dict, model: str):
    """Async generator yielding raw SSE bytes from Chutes. The read timeout
    (STREAM_IDLE) governs gaps once the stream is flowing; the first-token TTFT
    cap is enforced by the caller via asyncio.wait_for."""
    async with _client.stream(
        "POST",
        CHUTES_API_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {CHUTES_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=httpx.Timeout(connect=5.0, read=STREAM_IDLE, write=5.0, pool=5.0),
    ) as resp:
        if resp.status_code != 200:
            log.warning("Model %s stream returned status %s", model, resp.status_code)
            raise httpx.RemoteProtocolError(f"status {resp.status_code}")
        async for chunk in resp.aiter_bytes():
            yield chunk


async def _try_model(request: dict, model: str) -> Optional[JSONResponse]:
    """Single non-streaming attempt against an SN64 model. None on failure."""
    payload = {**request, "model": model}
    try:
        resp = await _client.post(
            CHUTES_API_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {CHUTES_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=ATTEMPT_TIMEOUT,
        )
        if resp.status_code == 429 or resp.status_code >= 500:
            log.warning("Model %s returned %s — next", model, resp.status_code)
            return None
        resp.raise_for_status()
        log.info("SN64 %s succeeded", model)
        return JSONResponse(content=resp.json(), headers={"X-Routed-Subnet": f"SN64-Chutes/{model}"})
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
        log.warning("Model %s timed out (%.0fs) — next", model, ATTEMPT_TIMEOUT)
        await _reset_client()
        return None
    except Exception as e:
        log.warning("Model %s error: %s — next", model, e)
        await _reset_client()
        return None


# ---------------------------------------------------------------------------
# Phase 2 — Groq backstop (invisible centralized last resort)
# ---------------------------------------------------------------------------
async def _groq_backstop(request: dict, is_stream: bool):
    """Last-resort failover to Groq. Stamps X-Routed-Subnet: groq-backstop for
    full transparency. Returns None if Groq also fails."""
    payload = {k: v for k, v in request.items() if k != "model"}
    payload["model"] = GROQ_MODEL
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    if is_stream:
        payload["stream"] = True
        payload.setdefault("stream_options", {"include_usage": True})
        gen = _open_groq_stream(payload)
        try:
            first = await asyncio.wait_for(gen.__anext__(), timeout=GROQ_TIMEOUT)
        except Exception as e:
            log.error("Groq backstop stream failed: %s", e)
            await _safe_aclose(gen)
            return None
        log.info("Groq backstop streaming (%s)", GROQ_MODEL)

        async def body():
            yield first
            async for chunk in gen:
                yield chunk

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={"X-Routed-Subnet": "groq-backstop"},
        )

    payload.pop("stream", None)
    try:
        resp = await _client.post(GROQ_API_URL, json=payload, headers=headers, timeout=GROQ_TIMEOUT)
        resp.raise_for_status()
        log.info("Groq backstop succeeded (%s)", GROQ_MODEL)
        return JSONResponse(content=resp.json(), headers={"X-Routed-Subnet": "groq-backstop"})
    except Exception as e:
        log.error("Groq backstop failed: %s", e)
        return None


async def _open_groq_stream(payload: dict):
    async with _client.stream(
        "POST",
        GROQ_API_URL,
        json=payload,
        headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
        timeout=httpx.Timeout(connect=5.0, read=STREAM_IDLE, write=5.0, pool=5.0),
    ) as resp:
        if resp.status_code != 200:
            raise httpx.RemoteProtocolError(f"groq status {resp.status_code}")
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
        timeout=httpx.Timeout(connect=5.0, read=STREAM_IDLE, write=5.0, pool=5.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )


async def _safe_aclose(agen):
    try:
        await agen.aclose()
    except Exception:
        pass


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
