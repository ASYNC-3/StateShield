import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai_guardrail.config import load_config
from ai_guardrail.core.tier1_filter import check_tier1, Tier1Result
from ai_guardrail.core.tier2_judge import judge_prompt, Tier2Result
from ai_guardrail.core.trust_engine import update_trust, TrustEvent, get_session_score
from ai_guardrail.core.output_guardrail import scan_output, OutputScanResult
from ai_guardrail.core.lineage_clustering import add_blocked_prompt
from ai_guardrail.proxy.adapters import get_adapter

app = FastAPI(
    title="ai-guardrail OpenAI-Compatible Proxy Server",
    description="CLI-installable security proxy intercepting and inspecting LLM completion requests.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_SESSION_CANARIES: Dict[str, str] = {}


def _build_openai_completion_response(
    content: str, model: str = "ai-guardrail-proxy", refusal: bool = False
) -> Dict[str, Any]:
    return {
        "id": f"chatcmpl-guardrail-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop" if not refusal else "content_filter",
            }
        ],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": len(content.split()),
            "total_tokens": 15 + len(content.split()),
        },
    }


@app.get("/health", tags=["system"])
async def health_check():
    cfg = load_config()
    return {
        "status": "ok",
        "service": "ai-guardrail proxy",
        "upstream": cfg.get("upstream", {}).get("provider", "openai"),
        "judge": cfg.get("judge", {}).get("provider", "groq"),
    }


@app.get("/v1/models", tags=["openai"])
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "ai-guardrail"},
            {"id": "gpt-4o", "object": "model", "owned_by": "ai-guardrail"},
            {"id": "llama-3.3-70b-versatile", "object": "model", "owned_by": "ai-guardrail"},
        ],
    }


@app.post("/v1/chat/completions", tags=["openai"])
async def chat_completions(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    messages: List[Dict[str, Any]] = body.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="'messages' array is required.")

    # Extract user prompt (last user message)
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_prompt = msg.get("content", "").strip()
            break

    if not user_prompt:
        raise HTTPException(status_code=400, detail="No user prompt found in messages.")

    # Extract session ID from request body, header, or fallback
    session_id = body.get("session_id") or request.headers.get("x-session-id") or "default-session"

    if session_id not in _SESSION_CANARIES:
        _SESSION_CANARIES[session_id] = f"SECRET-CANARY-{uuid.uuid4().hex[:8]}"
    canary_token = _SESSION_CANARIES[session_id]

    recent_turns = [m.get("content", "") for m in messages[-4:-1] if isinstance(m.get("content"), str)]

    # Step 1: Tier-1 Similarity Check
    t1_result: Tier1Result = check_tier1(user_prompt)
    t2_result: Optional[Tier2Result] = None
    blocked = False
    block_reason: Optional[str] = None
    signal = "benign"

    if t1_result["decision"] == "block":
        blocked = True
        block_reason = f"Tier-1 Similarity Block ({t1_result['nearest_family']}, similarity: {t1_result['similarity']:.2f})"
        signal = "tier1_block"
    elif t1_result["decision"] == "escalate":
        t2_result = judge_prompt(user_prompt, recent_turns)
        if t2_result["verdict"] in ["injection", "jailbreak", "leakage_attempt"]:
            blocked = True
            block_reason = f"Tier-2 Verdict Block: {t2_result['verdict']} ({t2_result['reason']})"
            signal = "tier2_flag" if t2_result["verdict"] != "leakage_attempt" else "leakage_attempt"
        else:
            signal = "benign"

    # Step 2: Update Trust Score
    new_trust_score = update_trust({"session_id": session_id, "signal": signal})  # type: ignore

    # Step 3: Handle Blocked Prompts
    if blocked:
        add_blocked_prompt(user_prompt, {"session_id": session_id, "reason": block_reason})
        refusal_msg = (
            f"🚫 [SECURITY BLOCK]: Your prompt was flagged by ai-guardrail.\n"
            f"Reason: {block_reason}\n"
            f"Current Session Trust Score: {new_trust_score:.1f}/100"
        )
        return _build_openai_completion_response(refusal_msg, model=body.get("model", "gpt-4o-mini"), refusal=True)

    # Step 4: Upstream LLM Forwarding & Output Scanning (Passed Prompts)
    cfg = load_config()
    provider = cfg.get("upstream", {}).get("provider", "openai")
    adapter = get_adapter(provider)
    transformed_req = adapter.to_upstream(body)

    # Generated response (mock or upstream response)
    raw_response_text = (
        f"Mock Upstream Response ({provider}): Evaluated request for '{user_prompt[:30]}...' successfully. "
        f"Session Trust Score: {new_trust_score:.1f}/100."
    )

    output_scan: OutputScanResult = scan_output(raw_response_text, canary_token)
    final_text = output_scan["redacted_text"]

    openai_resp = _build_openai_completion_response(final_text, model=body.get("model", "gpt-4o-mini"))
    return adapter.from_upstream(openai_resp)
