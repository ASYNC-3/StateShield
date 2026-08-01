import uuid
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.core.tier1_filter import check_tier1, Tier1Result
from backend.core.tier2_judge import judge_prompt, Tier2Result
from backend.core.trust_engine import update_trust, TrustEvent, get_trust_history
from backend.core.output_guardrail import scan_output, OutputScanResult
from backend.core.lineage_clustering import add_blocked_prompt

router = APIRouter(tags=["chat"])

# In-memory turn log history for session history lookup: session_id -> list of turn dicts
SESSION_TURN_LOGS: Dict[str, List[Dict[str, Any]]] = {}

# Mock canary token per session
SESSION_CANARY_TOKENS: Dict[str, str] = {}


class ChatRequest(BaseModel):
    session_id: str = Field(..., description="UUID4 session identifier")
    message: str = Field(..., description="User prompt text input")


class ChatResponse(BaseModel):
    session_id: str
    response: str
    blocked: bool
    block_reason: Optional[str] = None
    trust_score: float
    tier1_result: Optional[Dict[str, Any]] = None
    tier2_result: Optional[Dict[str, Any]] = None
    output_guardrail_result: Optional[Dict[str, Any]] = None


@router.post("/chat", response_model=ChatResponse)
async def chat_pipeline(request: ChatRequest) -> ChatResponse:
    """
    Main Guardrail Proxy Pipeline Endpoint:
    Orchestrates Session lookup -> Tier 1 -> (Tier 2 escalation) -> Trust update -> Mock LLM pass/block -> Output scan -> Log -> JSON response.
    """
    session_id = request.session_id
    user_message = request.message.strip()

    if not user_message:
        raise HTTPException(status_code=400, detail="User message cannot be empty.")

    # Initialize canary token if new session
    if session_id not in SESSION_CANARY_TOKENS:
        SESSION_CANARY_TOKENS[session_id] = f"SECRET-CANARY-{uuid.uuid4().hex[:8]}"
    canary_token = SESSION_CANARY_TOKENS[session_id]

    # Retrieve recent turns for context
    history = SESSION_TURN_LOGS.get(session_id, [])
    recent_turns = [turn["message"] for turn in history[-3:]]

    # Step 1: Tier-1 Similarity Search
    t1_result: Tier1Result = check_tier1(user_message)
    t2_result: Optional[Tier2Result] = None
    blocked = False
    block_reason: Optional[str] = None
    signal: str = "benign"

    # Evaluate Tier-1 Decision
    if t1_result["decision"] == "block":
        blocked = True
        block_reason = f"Tier-1 Similarity Block ({t1_result['nearest_family']}, score: {t1_result['similarity']:.2f})"
        signal = "tier1_block"

    elif t1_result["decision"] == "escalate":
        # Step 2: Tier-2 Escalation Judge
        t2_result = judge_prompt(user_message, recent_turns)
        if t2_result["verdict"] in ["injection", "jailbreak", "leakage_attempt"]:
            blocked = True
            block_reason = f"Tier-2 Verdict Block: {t2_result['verdict']} ({t2_result['reason']})"
            signal = "tier2_flag" if t2_result["verdict"] != "leakage_attempt" else "leakage_attempt"
        else:
            signal = "benign"

    # Step 3: Update Trust Engine
    trust_event: TrustEvent = {
        "session_id": session_id,
        "signal": signal,  # type: ignore
    }
    new_trust_score = update_trust(trust_event)

    # Step 4: Handle Blocked vs Passed Prompts
    if blocked:
        # Log to Attack Lineage Cluster
        add_blocked_prompt(
            prompt=user_message,
            metadata={
                "session_id": session_id,
                "block_reason": block_reason,
                "nearest_family": t1_result.get("nearest_family", "unknown"),
            },
        )

        refusal_response = (
            f"🚫 [SECURITY BLOCK]: Your prompt was flagged by the AI Security Layer.\n"
            f"Reason: {block_reason}\n"
            f"Current Session Trust Score: {new_trust_score:.1f}/100"
        )

        # Log turn history
        turn_data = {
            "message": user_message,
            "response": refusal_response,
            "blocked": True,
            "block_reason": block_reason,
            "trust_score": new_trust_score,
            "t1_result": t1_result,
            "t2_result": t2_result,
        }
        SESSION_TURN_LOGS.setdefault(session_id, []).append(turn_data)

        return ChatResponse(
            session_id=session_id,
            response=refusal_response,
            blocked=True,
            block_reason=block_reason,
            trust_score=new_trust_score,
            tier1_result=t1_result,
            tier2_result=t2_result,
            output_guardrail_result=None,
        )

    # Step 5: Mock Enterprise LLM Execution (Passed Prompts)
    raw_llm_response = (
        f"Mock Enterprise Assistant Response: I have received your request regarding '{user_message[:40]}...'. "
        f"Everything looks clear and safe! (Session Trust: {new_trust_score:.1f}/100)"
    )

    # Step 6: Output Guardrail Scan
    output_scan: OutputScanResult = scan_output(raw_llm_response, canary_token)

    final_response = output_scan["redacted_text"]

    # Log turn history
    turn_data = {
        "message": user_message,
        "response": final_response,
        "blocked": False,
        "block_reason": None,
        "trust_score": new_trust_score,
        "t1_result": t1_result,
        "t2_result": t2_result,
        "output_guardrail_result": output_scan,
    }
    SESSION_TURN_LOGS.setdefault(session_id, []).append(turn_data)

    return ChatResponse(
        session_id=session_id,
        response=final_response,
        blocked=False,
        block_reason=None,
        trust_score=new_trust_score,
        tier1_result=t1_result,
        tier2_result=t2_result,
        output_guardrail_result=output_scan,
    )
