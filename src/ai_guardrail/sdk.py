import uuid
from typing import Any, Dict, List, Optional
from ai_guardrail.config import load_config
from ai_guardrail.core.tier1_filter import check_tier1, Tier1Result
from ai_guardrail.core.tier2_judge import judge_prompt, Tier2Result
from ai_guardrail.core.trust_engine import update_trust
from ai_guardrail.core.output_guardrail import scan_output
from ai_guardrail.core.lineage_clustering import add_blocked_prompt


class _CompletionsWrapper:
    def __init__(self, guardrail_parent: "Guardrail"):
        self._parent = guardrail_parent

    def create(
        self,
        model: str = "gpt-4o-mini",
        messages: List[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Intercepts and inspects completion requests in-process."""
        if not messages:
            raise ValueError("'messages' list cannot be empty.")

        sid = session_id or "sdk-default-session"
        user_prompt = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_prompt = msg.get("content", "").strip()
                break

        recent_turns = [m.get("content", "") for m in messages[-4:-1] if isinstance(m.get("content"), str)]

        # Tier-1 Check
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

        new_score = update_trust({"session_id": sid, "signal": signal})  # type: ignore

        if blocked:
            add_blocked_prompt(user_prompt, {"session_id": sid, "reason": block_reason})
            refusal_msg = f"🚫 [SECURITY BLOCK]: {block_reason} (Session Trust: {new_score:.1f}/100)"
            return {
                "id": f"chatcmpl-sdk-blocked-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": refusal_msg}, "finish_reason": "content_filter"}],
            }

        # Upstream call
        if self._parent.upstream_client and hasattr(self._parent.upstream_client, "chat"):
            try:
                resp = self._parent.upstream_client.chat.completions.create(
                    model=model, messages=messages, **kwargs
                )
                return resp
            except Exception:
                pass

        # Fallback response
        response_text = f"Mock SDK Completion Response for '{user_prompt[:30]}...' (Session Trust: {new_score:.1f}/100)"
        return {
            "id": f"chatcmpl-sdk-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": response_text}, "finish_reason": "stop"}],
        }


class _ChatWrapper:
    def __init__(self, guardrail_parent: "Guardrail"):
        self.completions = _CompletionsWrapper(guardrail_parent)


class Guardrail:
    """In-process SDK wrapper mirroring OpenAI client syntax."""

    def __init__(self, upstream_client: Any = None, config: Optional[str] = None):
        self.upstream_client = upstream_client
        self.config_path = config
        self.chat = _ChatWrapper(self)
