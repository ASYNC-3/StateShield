from typing import TypedDict, Literal, List

class Tier2Result(TypedDict):
    verdict: Literal["benign", "injection", "jailbreak", "leakage_attempt"]
    confidence: float
    reason: str


def judge_prompt(prompt: str, recent_turns: List[str]) -> Tier2Result:
    """
    Escalation LLM classifier (Groq API llama-3.3-70b-versatile or local Ollama fallback).
    
    # TODO: Replace with real model logic (Groq / Ollama API structured JSON verdict call)
    """
    lower_prompt = prompt.lower()

    if "system prompt" in lower_prompt or "canary" in lower_prompt:
        return {
            "verdict": "leakage_attempt",
            "confidence": 0.95,
            "reason": "Attempted extraction of system configuration or secret tokens.",
        }
    elif "jailbreak" in lower_prompt or "override" in lower_prompt or "dan" in lower_prompt:
        return {
            "verdict": "jailbreak",
            "confidence": 0.91,
            "reason": "Roleplay framing attempting to bypass baseline behavioral guardrails.",
        }
    elif "ignore instructions" in lower_prompt or "new rule" in lower_prompt:
        return {
            "verdict": "injection",
            "confidence": 0.88,
            "reason": "Direct prompt injection pattern detected in input text.",
        }
    else:
        return {
            "verdict": "benign",
            "confidence": 0.98,
            "reason": "Prompt conforms to benign user inquiry standards.",
        }
