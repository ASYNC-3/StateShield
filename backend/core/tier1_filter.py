from typing import TypedDict, Literal
from backend.config import (
    TIER1_SIMILARITY_BLOCK_THRESHOLD,
    TIER1_SIMILARITY_ESCALATE_THRESHOLD,
)

class Tier1Result(TypedDict):
    similarity: float
    nearest_family: str          # e.g. "jailbreak_roleplay", "direct_injection"
    decision: Literal["block", "escalate", "pass"]


def check_tier1(prompt: str) -> Tier1Result:
    """
    Fast similarity filter against known attack embeddings in ChromaDB.
    
    # TODO: Replace with real model logic (ChromaDB cosine similarity vs known_attacks)
    """
    lower_prompt = prompt.lower()

    # Deterministic mock decision rules based on prompt content
    if any(keyword in lower_prompt for keyword in ["ignore previous", "jailbreak", "override safety", "dan mode", "bypass"]):
        return {
            "similarity": 0.92,
            "nearest_family": "jailbreak_roleplay",
            "decision": "block",
        }
    elif any(keyword in lower_prompt for keyword in ["system prompt", "developer mode", "canary", "secret key", "instructions"]):
        return {
            "similarity": 0.72,
            "nearest_family": "extraction_leakage",
            "decision": "escalate",
        }
    else:
        return {
            "similarity": 0.28,
            "nearest_family": "none",
            "decision": "pass",
        }
