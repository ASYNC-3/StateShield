"""Tier-1 Semantic Similarity Filter for AI Prompt Security."""

import logging
import os
import threading
from typing import Any, Literal, TypedDict

from ai_guardrail.core.embedder import embed

logger = logging.getLogger("ai_guardrail.tier1_filter")

THRESHOLD_BLOCK = 0.85
THRESHOLD_ESCALATE = 0.55
COLLECTION_NAME = "known_attacks"
SEARCH_TOP_K = 5


class Tier1Result(TypedDict):
    similarity: float
    nearest_family: str
    decision: Literal["block", "escalate", "pass"]


class ChromaDBConnectionManager:
    """Thread-safe connection manager for persistent ChromaDB access."""

    _client = None
    _collection = None
    _lock = threading.Lock()

    @classmethod
    def get_collection(cls) -> Any:
        if cls._collection is None:
            with cls._lock:
                if cls._collection is None:
                    import chromadb

                    db_path = os.path.abspath(
                        os.path.join(os.getcwd(), ".guardrail", "store", "chromadb")
                    )

                    try:
                        cls._client = chromadb.PersistentClient(path=db_path)
                        cls._collection = cls._client.get_collection(name=COLLECTION_NAME)
                    except Exception as err:
                        # Fallback heuristic if collection doesn't exist yet
                        cls._client = None
                        cls._collection = None
                        return None
        return cls._collection


def calculate_similarity(distance: float, space: str) -> float:
    if space == "cosine":
        return 1.0 - distance
    elif space == "l2":
        clamped_distance = max(0.0, distance)
        return 1.0 - (clamped_distance / 2.0)
    elif space == "ip":
        return distance
    else:
        clamped_distance = max(0.0, distance)
        return 1.0 - (clamped_distance / 2.0)


def check_tier1(prompt: str) -> Tier1Result:
    if prompt is None:
        raise TypeError("Prompt input must be a string, received None.")
    if not isinstance(prompt, str):
        raise TypeError(f"Prompt input must be a string, received {type(prompt).__name__}.")
    if not prompt.strip():
        raise ValueError("Prompt input cannot be empty or contain only whitespace.")

    lower_prompt = prompt.lower()

    # Rule-based fallback if ChromaDB is not yet seeded
    collection = ChromaDBConnectionManager.get_collection()
    if collection is None or collection.count() == 0:
        if any(w in lower_prompt for w in ["ignore previous", "jailbreak", "override safety", "dan mode", "bypass"]):
            return {"similarity": 0.92, "nearest_family": "jailbreak_roleplay", "decision": "block"}
        elif any(w in lower_prompt for w in ["system prompt", "developer mode", "canary", "secret key"]):
            return {"similarity": 0.72, "nearest_family": "extraction_leakage", "decision": "escalate"}
        else:
            return {"similarity": 0.28, "nearest_family": "none", "decision": "pass"}

    prompt_embedding = embed(prompt)
    results = collection.query(query_embeddings=[prompt_embedding], n_results=SEARCH_TOP_K)

    if not results or not results.get("ids") or len(results["ids"][0]) == 0:
        return {"similarity": 0.0, "nearest_family": "none", "decision": "pass"}

    nearest_distance = results["distances"][0][0]
    nearest_metadata = results["metadatas"][0][0]
    nearest_family = str(nearest_metadata.get("family", "unknown"))

    space = "l2"
    if collection.metadata and "hnsw:space" in collection.metadata:
        space = collection.metadata["hnsw:space"]

    similarity = calculate_similarity(nearest_distance, space)

    if similarity >= THRESHOLD_BLOCK:
        decision: Literal["block", "escalate", "pass"] = "block"
    elif similarity >= THRESHOLD_ESCALATE:
        decision: Literal["block", "escalate", "pass"] = "escalate"
    else:
        decision: Literal["block", "escalate", "pass"] = "pass"

    return {
        "similarity": similarity,
        "nearest_family": nearest_family,
        "decision": decision,
    }
