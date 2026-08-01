# Shared Interface Contracts — AI Security Layer / Guardrail Proxy

All core modules strictly implement the following Python interface contracts.

```python
from typing import TypedDict, Literal

# --- embedder.py ---
def embed(text: str) -> list[float]:
    """Generates a 384-dim dense embedding vector for the input string."""
    ...

def embed_batch(texts: list[str]) -> list[list[float]]:
    """Generates dense embeddings for a batch of strings."""
    ...

# --- tier1_filter.py ---
class Tier1Result(TypedDict):
    similarity: float
    nearest_family: str          # e.g. "jailbreak_roleplay", "direct_injection"
    decision: Literal["block", "escalate", "pass"]

def check_tier1(prompt: str) -> Tier1Result:
    """Fast similarity filter against known attack embeddings in ChromaDB."""
    ...

# --- tier2_judge.py ---
class Tier2Result(TypedDict):
    verdict: Literal["benign", "injection", "jailbreak", "leakage_attempt"]
    confidence: float
    reason: str

def judge_prompt(prompt: str, recent_turns: list[str]) -> Tier2Result:
    """Escalation classifier (Groq LLM / Ollama fallback)."""
    ...

# --- trust_engine.py ---
class TrustEvent(TypedDict):
    session_id: str
    signal: Literal["tier1_block", "tier2_flag", "leakage_attempt", "benign", "repeat_probe"]

def update_trust(event: TrustEvent) -> float:
    """Updates session trust score based on event signal and returns new score."""
    ...

def get_trust_history(session_id: str) -> list[tuple[str, float]]:
    """Returns list of timestamp and score tuples for a given session."""
    ...

# --- output_guardrail.py ---
class OutputScanResult(TypedDict):
    pii_found: bool
    leakage_detected: bool
    redacted_text: str

def scan_output(text: str, canary_token: str) -> OutputScanResult:
    """Scans LLM output for PII leakage and canary system prompt tokens."""
    ...

# --- lineage_clustering.py ---
class LineagePoint(TypedDict):
    x: float
    y: float
    cluster_id: int
    family_label: str            # nearest seed family, or "unlabeled_emerging"
    prompt_snippet: str

def add_blocked_prompt(prompt: str, metadata: dict) -> None:
    """Adds a blocked prompt embedding to the attack lineage database."""
    ...

def get_projection() -> list[LineagePoint]:
    """Returns 2D UMAP + HDBSCAN cluster projections for the lineage plot."""
    ...
```
