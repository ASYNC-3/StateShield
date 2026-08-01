import os
from typing import Dict

# --- Server & Service Ports ---
BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
FRONTEND_PORT: int = int(os.getenv("FRONTEND_PORT", "8501"))

# --- Model & Provider Settings ---
EMBEDDING_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM: int = 384

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

# --- Tier 1 Filter Thresholds ---
TIER1_SIMILARITY_BLOCK_THRESHOLD: float = float(
    os.getenv("TIER1_SIMILARITY_BLOCK_THRESHOLD", "0.85")
)
TIER1_SIMILARITY_ESCALATE_THRESHOLD: float = float(
    os.getenv("TIER1_SIMILARITY_ESCALATE_THRESHOLD", "0.55")
)

# --- Trust Engine Parameters ---
INITIAL_TRUST: float = 100.0
LOCKDOWN_THRESHOLD: float = 30.0

TRUST_PENALTIES: Dict[str, float] = {
    "tier1_block": -40.0,
    "tier2_flag": -25.0,
    "leakage_attempt": -30.0,
    "repeat_probe": -10.0,
}
RECOVERY_PER_BENIGN_TURN: float = 2.0

# --- Seed Attack Families for Mock Data ---
ATTACK_FAMILIES = [
    "direct_injection",
    "jailbreak_roleplay",
    "obfuscation",
    "extraction_leakage",
    "unlabeled_emerging",
]
