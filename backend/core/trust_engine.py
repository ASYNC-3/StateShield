from datetime import datetime
from typing import TypedDict, Literal, List, Tuple, Dict
from backend.config import (
    INITIAL_TRUST,
    TRUST_PENALTIES,
    RECOVERY_PER_BENIGN_TURN,
    LOCKDOWN_THRESHOLD,
)

class TrustEvent(TypedDict):
    session_id: str
    signal: Literal["tier1_block", "tier2_flag", "leakage_attempt", "benign", "repeat_probe"]


# In-memory storage for session trust history: session_id -> list of (timestamp_str, score)
_SESSION_TRUST_HISTORIES: Dict[str, List[Tuple[str, float]]] = {}
_SESSION_CURRENT_SCORES: Dict[str, float] = {}


def update_trust(event: TrustEvent) -> float:
    """
    Updates session trust score based on incoming event signals.
    
    # TODO: Replace with persistent SQLite database storage and multi-step repeat probing analysis
    """
    session_id = event["session_id"]
    signal = event["signal"]
    now_str = datetime.utcnow().strftime("%H:%M:%S")

    current_score = _SESSION_CURRENT_SCORES.get(session_id, INITIAL_TRUST)

    delta = TRUST_PENALTIES.get(signal, RECOVERY_PER_BENIGN_TURN)
    new_score = max(0.0, min(100.0, current_score + delta))

    _SESSION_CURRENT_SCORES[session_id] = new_score

    if session_id not in _SESSION_TRUST_HISTORIES:
        _SESSION_TRUST_HISTORIES[session_id] = [(now_str, INITIAL_TRUST)]

    _SESSION_TRUST_HISTORIES[session_id].append((now_str, new_score))

    return new_score


def get_trust_history(session_id: str) -> List[Tuple[str, float]]:
    """
    Returns history of (timestamp, trust_score) tuples for a given session.
    
    # TODO: Replace with SQLite query for persistent trust trajectory tracking
    """
    if session_id not in _SESSION_TRUST_HISTORIES:
        now_str = datetime.utcnow().strftime("%H:%M:%S")
        _SESSION_TRUST_HISTORIES[session_id] = [(now_str, INITIAL_TRUST)]
        _SESSION_CURRENT_SCORES[session_id] = INITIAL_TRUST

    return _SESSION_TRUST_HISTORIES[session_id]
