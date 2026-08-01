import uuid
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException

from backend.core.lineage_clustering import get_projection, LineagePoint
from backend.core.trust_engine import get_trust_history
from backend.routers.chat import SESSION_TURN_LOGS

router = APIRouter(tags=["dashboard"])


@router.get("/lineage", response_model=List[LineagePoint])
async def get_lineage_projection() -> List[LineagePoint]:
    """
    Returns 2D cluster projection points of blocked prompts for Attack Lineage dashboard plot.
    """
    return get_projection()


@router.get("/session/{session_id}/trust")
async def get_session_trust_trajectory(session_id: str) -> Dict[str, Any]:
    """
    Returns timeline history of trust scores for the given session.
    """
    history = get_trust_history(session_id)
    return {
        "session_id": session_id,
        "history": [{"timestamp": t, "trust_score": s} for t, s in history],
    }


@router.get("/session/{session_id}/history")
async def get_session_history(session_id: str) -> Dict[str, Any]:
    """
    Returns full turn-by-turn turn logs for the given session.
    """
    turns = SESSION_TURN_LOGS.get(session_id, [])
    return {
        "session_id": session_id,
        "total_turns": len(turns),
        "history": turns,
    }


@router.post("/session/new")
async def create_new_session() -> Dict[str, str]:
    """
    Generates a new UUID4 session identifier for fresh chat sessions.
    """
    new_id = str(uuid.uuid4())
    # Initialize history
    get_trust_history(new_id)
    return {"session_id": new_id, "status": "created"}
