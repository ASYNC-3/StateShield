from datetime import datetime
from collections import deque
from typing import TypedDict, Literal, List, Tuple, Dict
import sqlite3
import os

from ai_guardrail.config import load_config

class TrustEvent(TypedDict):
    session_id: str
    signal: Literal["tier1_block", "tier2_flag", "leakage_attempt", "benign", "repeat_probe"]


INITIAL_TRUST = 100.0
TRUST_PENALTIES: Dict[str, float] = {
    "tier1_block": -40.0,
    "tier2_flag": -25.0,
    "leakage_attempt": -30.0,
    "repeat_probe": -10.0,
}
RECOVERY_PER_BENIGN_TURN = 2.0
LOCKDOWN_THRESHOLD = 30.0


class SessionState:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.trust_score: float = INITIAL_TRUST
        self.recent_signals: deque = deque(maxlen=5)
        self.history: List[Tuple[str, float, str]] = []
        self.locked: bool = False

        now_str = datetime.utcnow().strftime("%H:%M:%S")
        self.history.append((now_str, INITIAL_TRUST, "initial"))

    def update(self, signal: str) -> float:
        now_str = datetime.utcnow().strftime("%H:%M:%S")
        suspicious_signals = {"tier1_block", "tier2_flag", "leakage_attempt"}

        repeat_probe_penalty = 0.0
        if signal in suspicious_signals:
            previous_suspicious_count = sum(1 for s in self.recent_signals if s in suspicious_signals)
            if previous_suspicious_count >= 1:
                repeat_probe_penalty = TRUST_PENALTIES.get("repeat_probe", -10.0)

        if signal in TRUST_PENALTIES:
            delta = TRUST_PENALTIES[signal] + repeat_probe_penalty
        else:
            delta = RECOVERY_PER_BENIGN_TURN

        self.trust_score = max(0.0, min(100.0, self.trust_score + delta))
        self.recent_signals.append(signal)

        if self.trust_score < LOCKDOWN_THRESHOLD:
            self.locked = True

        self.history.append((now_str, self.trust_score, signal))
        return self.trust_score


_SESSIONS: Dict[str, SessionState] = {}


def _get_db_path() -> str:
    cfg = load_config()
    store_dir = os.path.abspath(cfg.get("storage", {}).get("path", ".guardrail/store"))
    os.makedirs(store_dir, exist_ok=True)
    return os.path.join(store_dir, "sessions.db")


def _init_sqlite_db():
    try:
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_trust (
                session_id TEXT,
                timestamp TEXT,
                trust_score REAL,
                signal TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


_init_sqlite_db()


def _get_or_create_session(session_id: str) -> SessionState:
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = SessionState(session_id)
    return _SESSIONS[session_id]


def update_trust(event: TrustEvent) -> float:
    session_id = event["session_id"]
    signal = event["signal"]

    session = _get_or_create_session(session_id)
    new_score = session.update(signal)

    try:
        now_str = datetime.utcnow().strftime("%H:%M:%S")
        conn = sqlite3.connect(_get_db_path())
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO session_trust (session_id, timestamp, trust_score, signal) VALUES (?, ?, ?, ?)",
            (session_id, now_str, new_score, signal)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return new_score


def get_trust_history(session_id: str) -> List[Tuple[str, float]]:
    session = _get_or_create_session(session_id)
    return [(t, score) for t, score, _ in session.history]


def is_session_locked(session_id: str) -> bool:
    session = _get_or_create_session(session_id)
    return session.locked


def get_session_score(session_id: str) -> float:
    session = _get_or_create_session(session_id)
    return session.trust_score
