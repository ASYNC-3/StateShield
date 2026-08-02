import unittest
import uuid
from backend.core.trust_engine import (
    update_trust,
    get_trust_history,
    get_session_score,
    is_session_locked,
    TrustEvent,
)

class TestTrustEngine(unittest.TestCase):

    def test_initial_session_trust(self):
        session_id = f"test-init-{uuid.uuid4()}"
        score = get_session_score(session_id)
        self.assertEqual(score, 100.0)
        self.assertFalse(is_session_locked(session_id))

    def test_tier1_block_penalty(self):
        session_id = f"test-t1-{uuid.uuid4()}"
        event: TrustEvent = {"session_id": session_id, "signal": "tier1_block"}
        new_score = update_trust(event)
        self.assertEqual(new_score, 60.0)  # 100 - 40

    def test_benign_turn_recovery(self):
        session_id = f"test-rec-{uuid.uuid4()}"
        update_trust({"session_id": session_id, "signal": "tier2_flag"})  # 100 - 25 = 75
        self.assertEqual(get_session_score(session_id), 75.0)

        new_score = update_trust({"session_id": session_id, "signal": "benign"})
        self.assertEqual(new_score, 77.0)  # 75 + 2

    def test_repeat_probing_penalty(self):
        session_id = f"test-repeat-{uuid.uuid4()}"
        # Turn 1: suspicious signal
        s1 = update_trust({"session_id": session_id, "signal": "tier1_block"})  # 100 - 40 = 60
        self.assertEqual(s1, 60.0)

        # Turn 2: second suspicious signal in window -> triggers extra repeat_probe penalty (-10)
        s2 = update_trust({"session_id": session_id, "signal": "tier2_flag"})  # 60 - 25 - 10 = 25
        self.assertEqual(s2, 25.0)
        self.assertTrue(is_session_locked(session_id))  # score 25 < 30 threshold

    def test_score_bounds_and_lockdown(self):
        session_id = f"test-bounds-{uuid.uuid4()}"
        for _ in range(5):
            update_trust({"session_id": session_id, "signal": "tier1_block"})

        self.assertEqual(get_session_score(session_id), 0.0)  # bounded at 0
        self.assertTrue(is_session_locked(session_id))


if __name__ == "__main__":
    unittest.main()
