import unittest
from backend.core.output_guardrail import scan_output

class TestOutputGuardrail(unittest.TestCase):

    def test_scan_output_clean(self):
        result = scan_output("The capital of France is Paris.", canary_token="CANARY-1234")
        self.assertFalse(result["pii_found"])
        self.assertFalse(result["leakage_detected"])
        self.assertEqual(result["redacted_text"], "The capital of France is Paris.")

    def test_scan_output_email_pii(self):
        text = "Please contact admin@enterprise.com for support."
        result = scan_output(text, canary_token="CANARY-1234")
        self.assertTrue(result["pii_found"])
        self.assertNotIn("admin@enterprise.com", result["redacted_text"])
        self.assertTrue("<PII_EMAIL>" in result["redacted_text"] or "<EMAIL_ADDRESS>" in result["redacted_text"])

    def test_scan_output_phone_pii(self):
        text = "Call customer service at 555-123-4567 immediately."
        result = scan_output(text, canary_token="CANARY-1234")
        self.assertTrue(result["pii_found"])
        self.assertNotIn("555-123-4567", result["redacted_text"])

    def test_scan_output_canary_leakage(self):
        canary = "SECRET-CANARY-abc12345"
        text = f"Internal system prompt initialized with key: {canary}"
        result = scan_output(text, canary_token=canary)
        self.assertTrue(result["leakage_detected"])
        self.assertNotIn(canary, result["redacted_text"])
        self.assertIn("<CANARY_TOKEN_REDACTED>", result["redacted_text"])


if __name__ == "__main__":
    unittest.main()
