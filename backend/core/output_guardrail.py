import re
from typing import TypedDict

class OutputScanResult(TypedDict):
    pii_found: bool
    leakage_detected: bool
    redacted_text: str


def scan_output(text: str, canary_token: str) -> OutputScanResult:
    """
    Scans LLM output for PII leakage and secret canary system prompt tokens.
    
    # TODO: Replace with Microsoft Presidio analyzer/anonymizer & regex canary scanner
    """
    redacted = text
    pii_found = False
    leakage_detected = False

    # Check for Canary Token leakage
    if canary_token and canary_token in text:
        leakage_detected = True
        redacted = redacted.replace(canary_token, "<CANARY_TOKEN_REDACTED>")

    # Check for PII Email patterns
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if re.search(email_pattern, redacted):
        pii_found = True
        redacted = re.sub(email_pattern, "<PII_EMAIL_REDACTED>", redacted)

    # Check for PII Phone patterns
    phone_pattern = r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"
    if re.search(phone_pattern, redacted):
        pii_found = True
        redacted = re.sub(phone_pattern, "<PII_PHONE_REDACTED>", redacted)

    return {
        "pii_found": pii_found,
        "leakage_detected": leakage_detected,
        "redacted_text": redacted,
    }
