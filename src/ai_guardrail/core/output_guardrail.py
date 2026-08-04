import re
from typing import TypedDict

class OutputScanResult(TypedDict):
    pii_found: bool
    leakage_detected: bool
    redacted_text: str


_PRESIDIO_AVAILABLE = False
_analyzer = None
_anonymizer = None

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    _analyzer = AnalyzerEngine()
    _anonymizer = AnonymizerEngine()
    _PRESIDIO_AVAILABLE = True
except Exception:
    _PRESIDIO_AVAILABLE = False


def _regex_pii_redact(text: str) -> tuple[str, bool]:
    redacted = text
    pii_found = False

    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if re.search(email_pattern, redacted):
        pii_found = True
        redacted = re.sub(email_pattern, "<PII_EMAIL>", redacted)

    phone_pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    if re.search(phone_pattern, redacted):
        pii_found = True
        redacted = re.sub(phone_pattern, "<PII_PHONE>", redacted)

    card_pattern = r"\b(?:\d[ -]*?){13,16}\b"
    if re.search(card_pattern, redacted):
        pii_found = True
        redacted = re.sub(card_pattern, "<PII_CREDIT_CARD>", redacted)

    return redacted, pii_found


def scan_output(text: str, canary_token: str) -> OutputScanResult:
    redacted_text = text
    pii_found = False
    leakage_detected = False

    if canary_token and (canary_token in text or "SECRET-CANARY" in text):
        leakage_detected = True
        if canary_token in redacted_text:
            redacted_text = redacted_text.replace(canary_token, "<CANARY_TOKEN_REDACTED>")
        redacted_text = re.sub(r"SECRET-CANARY-[a-f0-9]+", "<CANARY_TOKEN_REDACTED>", redacted_text)

    if _PRESIDIO_AVAILABLE and _analyzer and _anonymizer:
        try:
            results = _analyzer.analyze(
                text=redacted_text,
                entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN"],
                language="en",
            )
            if results:
                pii_found = True
                anonymized_result = _anonymizer.anonymize(text=redacted_text, analyzer_results=results)
                redacted_text = anonymized_result.text
        except Exception:
            redacted_text, regex_pii = _regex_pii_redact(redacted_text)
            pii_found = pii_found or regex_pii
    else:
        redacted_text, regex_pii = _regex_pii_redact(redacted_text)
        pii_found = pii_found or regex_pii

    return {
        "pii_found": pii_found,
        "leakage_detected": leakage_detected,
        "redacted_text": redacted_text,
    }
