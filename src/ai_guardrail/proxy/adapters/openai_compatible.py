from typing import Dict, Any

class OpenAICompatibleAdapter:
    """Covers OpenAI, Groq, Azure OpenAI, Ollama (/v1 mode), Together, and Fireworks."""

    def to_upstream(self, openai_style_request: Dict[str, Any]) -> Dict[str, Any]:
        """Request payload is already OpenAI-compatible."""
        return openai_style_request

    def from_upstream(self, upstream_response: Dict[str, Any]) -> Dict[str, Any]:
        """Response is already OpenAI-compatible."""
        return upstream_response
