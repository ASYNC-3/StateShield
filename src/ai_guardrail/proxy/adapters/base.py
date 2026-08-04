from typing import Protocol, Dict, Any

class LLMAdapter(Protocol):
    """Protocol interface for multi-LLM provider request/response transformation adapters."""

    def to_upstream(self, openai_style_request: Dict[str, Any]) -> Dict[str, Any]:
        """Transforms an OpenAI-style /v1/chat/completions payload to upstream format."""
        ...

    def from_upstream(self, upstream_response: Dict[str, Any]) -> Dict[str, Any]:
        """Transforms an upstream LLM provider response back into OpenAI-compatible format."""
        ...
