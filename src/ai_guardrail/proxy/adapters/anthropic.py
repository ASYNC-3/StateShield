import time
from typing import Dict, Any

class AnthropicAdapter:
    """Transforms between OpenAI ChatCompletions schema and Anthropic Messages API schema."""

    def to_upstream(self, openai_style_request: Dict[str, Any]) -> Dict[str, Any]:
        messages = openai_style_request.get("messages", [])
        system_content = next((m.get("content") for m in messages if m.get("role") == "system"), None)
        turns = [m for m in messages if m.get("role") != "system"]

        payload = {
            "model": openai_style_request.get("model", "claude-3-haiku-20240307"),
            "messages": turns,
            "max_tokens": openai_style_request.get("max_tokens", 1024),
        }
        if system_content:
            payload["system"] = system_content
        return payload

    def from_upstream(self, upstream_response: Dict[str, Any]) -> Dict[str, Any]:
        text = ""
        if "content" in upstream_response and isinstance(upstream_response["content"], list):
            if len(upstream_response["content"]) > 0:
                text = upstream_response["content"][0].get("text", "")

        return {
            "id": f"chatcmpl-anthropic-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": upstream_response.get("model", "claude-3-haiku-20240307"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": upstream_response.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": upstream_response.get("usage", {}).get("output_tokens", 0),
                "total_tokens": (
                    upstream_response.get("usage", {}).get("input_tokens", 0)
                    + upstream_response.get("usage", {}).get("output_tokens", 0)
                ),
            },
        }
