from ai_guardrail.proxy.adapters.openai_compatible import OpenAICompatibleAdapter
from ai_guardrail.proxy.adapters.anthropic import AnthropicAdapter

def get_adapter(provider_name: str):
    if provider_name.lower() == "anthropic":
        return AnthropicAdapter()
    return OpenAICompatibleAdapter()
