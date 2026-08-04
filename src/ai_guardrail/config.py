import os
import yaml
from pathlib import Path
from typing import Any, Dict

CONFIG_DIR = Path(".guardrail")
CONFIG_FILE = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG: Dict[str, Any] = {
    "upstream": {
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "model": "gpt-4o-mini",
    },
    "judge": {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
    },
    "thresholds": {
        "tier1_block": 0.85,
        "tier1_escalate": 0.55,
        "trust_lockdown": 30.0,
    },
    "storage": {
        "path": ".guardrail/store",
    },
}


def load_config() -> Dict[str, Any]:
    """Loads configuration from .guardrail/config.yaml with fallback to defaults."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
                # Deep merge defaults with user config
                merged = DEFAULT_CONFIG.copy()
                for key in ["upstream", "judge", "thresholds", "storage"]:
                    if key in user_cfg:
                        merged[key].update(user_cfg[key])
                return merged
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_default_config() -> Path:
    """Ensures .guardrail/config.yaml exists with default settings."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(DEFAULT_CONFIG, f, default_flow_style=False)
    return CONFIG_FILE
