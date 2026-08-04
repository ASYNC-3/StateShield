# Architecture Update — CLI-Installable Middleware + Analytics-Only Dashboard
### Supersedes the delivery layer of the original technical spec — the detection core doesn't change

---

## What Changes vs. What Stays the Same

| Stays exactly the same | Changes |
|---|---|
| Tier-1 embedding filter, Tier-2 LLM judge, Trust Trajectory engine, Attack Lineage clustering, Output Guardrail — all of `core/` | The chat UI disappears entirely — no more Streamlit chat box |
| ChromaDB + SQLite for storage | The dashboard becomes **read-only analytics**, decoupled from any single app or LLM |
| The interface contracts from Part 3 of the original spec | Delivery shifts from "one demo app" to a **pip-installable CLI tool** that fronts *any* LLM traffic |
| The 3-person work split, roughly | The web dev builds a proxy server + CLI instead of a chat UI — same skill, different target |

This is a good pivot: it turns "we built a security demo" into "we built a product you could `pip install` right now," which is a materially stronger claim in front of judges — and technically it's less work, not more, because you're deleting the chat UI, not adding a new detection layer.

---

## The New Shape of the System

```
┌──────────────────────────┐        ┌──────────────────────────┐
│   ANY existing LLM app    │        │  Second terminal:          │
│   (OpenAI SDK, LangChain,  │        │  `guardrail dashboard`     │
│   your own curl script…)  │        │  analytics-only, no chat   │
│                            │        │  input, reads shared store │
│   ONLY change: point       │        └────────────▲───────────────┘
│   base_url at localhost    │                     │ reads
└─────────────┬──────────────┘                     │
              │ POST /v1/chat/completions           │
              ▼                                     │
     ┌────────────────────────────────────────────┐ │
     │        `guardrail serve`  (FastAPI)          │ │
     │        OpenAI-compatible proxy server        │ │
     │                                              │ │
     │  1. Tier-1 fast filter (ChromaDB + MiniLM)   │ │
     │  2. Trust Trajectory update (session state)  │ │
     │  3. Tier-2 LLM judge (only if escalated)     │ │
     │       └─ BLOCK → refusal, OpenAI-shaped JSON │ │
     │  4. Adapter translates request to whatever   │ │
     │     upstream schema is configured             │ │
     │  5. Forwards to the REAL upstream LLM ────────┼─┼──▶  OpenAI / Anthropic /
     │  6. Output Guardrail scans the reply          │ │      Groq / Azure / Ollama /
     │  7. Logs the full turn to SQLite + ChromaDB ──┘ │      anything you configure
     │  8. Returns an OpenAI-compatible response       │
     └──────────────────────────────────────────────┘
```

The proxy is the product. The dashboard is a window into what the proxy has seen — it no longer needs to be, or contain, the thing generating traffic.

---

## Two Ways to Integrate (offer both — they serve different demos)

### 1. Reverse-proxy mode — zero code change in the client app
Anything already built on an OpenAI-compatible client (which by now includes most LangChain/LlamaIndex apps, raw `openai` SDK usage, and a lot of internal tooling) integrates by changing **one line**:

```python
# before
client = OpenAI(api_key=OPENAI_API_KEY)

# after — the only change
client = OpenAI(api_key=OPENAI_API_KEY, base_url="http://localhost:8000/v1")
```

Everything else in the calling app is untouched. This is the strongest hackathon demo you can give: pull up someone's *existing* app, change one line on stage, and show the guardrail catching things live.

### 2. SDK mode — explicit in-process wrapper
For teams that don't want a separate network hop, or are embedding this inside a larger service:

```python
from ai_guardrail import Guardrail
from openai import OpenAI

upstream = OpenAI()
guard = Guardrail(upstream, config="./.guardrail/config.yaml")

response = guard.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": user_input}],
    session_id=session_id,   # ties this call into a Trust Trajectory
)
```

The method signature deliberately mirrors the OpenAI SDK's own shape, so switching a codebase from `client.chat.completions.create(...)` to `guard.chat.completions.create(...)` is close to a find-and-replace.

---

## Multi-LLM Support — the Adapter Layer

Most providers now speak an OpenAI-compatible schema out of the box (Groq, Ollama's `/v1` mode, Azure OpenAI, Together, Fireworks) — for those, the adapter is close to a passthrough, just re-pointing `base_url` and swapping the API key header. Anthropic's native Messages API has a different shape (separate `system` field, content blocks), so it needs a real translation layer. Keep the adapter interface tiny and swappable:

```python
# proxy/adapters/base.py
class LLMAdapter(Protocol):
    def to_upstream(self, openai_style_request: dict) -> dict: ...
    def from_upstream(self, upstream_response: dict) -> dict: ...
```

```python
# proxy/adapters/openai_compatible.py
class OpenAICompatibleAdapter:
    """Covers OpenAI, Groq, Azure OpenAI, Ollama (/v1 mode), Together, Fireworks."""
    def to_upstream(self, req):
        return req  # already the right shape
    def from_upstream(self, resp):
        return resp
```

```python
# proxy/adapters/anthropic.py
class AnthropicAdapter:
    def to_upstream(self, req):
        system = next((m["content"] for m in req["messages"] if m["role"] == "system"), None)
        turns = [m for m in req["messages"] if m["role"] != "system"]
        return {"model": req["model"], "system": system, "messages": turns, "max_tokens": 1024}
    def from_upstream(self, resp):
        # reshape Anthropic's response back into an OpenAI-style completion object
        return {
            "choices": [{"message": {"role": "assistant", "content": resp["content"][0]["text"]}}]
        }
```

Which adapter to use is picked from the config file — the rest of the pipeline (Tier-1/Trust/Tier-2/Output) never knows or cares which upstream it's talking to, because it only ever sees the normalized OpenAI-style `messages` array.

---

## Config File — `.guardrail/config.yaml`

```yaml
upstream:
  provider: openai              # openai | anthropic | groq | azure_openai | ollama
  base_url: https://api.openai.com/v1
  api_key_env: OPENAI_API_KEY
  model: gpt-4o-mini

judge:
  provider: groq
  model: llama-3.3-70b-versatile
  api_key_env: GROQ_API_KEY

thresholds:
  tier1_block: 0.85
  tier1_escalate: 0.55
  trust_lockdown: 30

storage:
  path: .guardrail/store          # SQLite + ChromaDB live here
```

`guardrail init` generates this with sane defaults and prompts for the two API keys it actually needs (upstream + judge) — everything else about the pipeline stays config-driven so switching a demo from OpenAI to Groq-hosted Llama, live, is a one-line edit and a restart.

---

## CLI Commands

| Command | What it does |
|---|---|
| `guardrail init` | Creates `.guardrail/config.yaml`, initializes local SQLite + ChromaDB, seeds the attack corpus (reuses the same `seed_chromadb.py` from Member 1's work) |
| `guardrail serve` | Starts the FastAPI reverse proxy (default `:8000`), exposing an OpenAI-compatible `/v1/chat/completions` endpoint |
| `guardrail dashboard` | Launches the **analytics-only** dashboard (default `:8501`) — Trust Trajectory, Attack Lineage, live blocked-event feed, reading the same local store `serve` writes to. No chat input anywhere in it. |
| `guardrail test` | Runs the labeled adversarial corpus against the running proxy and prints precision/recall/F1 — your live, on-demand "here's our actual catch rate" number for Q&A |
| `guardrail status` | Quick health check — confirms the proxy is up and which upstream/judge it's currently configured to use |

---

## Updated Package Layout (pip-installable)

```
ai-guardrail/
├── pyproject.toml                  # defines the `guardrail` console_script entry point
├── README.md
├── src/
│   └── ai_guardrail/
│       ├── __init__.py
│       ├── cli.py                  # ── Web Dev ── typer app: init / serve / dashboard / test / status
│       ├── config.py               # ── Web Dev ── loads & validates .guardrail/config.yaml
│       │
│       ├── proxy/                  # ── Web Dev ──
│       │   ├── server.py           # FastAPI app, /v1/chat/completions
│       │   └── adapters/
│       │       ├── base.py
│       │       ├── openai_compatible.py
│       │       └── anthropic.py
│       │
│       ├── sdk.py                  # ── Web Dev ── in-process Guardrail() wrapper (mode 2)
│       │
│       ├── core/                   # ── UNCHANGED from the original spec ──
│       │   ├── embedder.py         # Member 1
│       │   ├── tier1_filter.py     # Member 1
│       │   ├── lineage_clustering.py  # Member 1
│       │   ├── tier2_judge.py      # Member 2
│       │   ├── trust_engine.py     # Member 2
│       │   └── output_guardrail.py # Member 2
│       │
│       ├── dashboard/
│       │   └── app_streamlit.py    # ── Web Dev ── analytics only: no st.chat_input anywhere
│       │
│       └── data/
│           └── attack_corpus/      # Member 1, same corpus as before
│
└── tests/
    ├── test_tier1_filter.py
    ├── test_trust_engine.py
    └── eval_adversarial_set.py
```

```toml
# pyproject.toml (relevant bit)
[project.scripts]
guardrail = "ai_guardrail.cli:app"
```

**Note what didn't move:** everything under `core/` is copy-pasted unchanged from the original spec — Member 1 and Member 2's work is not affected by this pivot at all. Only the web dev's scope changes shape: instead of `routers/chat.py` + `frontend/app_streamlit.py` (chat UI), it's now `proxy/server.py` + `cli.py` + `dashboard/app_streamlit.py` (analytics-only). Same person, same amount of work, arguably simpler since there's no chat state to manage on the frontend anymore.

---

## Live Demo Script (this is the actual pitch now)

```bash
pip install -e .
guardrail init                          # creates config, seeds ChromaDB
export OPENAI_API_KEY=...  GROQ_API_KEY=...
guardrail serve                         # proxy live on :8000
```
In a second terminal:
```bash
guardrail dashboard                     # analytics live on :8501
```
Then, on stage: take any existing OpenAI-SDK-based snippet (yours, or genuinely anyone's), change one line to point `base_url` at `http://localhost:8000/v1`, and run it. Send a couple of normal prompts, then a couple of adversarial ones — narrate what shows up on the dashboard in real time: the Trust Trajectory line moving, a new point landing in the Attack Lineage map. Close with `guardrail test` printing a real precision/recall number against your labeled corpus.

**Why this beats the chatbot demo:** every other team in the room is demoing their own toy chat interface. You're demoing infrastructure — the fact that it works against an app it has never seen before, with a one-line integration change, is the whole point, and it directly answers "how would this actually get adopted" before a judge even asks.
