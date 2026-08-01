# AI Security Layer / Guardrail Proxy

A real-time, multi-tiered AI Security Layer & Guardrail Proxy built for Enterprise LLM deployments. Features fast vector similarity filtering, LLM judge escalation, dynamic trust trajectory scoring, output PII/canary leakage redaction, and 2D attack lineage clustering visualization.

---

## 🏗️ Architecture Overview

```
Streamlit UI (Port 8501) <---> FastAPI Proxy Gateway (Port 8000)
                                 ├── 1. Session Manager
                                 ├── 2. Tier-1 Fast Vector Filter (MiniLM + ChromaDB)
                                 ├── 3. Tier-2 LLM Escalation Judge (Groq / Ollama)
                                 ├── 4. Dynamic Session Trust Engine
                                 ├── 5. Mock Enterprise LLM Execution
                                 ├── 6. Output Guardrail (PII Redaction + Canary Check)
                                 └── 7. Attack Lineage Clustering (UMAP + HDBSCAN)
```

---

## 📁 Repository Structure

```
d:\ZeAI\
├── requirements.txt
├── .env.example
├── README.md
├── docs/
│   └── interfaces.md
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── core/
│   │   ├── embedder.py
│   │   ├── tier1_filter.py
│   │   ├── tier2_judge.py
│   │   ├── trust_engine.py
│   │   ├── output_guardrail.py
│   │   └── lineage_clustering.py
│   └── routers/
│       ├── chat.py
│       └── dashboard.py
├── frontend/
│   └── app_streamlit.py
└── scripts/
    ├── run_dev.ps1
    └── run_dev.sh
```

---

## 🚀 Quick Start Guide

### 1. Installation

Install all required Python dependencies:

```bash
pip install -r requirements.txt
```

### 2. Launch FastAPI Backend Server

Run the FastAPI proxy server locally on port 8000:

```bash
uvicorn backend.main:app --reload --port 8000
```

Interactive OpenAPI Documentation: `http://localhost:8000/docs`

### 3. Launch Streamlit Dashboard UI

In a separate terminal, launch the Streamlit frontend:

```bash
streamlit run frontend/app_streamlit.py --server.port 8501
```

Access the Live Dashboard UI at `http://localhost:8501`

---

## 🧪 Testing the API Endpoints

- **Chat Pipeline (`POST /chat`):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/chat" -Method Post -ContentType "application/json" -Body '{"session_id": "demo-123", "message": "What is the capital of France?"}'
  ```

- **Attack Lineage Scatter Points (`GET /lineage`):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/lineage" -Method Get
  ```

- **Session Trust History (`GET /session/demo-123/trust`):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/session/demo-123/trust" -Method Get
  ```
