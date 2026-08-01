import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import uuid

# --- Configuration & Styling ---
BACKEND_URL = "http://localhost:8000"

st.set_page_config(
    page_title="AI Security Layer / Guardrail Proxy",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AI Security Layer / Guardrail Proxy")
st.caption("Live Real-Time Security Operations Console & Multi-Tier Guardrail Pipeline")

# --- Session State Initialization ---
if "session_id" not in st.session_state:
    try:
        res = requests.post(f"{BACKEND_URL}/session/new", timeout=2)
        if res.status_code == 200:
            st.session_state.session_id = res.json()["session_id"]
        else:
            st.session_state.session_id = str(uuid.uuid4())
    except Exception:
        st.session_state.session_id = str(uuid.uuid4())

if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ Session Controls")
    st.markdown("**Session ID:**")
    st.code(st.session_state.session_id, language="text")

    if st.button("🔄 Start New Session", use_container_width=True):
        try:
            res = requests.post(f"{BACKEND_URL}/session/new", timeout=2)
            if res.status_code == 200:
                st.session_state.session_id = res.json()["session_id"]
        except Exception:
            st.session_state.session_id = str(uuid.uuid4())
        st.session_state.messages = []
        st.rerun()

    st.divider()
    st.markdown("### 📊 Guardrail Settings")
    st.markdown("- **Tier 1 Filter:** MiniLM-L6-v2 + ChromaDB")
    st.markdown("- **Tier 2 Judge:** Groq llama-3.3-70b")
    st.markdown("- **Trust Engine:** Dynamic Scoring")
    st.markdown("- **Output Guardrail:** Presidio + Canary")

# --- Layout Setup: Split-Screen ---
left_col, right_col = st.columns([1.2, 1.0])

# ==============================================================================
# LEFT PANEL: Chat Interface
# ==============================================================================
with left_col:
    st.subheader("💬 Protected LLM Chat Interface")
    
    # Display conversation messages
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "trust_score" in msg:
                st.caption(f"Session Trust Score: {msg['trust_score']:.1f}/100")

    # User input
    if prompt := st.chat_input("Type your prompt to the Enterprise LLM..."):
        # Append user prompt
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Call FastAPI Proxy /chat endpoint
        with st.chat_message("assistant"):
            with st.spinner("Evaluating prompt through Guardrail Proxy..."):
                try:
                    payload = {
                        "session_id": st.session_state.session_id,
                        "message": prompt,
                    }
                    response = requests.post(f"{BACKEND_URL}/chat", json=payload, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        bot_response = data["response"]
                        trust_score = data["trust_score"]
                        blocked = data["blocked"]

                        if blocked:
                            st.error(bot_response)
                        else:
                            st.markdown(bot_response)

                        st.caption(f"Session Trust Score: {trust_score:.1f}/100")

                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": bot_response,
                            "trust_score": trust_score,
                            "blocked": blocked,
                        })
                    else:
                        st.error(f"Backend API Error: HTTP {response.status_code}")
                except Exception as e:
                    st.error(f"Connection failed: Could not reach FastAPI backend at {BACKEND_URL}. Details: {str(e)}")

# ==============================================================================
# RIGHT PANEL: Live Security Console
# ==============================================================================
with right_col:
    st.subheader("🛡️ Live Security Console")
    
    tab1, tab2, tab3 = st.tabs(["📉 Trust Trajectory", "🌌 Attack Lineage", "🔍 Why Blocked"])

    # --------------------------------------------------------------------------
    # TAB 1: Trust Trajectory
    # --------------------------------------------------------------------------
    with tab1:
        st.markdown("##### Session Trust Score Timeline")
        try:
            res = requests.get(f"{BACKEND_URL}/session/{st.session_state.session_id}/trust", timeout=2)
            if res.status_code == 200:
                history_data = res.json().get("history", [])
                if history_data:
                    df_trust = pd.DataFrame(history_data)
                    fig_trust = px.line(
                        df_trust,
                        x="timestamp",
                        y="trust_score",
                        markers=True,
                        title="Dynamic Session Trust Score (0 - 100)",
                        labels={"timestamp": "Time", "trust_score": "Trust Score"},
                        range_y=[0, 105],
                    )
                    fig_trust.add_hline(y=30, line_dash="dash", line_color="red", annotation_text="Lockdown Threshold (30)")
                    fig_trust.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
                    st.plotly_chart(fig_trust, use_container_width=True)
                else:
                    st.info("No trust data recorded yet for this session.")
            else:
                st.warning("Could not load trust history.")
        except Exception:
            st.info("Start the backend server to view dynamic trust score updates.")

    # --------------------------------------------------------------------------
    # TAB 2: Attack Lineage Scatter Plot
    # --------------------------------------------------------------------------
    with tab2:
        st.markdown("##### Attack Lineage 2D Projection (UMAP + HDBSCAN)")
        try:
            res = requests.get(f"{BACKEND_URL}/lineage", timeout=2)
            if res.status_code == 200:
                lineage_points = res.json()
                if lineage_points:
                    df_lineage = pd.DataFrame(lineage_points)
                    fig_scatter = px.scatter(
                        df_lineage,
                        x="x",
                        y="y",
                        color="family_label",
                        hover_data=["prompt_snippet", "cluster_id"],
                        title="Blocked Attack Embeddings & Emerging Vectors",
                        labels={"family_label": "Attack Family"},
                    )
                    fig_scatter.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
                    st.plotly_chart(fig_scatter, use_container_width=True)
                else:
                    st.info("No attack lineage data available.")
            else:
                st.warning("Could not load lineage data.")
        except Exception:
            st.info("Start the backend server to render live attack lineage projection.")

    # --------------------------------------------------------------------------
    # TAB 3: Why Blocked Explanation Feed
    # --------------------------------------------------------------------------
    with tab3:
        st.markdown("##### Detailed Security Explanation Log")
        try:
            res = requests.get(f"{BACKEND_URL}/session/{st.session_state.session_id}/history", timeout=2)
            if res.status_code == 200:
                history = res.json().get("history", [])
                blocked_turns = [t for t in history if t.get("blocked")]
                
                if blocked_turns:
                    for idx, turn in enumerate(reversed(blocked_turns)):
                        with st.expander(f"🚫 Blocked Turn #{len(blocked_turns) - idx}: {turn['message'][:35]}..."):
                            st.write(f"**User Prompt:** {turn['message']}")
                            st.write(f"**Block Reason:** {turn.get('block_reason', 'N/A')}")
                            st.write(f"**Session Trust at Block:** {turn.get('trust_score', 'N/A')}")
                            
                            t1 = turn.get("t1_result")
                            if t1:
                                st.json({"Tier-1 Result": t1})
                            t2 = turn.get("t2_result")
                            if t2:
                                st.json({"Tier-2 Result": t2})
                else:
                    st.success("No prompts have been blocked in this session yet.")
            else:
                st.warning("Could not load session history.")
        except Exception:
            st.info("Start the backend server to inspect block log explanations.")
