import os
import sys
import sqlite3
import pandas as pd
import plotly.express as px
import streamlit as st

# Ensure package root and src are in sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for p in [SRC_DIR, ROOT_DIR]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from ai_guardrail.config import load_config
from ai_guardrail.core.lineage_clustering import get_projection

st.set_page_config(
    page_title="ai-guardrail Analytics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ ai-guardrail Security Analytics Console")
st.caption("Read-Only Live Analytics Engine & Multi-Tier Guardrail Audit Trail (No Chat Input)")

cfg = load_config()
store_dir = os.path.abspath(cfg.get("storage", {}).get("path", ".guardrail/store"))
db_path = os.path.join(store_dir, "sessions.db")

# Sidebar Status
with st.sidebar:
    st.header("⚙️ Middleware Config")
    st.markdown(f"**Upstream Provider:** `{cfg.get('upstream', {}).get('provider', 'openai')}`")
    st.markdown(f"**Judge Model:** `{cfg.get('judge', {}).get('model', 'llama-3.3-70b')}`")
    st.markdown(f"**Tier-1 Block Threshold:** `{cfg.get('thresholds', {}).get('tier1_block', 0.85)}`")
    st.markdown(f"**Trust Lockdown:** `< {cfg.get('thresholds', {}).get('trust_lockdown', 30)}`")
    st.divider()
    if st.button("🔄 Refresh Analytics", use_container_width=True):
        st.rerun()

tab1, tab2, tab3 = st.tabs(["📉 Trust Trajectory", "🌌 Attack Lineage Map", "🔍 Security Audit Feed"])

# ------------------------------------------------------------------------------
# TAB 1: Trust Trajectory
# ------------------------------------------------------------------------------
with tab1:
    st.markdown("### Session Trust Score Trajectories")
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            df_trust = pd.read_sql_query("SELECT session_id, timestamp, trust_score, signal FROM session_trust", conn)
            conn.close()

            if not df_trust.empty:
                session_list = df_trust["session_id"].unique().tolist()
                selected_session = st.selectbox("Select Session ID:", session_list)

                df_filtered = df_trust[df_trust["session_id"] == selected_session]
                fig_trust = px.line(
                    df_filtered,
                    x="timestamp",
                    y="trust_score",
                    markers=True,
                    title=f"Dynamic Trust Score Timeline for Session: {selected_session}",
                    labels={"timestamp": "Time", "trust_score": "Trust Score (0-100)"},
                    range_y=[0, 105],
                )
                fig_trust.add_hline(y=30, line_dash="dash", line_color="red", annotation_text="Lockdown Threshold (30)")
                fig_trust.update_layout(height=400, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig_trust, use_container_width=True)

                st.markdown("#### Turn Signal History")
                st.dataframe(df_filtered.tail(10), use_container_width=True)
            else:
                st.info("No session trust events recorded yet.")
        except Exception as e:
            st.warning(f"Error reading session database: {e}")
    else:
        st.info("Start `guardrail serve` and send requests to generate live trust trajectory data.")

# ------------------------------------------------------------------------------
# TAB 2: Attack Lineage Map
# ------------------------------------------------------------------------------
with tab2:
    st.markdown("### 2D Attack Lineage Projection (UMAP + HDBSCAN)")
    try:
        lineage_points = get_projection()
        if lineage_points:
            df_lineage = pd.DataFrame(lineage_points)
            fig_scatter = px.scatter(
                df_lineage,
                x="x",
                y="y",
                color="family_label",
                hover_data=["prompt_snippet", "cluster_id"],
                title="Blocked Attack Vector Clusters & Emerging Threat Projections",
                labels={"family_label": "Attack Family"},
            )
            fig_scatter.update_layout(height=450, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_scatter, use_container_width=True)
        else:
            st.info("No lineage projection points available.")
    except Exception as e:
        st.warning(f"Error loading lineage points: {e}")

# ------------------------------------------------------------------------------
# TAB 3: Security Audit Feed
# ------------------------------------------------------------------------------
with tab3:
    st.markdown("### Live Blocked Events & Security Explanations")
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            df_blocks = pd.read_sql_query(
                "SELECT session_id, timestamp, trust_score, signal FROM session_trust WHERE signal != 'benign' ORDER BY ROWID DESC",
                conn
            )
            conn.close()

            if not df_blocks.empty:
                st.dataframe(df_blocks, use_container_width=True)
            else:
                st.success("Zero security blocks recorded. All traffic is clean.")
        except Exception as e:
            st.warning(f"Error reading block log feed: {e}")
    else:
        st.info("No block events logged yet.")
