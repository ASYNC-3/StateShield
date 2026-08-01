#!/usr/bin/env bash
# Shell script to launch FastAPI server and Streamlit frontend concurrently

echo "Starting FastAPI backend server on http://localhost:8000..."
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

sleep 2

echo "Starting Streamlit dashboard UI on http://localhost:8501..."
streamlit run frontend/app_streamlit.py --server.port 8501 &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
