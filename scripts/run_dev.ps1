# Run script to start FastAPI backend and Streamlit frontend concurrently on Windows

Write-Host "Starting AI Security Layer FastAPI Backend on http://localhost:8000 ..." -ForegroundColor Green
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"

Start-Sleep -Seconds 2

Write-Host "Starting Streamlit Security Console UI on http://localhost:8501 ..." -ForegroundColor Cyan
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "streamlit run frontend/app_streamlit.py --server.port 8501"
