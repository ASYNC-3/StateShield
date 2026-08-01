from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers import chat, dashboard
from backend.config import BACKEND_HOST, BACKEND_PORT

app = FastAPI(
    title="AI Security Layer / Guardrail Proxy API",
    description="Stubbed Infrastructure Proxy Service for Prompt Security, Trust Evaluation, and Attack Lineage",
    version="0.1.0",
)

# Configure CORS Middleware for local Streamlit development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow requests from Streamlit UI running on localhost
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(chat.router)
app.include_router(dashboard.router)


@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint to verify backend server status."""
    return {"status": "ok", "service": "AI Security Layer Proxy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=BACKEND_HOST, port=BACKEND_PORT, reload=True)
