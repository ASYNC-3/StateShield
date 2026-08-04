import os
import sys
import subprocess
import typer
from typing import Optional
from pathlib import Path

from ai_guardrail.config import load_config, save_default_config

app = typer.Typer(
    name="guardrail",
    help="CLI-Installable AI Security Middleware & Guardrail Proxy",
    add_completion=False,
)


@app.command()
def init():
    """Initializes .guardrail/config.yaml, creates local storage, and seeds ChromaDB."""
    typer.secho("[ai-guardrail] Initializing middleware configuration...", fg=typer.colors.CYAN, bold=True)

    cfg_file = save_default_config()
    typer.secho(f"  + Configuration saved to {cfg_file.resolve()}", fg=typer.colors.GREEN)

    cfg = load_config()
    store_path = Path(cfg.get("storage", {}).get("path", ".guardrail/store"))
    store_path.mkdir(parents=True, exist_ok=True)
    typer.secho(f"  + Storage directory created at {store_path.resolve()}", fg=typer.colors.GREEN)

    seed_script = Path("backend/data/seed_chromadb.py")
    if seed_script.exists():
        typer.secho("  ... Seeding ChromaDB attack vector collection...", fg=typer.colors.YELLOW)
        res = subprocess.run([sys.executable, str(seed_script)], capture_output=True, text=True)
        if res.returncode == 0:
            typer.secho("  + ChromaDB attack vector database successfully seeded!", fg=typer.colors.GREEN)
        else:
            typer.secho(f"  ! ChromaDB seeding notice: {res.stderr[:200]}", fg=typer.colors.YELLOW)

    typer.secho("\nInitialization complete! Run 'guardrail serve' to start the proxy.", fg=typer.colors.GREEN, bold=True)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host address to bind the proxy server"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number for the proxy server"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload on code changes"),
):
    """Starts the OpenAI-compatible FastAPI reverse proxy server."""
    typer.secho(f"[ai-guardrail] Starting proxy server on http://{host}:{port} ...", fg=typer.colors.GREEN, bold=True)
    typer.secho(f"  OpenAI Endpoint: http://{host}:{port}/v1/chat/completions", fg=typer.colors.CYAN)

    import uvicorn
    uvicorn.run("ai_guardrail.proxy.server:app", host=host, port=port, reload=reload)


@app.command()
def dashboard(
    port: int = typer.Option(8501, "--port", "-p", help="Port number for the Streamlit analytics dashboard"),
):
    """Launches the analytics-only Streamlit security dashboard."""
    typer.secho(f"[ai-guardrail] Launching Analytics Dashboard on http://localhost:{port} ...", fg=typer.colors.CYAN, bold=True)

    dashboard_file = Path(__file__).parent / "dashboard" / "app_streamlit.py"
    env = os.environ.copy()
    src_path = str(Path(__file__).parent.parent.resolve())
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(dashboard_file), "--server.port", str(port)], env=env)


@app.command()
def test():
    """Runs the labeled adversarial evaluation corpus against the guardrail engine."""
    typer.secho("[ai-guardrail] Running adversarial evaluation suite...", fg=typer.colors.YELLOW, bold=True)

    eval_script = Path("backend/tests/eval_adversarial_set.py")
    if eval_script.exists():
        subprocess.run([sys.executable, str(eval_script)])
    else:
        typer.secho("  ! Evaluation script backend/tests/eval_adversarial_set.py not found.", fg=typer.colors.RED)


@app.command()
def status():
    """Displays current proxy configuration, upstream provider, and guardrail thresholds."""
    typer.secho("[ai-guardrail] Middleware Status", fg=typer.colors.MAGENTA, bold=True)

    cfg = load_config()
    upstream = cfg.get("upstream", {})
    judge = cfg.get("judge", {})
    thresholds = cfg.get("thresholds", {})

    typer.echo(f"  * Upstream Provider : {upstream.get('provider', 'openai')} ({upstream.get('base_url', '')})")
    typer.echo(f"  * Upstream Model    : {upstream.get('model', 'gpt-4o-mini')}")
    typer.echo(f"  * Judge Provider    : {judge.get('provider', 'groq')} ({judge.get('model', 'llama-3.3-70b-versatile')})")
    typer.echo(f"  * Tier-1 Block      : >= {thresholds.get('tier1_block', 0.85)}")
    typer.echo(f"  * Tier-1 Escalate   : >= {thresholds.get('tier1_escalate', 0.55)}")
    typer.echo(f"  * Trust Lockdown    : < {thresholds.get('trust_lockdown', 30)}")
    typer.echo(f"  * Storage Path      : {cfg.get('storage', {}).get('path', '.guardrail/store')}")


if __name__ == "__main__":
    app()
