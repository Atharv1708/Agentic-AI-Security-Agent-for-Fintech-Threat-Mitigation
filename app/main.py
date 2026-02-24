# app/main.py

import logging
import asyncio
import httpx
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

# Project Imports
from .config import settings
from .state import app_state
from .api.endpoints import router as api_router
from .services.monitoring import stop_all_monitoring
from .api.websocket import broadcast_metrics_periodically

# --------------------------------------------------
# Logging Configuration
# --------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("AI-Security-Agent")

# --------------------------------------------------
# Ollama Connectivity Check (Safe for Cloud)
# --------------------------------------------------


async def check_ollama_connection(client: httpx.AsyncClient, url: str):
    """
    Safe Ollama health check.
    Will NOT crash app if Ollama is offline.
    """

    if not url:
        logger.warning("OLLAMA_URL not configured. Skipping check.")
        return False

    health_url = url.split("/api/")[0] if "/api/" in url else url

    if not health_url.endswith("/"):
        health_url += "/"

    try:
        logger.info(f"Checking Ollama at: {health_url}")
        response = await client.get(health_url, timeout=5.0)
        response.raise_for_status()
        logger.info("Ollama connection successful.")
        return True

    except Exception as e:
        logger.warning(f"Ollama check failed (non-fatal): {e}")
        return False


# --------------------------------------------------
# Lifespan (Startup & Shutdown)
# --------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info("Application starting up...")

    # ---- Create shared HTTP client ----
    timeout = httpx.Timeout(15.0, connect=5.0)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)

    app_state.http_client = httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        verify=False,
    )

    logger.info("Shared HTTP client initialized.")

    # ---- Optional Ollama health check ----
    if os.environ.get("ENABLE_OLLAMA", "false").lower() == "true":
        await check_ollama_connection(app_state.http_client, settings.OLLAMA_URL)
    else:
        logger.info("Ollama check disabled.")

    # ---- Start Metrics Broadcaster ----
    app.state.metrics_task = asyncio.create_task(
        broadcast_metrics_periodically(),
        name="metrics_broadcaster"
    )

    logger.info("Metrics broadcasting started.")
    logger.info("Startup complete.")

    yield  # Application runs here

    # ---- Shutdown Logic ----
    logger.info("Shutting down application...")

    if hasattr(app.state, "metrics_task"):
        app.state.metrics_task.cancel()
        try:
            await app.state.metrics_task
        except asyncio.CancelledError:
            logger.info("Metrics task cancelled cleanly.")

    await stop_all_monitoring()

    if app_state.http_client:
        await app_state.http_client.aclose()
        logger.info("HTTP client closed.")

    logger.info("Shutdown complete.")


# --------------------------------------------------
# Create FastAPI App
# --------------------------------------------------

app = FastAPI(
    title="AI Security Agent",
    description="Cloud-hosted autonomous AI threat detection system.",
    version="1.0.0-production",
    lifespan=lifespan,
)

# --------------------------------------------------
# API Routes
# --------------------------------------------------

app.include_router(api_router)

# --------------------------------------------------
# Static Files (Cloud-Safe Path)
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "static"))

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    logger.info(f"Mounted static files from: {STATIC_DIR}")
else:
    logger.warning(f"Static directory not found at: {STATIC_DIR}")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    index_path = os.path.join(STATIC_DIR, "index.html")

    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    else:
        logger.error("index.html not found.")
        return PlainTextResponse(
            "Frontend file (index.html) not found.",
            status_code=404
        )


# --------------------------------------------------
# Health Endpoint (Cloud Monitoring)
# --------------------------------------------------

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok"}
