# app/main.py

import logging
import asyncio
import httpx
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

from .state import app_state
from .api.endpoints import router as api_router
from .api.websocket import router as websocket_router
from .api.websocket import broadcast_metrics_periodically

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("AI-Security-Agent")


@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info("Application starting...")

    app_state.http_client = httpx.AsyncClient()

    app.state.metrics_task = asyncio.create_task(
        broadcast_metrics_periodically()
    )

    yield

    logger.info("Application shutting down...")

    app.state.metrics_task.cancel()

    await app_state.http_client.aclose()


app = FastAPI(
    title="AI Security Agent",
    version="1.0.0",
    lifespan=lifespan,
)

# 🔥 ROUTES
app.include_router(api_router)
app.include_router(websocket_router)

# 🔥 STATIC FILES
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "static"))

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    logger.info(f"Mounted static at: {STATIC_DIR}")
else:
    logger.warning("Static folder not found")

@app.get("/", include_in_schema=False)
async def serve_frontend():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return PlainTextResponse("index.html not found", status_code=404)


@app.get("/health")
async def health():
    return {"status": "ok"}
