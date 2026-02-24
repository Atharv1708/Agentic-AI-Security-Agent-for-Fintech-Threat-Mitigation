# app/api/websocket.py

import asyncio
import json
import logging
import time
from typing import Set
from fastapi import WebSocket, WebSocketDisconnect, APIRouter

from ..state import app_state
from ..config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """
    Manages active WebSocket connections.
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            f"WebSocket connected: {websocket.client} | Total: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(
            f"WebSocket disconnected: {websocket.client} | Total: {len(self.active_connections)}"
        )

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return

        try:
            message_json = json.dumps(message, default=str)
        except Exception as e:
            logger.error(f"Message serialization failed: {e}")
            return

        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                logger.warning(
                    f"Failed to send WS message: {type(e).__name__} - {e}"
                )
                disconnected.add(connection)

        self.active_connections -= disconnected


manager = ConnectionManager()


# ================================
# 🔥 ACTUAL WEBSOCKET ENDPOINT
# ================================
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket unexpected error: {e}")
        manager.disconnect(websocket)


# ================================
# 🔥 Metrics Broadcast Loop
# ================================
async def broadcast_metrics_periodically():
    logger.info("Metrics broadcast task started.")
    while True:
        try:
            await asyncio.sleep(5)

            now = time.time()
            cutoff = now - settings.TIME_WINDOW_SECONDS

            while app_state.request_timestamps and app_state.request_timestamps[0] < cutoff:
                app_state.request_timestamps.popleft()

            while app_state.error_event_timestamps and app_state.error_event_timestamps[0] < cutoff:
                app_state.error_event_timestamps.popleft()

            requests_per_minute = len(app_state.request_timestamps)
            errors_per_minute = len(app_state.error_event_timestamps)

            llm_state = app_state.llm_circuit_state

            if llm_state.is_open:
                llm_status = "OPEN"
            elif llm_state.failure_count > 0:
                llm_status = "DEGRADED"
            else:
                llm_status = "ACTIVE"

            metrics = {
                "type": "metrics_update",
                "requests_per_minute": requests_per_minute,
                "error_events_per_minute": errors_per_minute,
                "active_ws_clients": len(manager.active_connections),
                "llm_status": llm_status,
            }

            await manager.broadcast(metrics)

        except asyncio.CancelledError:
            logger.info("Metrics broadcast task cancelled.")
            break
        except Exception as e:
            logger.error(f"Metrics loop error: {e}", exc_info=True)
            await asyncio.sleep(5)
