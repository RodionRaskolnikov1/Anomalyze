import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status

from app.core.config import settings
from app.core.ws_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

_PING_INTERVAL_SECONDS = 30
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@router.websocket("/ws/alerts")
async def websocket_alerts(
    websocket: WebSocket,
    api_key:      str = Query(..., description="Your API key (required)."),
    min_severity: str = Query("HIGH", description="Minimum severity to receive: CRITICAL | HIGH | MEDIUM | LOW"),
):
    
    if api_key != settings.API_KEY:
        await websocket.close(code=1008)  # 1008 = Policy Violation
        logger.warning("WebSocket rejected — invalid API key.")
        return

    if min_severity not in _VALID_SEVERITIES:
        await websocket.close(code=1008)
        logger.warning("WebSocket rejected — invalid min_severity: %s", min_severity)
        return

    await manager.connect(websocket)

    await websocket.send_text(json.dumps({
        "type":         "connected",
        "message":      "Connected to Anomalyze live alert stream.",
        "min_severity": min_severity,
        "active_connections": manager.active_connections,
    }))

    try:
       
        while True:
            await asyncio.sleep(_PING_INTERVAL_SECONDS)
            await websocket.send_text(json.dumps({"type": "ping"}))

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected cleanly.")

    except Exception:
        manager.disconnect(websocket)
        logger.exception("WebSocket connection closed with error.")