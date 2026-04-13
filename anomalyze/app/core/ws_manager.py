import json
import logging
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class ConnectionManager:

    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)
        logger.info(
            "WebSocket client connected. Active connections: %d",
            len(self._connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)
        logger.info(
            "WebSocket client disconnected. Active connections: %d",
            len(self._connections),
        )

    async def broadcast(self, alert_data: dict, min_severity: str = "HIGH") -> None:
        
        severity = alert_data.get("severity", "LOW")
        min_rank  = _SEVERITY_RANK.get(min_severity, 1)
        alert_rank = _SEVERITY_RANK.get(severity, 3)

        if alert_rank > min_rank:
            # Below threshold — don't broadcast
            return

        if not self._connections:
            return

        payload = json.dumps(alert_data, default=str)

        dead: Set[WebSocket] = set()

        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        for ws in dead:
            self.disconnect(ws)

        if len(self._connections) > 0:
            logger.debug(
                "Broadcast alert | severity=%s | rule=%s | clients=%d",
                severity,
                alert_data.get("rule_name"),
                len(self._connections),
            )

    @property
    def active_connections(self) -> int:
        return len(self._connections)


manager = ConnectionManager()