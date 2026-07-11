"""Tests for /api/ws authentication: bad or missing tokens are rejected with
a policy-violation close; valid tokens (query param or first message) connect."""
import pytest
from starlette.websockets import WebSocketDisconnect

from app.auth import ADMIN_TOKEN

POLICY_VIOLATION = 1008


def test_ws_rejects_bad_query_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/ws?token=wrong-token") as ws:
            ws.receive_text()
    assert exc.value.code == POLICY_VIOLATION


def test_ws_rejects_bad_first_message_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/ws") as ws:
            ws.send_text("wrong-token")
            ws.receive_text()
    assert exc.value.code == POLICY_VIOLATION


def test_ws_accepts_valid_query_token(client, enrolled_device):
    with client.websocket_connect(f"/api/ws?token={ADMIN_TOKEN}") as ws:
        # An authenticated socket receives hub broadcasts (enrollment event).
        client.post(
            "/api/agent/telemetry",
            json={"events": [{"source": "agent", "action": "test", "summary": "ping"}]},
            headers=enrolled_device["headers"],
        )
        msg = ws.receive_json()
        assert msg["type"] == "threat_event"
        assert msg["summary"] == "ping"


def test_ws_accepts_valid_first_message_token(client, enrolled_device):
    with client.websocket_connect("/api/ws") as ws:
        ws.send_text(ADMIN_TOKEN)
        client.post(
            "/api/agent/telemetry",
            json={"events": [{"source": "agent", "action": "test", "summary": "ping2"}]},
            headers=enrolled_device["headers"],
        )
        msg = ws.receive_json()
        assert msg["type"] == "threat_event"
        assert msg["summary"] == "ping2"
