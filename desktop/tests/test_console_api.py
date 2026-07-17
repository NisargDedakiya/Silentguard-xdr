"""Tests for the desktop console's API client (no network — fake session)."""
import json

import pytest

from silentguard_console.api_client import ApiClient, ApiError


class FakeResp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data
        self.content = json.dumps(data).encode() if data is not None else b""

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class FakeSession:
    def __init__(self):
        self.calls = []
        self.handler = lambda method, url, kw: FakeResp(200, {})

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        return self.handler(method, url, kw)


def _client():
    s = FakeSession()
    return ApiClient("http://srv:8000/", session=s), s


# -- auth -----------------------------------------------------------------
def test_login_admin_sets_token_and_validates():
    c, s = _client()
    s.handler = lambda m, u, kw: FakeResp(200, {"plan": "enterprise"})
    assert c.login_admin("secret") is True
    call = s.calls[-1]
    assert call["url"] == "http://srv:8000/api/admin/entitlements"
    assert call["headers"]["X-Admin-Token"] == "secret"


def test_login_admin_bad_token_raises():
    c, s = _client()
    s.handler = lambda m, u, kw: FakeResp(401, {"detail": "no"})
    with pytest.raises(ApiError) as e:
        c.login_admin("wrong")
    assert e.value.status == 401


def test_login_user_stores_bearer():
    c, s = _client()
    s.handler = lambda m, u, kw: FakeResp(200, {"access_token": "jwt123", "refresh_token": "r"})
    c.login_user("me@x.com", "pw")
    assert c.access_token == "jwt123"
    # subsequent call uses the bearer header
    s.handler = lambda m, u, kw: FakeResp(200, [])
    c.devices()
    assert s.calls[-1]["headers"]["Authorization"] == "Bearer jwt123"


# -- reads ----------------------------------------------------------------
def test_read_endpoints_hit_right_paths():
    c, s = _client()
    c.admin_token = "t"
    s.handler = lambda m, u, kw: FakeResp(200, [])
    c.devices(); assert s.calls[-1]["url"].endswith("/api/admin/devices")
    c.detections(); assert "/api/admin/detections" in s.calls[-1]["url"]
    c.blocklist(); assert s.calls[-1]["url"].endswith("/api/admin/blocklist")
    c.members(); assert s.calls[-1]["url"].endswith("/api/admin/users")
    c.entitlements(); assert s.calls[-1]["url"].endswith("/api/admin/entitlements")


# -- actions --------------------------------------------------------------
def test_add_and_remove_block():
    c, s = _client()
    c.admin_token = "t"
    s.handler = lambda m, u, kw: FakeResp(201, {"id": 5})
    c.add_block("domain", "evil.example")
    add = s.calls[-1]
    assert add["method"] == "POST" and add["json"] == {"kind": "domain", "value": "evil.example"}
    s.handler = lambda m, u, kw: FakeResp(204)
    c.remove_block(5)
    assert s.calls[-1]["method"] == "DELETE" and s.calls[-1]["url"].endswith("/blocklist/5")


def test_isolate_calls_action():
    c, s = _client()
    c.admin_token = "t"
    s.handler = lambda m, u, kw: FakeResp(200, {})
    c.isolate("dev-1", True)
    assert s.calls[-1]["url"].endswith("/api/admin/devices/dev-1/isolate")
    c.isolate("dev-1", False)
    assert s.calls[-1]["url"].endswith("/api/admin/devices/dev-1/release")


def test_error_detail_propagated():
    c, s = _client()
    c.admin_token = "t"
    s.handler = lambda m, u, kw: FakeResp(402, {"detail": "Integrations require the Team plan"})
    with pytest.raises(ApiError) as e:
        c.add_block("domain", "x")
    assert e.value.status == 402 and "Team plan" in e.value.message


def test_login_key_stores_bearer():
    c, s = _client()
    s.handler = lambda m, u, kw: FakeResp(200, {"access_token": "keyjwt", "refresh_token": "r"})
    c.login_key("sgk_abc")
    call = s.calls[-1]
    assert call["url"].endswith("/api/auth/key-login")
    assert call["json"] == {"admin_key": "sgk_abc"}
    assert c.access_token == "keyjwt"
