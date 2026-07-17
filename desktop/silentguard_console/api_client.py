"""HTTP client for the SilentGuard server — the logic behind the desktop console.

Kept UI-free and fully testable: every call goes through ``_request`` on an
injectable ``requests.Session``, so tests drive it with a fake session and no
network. Auth supports either the admin token or an email/password login (JWT).
"""
import requests

TIMEOUT = 15


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ApiClient:
    def __init__(self, base_url: str, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.admin_token: str | None = None
        self.access_token: str | None = None

    # -- auth -------------------------------------------------------------
    def _headers(self) -> dict:
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        if self.admin_token:
            return {"X-Admin-Token": self.admin_token}
        return {}

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{path}"
        headers = {**self._headers(), **kwargs.pop("headers", {})}
        try:
            resp = self.session.request(method, url, headers=headers, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise ApiError(0, f"Cannot reach server: {exc}") from exc
        if resp.status_code >= 400:
            detail = _safe_detail(resp)
            raise ApiError(resp.status_code, detail)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    def login_admin(self, token: str) -> bool:
        self.admin_token = token
        self.access_token = None
        self._request("GET", "/api/admin/entitlements")  # validates the token
        return True

    def login_key(self, admin_key: str) -> dict:
        """Log in with an org admin key (from provisioning)."""
        data = self._request("POST", "/api/auth/key-login", json={"admin_key": admin_key})
        self.access_token = data["access_token"]
        self.admin_token = None
        return data

    def login_user(self, email: str, password: str, mfa_code: str | None = None) -> dict:
        body = {"email": email, "password": password}
        if mfa_code:
            body["mfa_code"] = mfa_code
        data = self._request("POST", "/api/auth/login", json=body)
        self.access_token = data["access_token"]
        self.admin_token = None
        return data

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    # -- read -------------------------------------------------------------
    def entitlements(self) -> dict:
        return self._request("GET", "/api/admin/entitlements")

    def devices(self) -> list:
        return self._request("GET", "/api/admin/devices")

    def detections(self, limit: int = 200) -> list:
        return self._request("GET", f"/api/admin/detections?limit={limit}")

    def events(self, limit: int = 200) -> list:
        return self._request("GET", f"/api/admin/events?limit={limit}")

    def blocklist(self) -> list:
        return self._request("GET", "/api/admin/blocklist")

    def members(self) -> list:
        return self._request("GET", "/api/admin/users")

    def organizations(self) -> list:
        return self._request("GET", "/api/admin/organizations")

    # -- actions ----------------------------------------------------------
    def add_block(self, kind: str, value: str) -> dict:
        return self._request("POST", "/api/admin/blocklist",
                             json={"kind": kind, "value": value})

    def remove_block(self, entry_id: int) -> None:
        self._request("DELETE", f"/api/admin/blocklist/{entry_id}")

    def isolate(self, device_id: str, isolate: bool) -> None:
        action = "isolate" if isolate else "release"
        self._request("POST", f"/api/admin/devices/{device_id}/{action}")

    def invite(self, email: str, role: str) -> dict:
        return self._request("POST", "/api/admin/users/invite",
                             json={"email": email, "role": role})


def _safe_detail(resp) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict) and "detail" in body:
            return str(body["detail"])
    except ValueError:
        pass
    return f"HTTP {resp.status_code}"
