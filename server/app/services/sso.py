"""SSO via OpenID Connect (v1.4).

Authorization-code OIDC login so an enterprise can front SilentGuard with its own
IdP (Okta, Entra ID, Google Workspace, Keycloak, …) — the IdP owns authentication
(including its own MFA), and SilentGuard maps the verified identity onto a local
user and issues its normal JWT session.

Flow:

1. ``begin_login()`` builds the IdP authorization URL, carrying a **signed state**
   (a short-lived HS256 token binding a nonce) so no server-side session store is
   needed and the callback state can't be forged.
2. ``login()`` handles the callback: exchange the code at the token endpoint,
   verify the ``id_token`` signature against the IdP's JWKS (RS256/ES256) plus
   issuer/audience/nonce, then provision-or-match a local user and issue tokens.

The HTTP boundary uses ``urllib`` (like `integrations.py`) so it is easily
mocked; tests stub ``fetch_claims`` and never touch the network.
"""
import json
import secrets
import time
import urllib.parse
import urllib.request

import jwt

from ..core.config import settings
from ..core.logging import get_logger
from ..models import User
from . import auth_service

log = get_logger("silentguard.sso")

TIMEOUT = 10
_discovery_cache: dict = {}


class SSOError(RuntimeError):
    """OIDC login could not be completed."""


def is_available() -> bool:
    return settings.oidc_available


# -- HTTP helpers (mockable) ----------------------------------------------
def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def discovery() -> dict:
    """Fetch and cache the IdP's OpenID discovery document."""
    if not _discovery_cache:
        url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        _discovery_cache.update(_get_json(url))
    return _discovery_cache


# -- signed state ---------------------------------------------------------
def _state_token(nonce: str) -> str:
    return jwt.encode(
        {"nonce": nonce, "typ": "oidc_state", "exp": int(time.time()) + 600},
        settings.effective_jwt_secret, algorithm="HS256")


def _verify_state(state: str) -> str:
    try:
        payload = jwt.decode(state, settings.effective_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise SSOError("invalid or expired SSO state") from exc
    if payload.get("typ") != "oidc_state":
        raise SSOError("invalid SSO state")
    return payload.get("nonce", "")


# -- flow -----------------------------------------------------------------
def begin_login() -> str:
    if not is_available():
        raise SSOError("SSO is not configured")
    nonce = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": _state_token(nonce),
        "nonce": nonce,
    }
    return discovery()["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)


def _verify_id_token(id_token: str, disc: dict, nonce: str) -> dict:
    try:
        signing_key = jwt.PyJWKClient(disc["jwks_uri"]).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token, signing_key.key, algorithms=["RS256", "ES256"],
            audience=settings.oidc_client_id, issuer=disc.get("issuer"))
    except jwt.PyJWTError as exc:
        raise SSOError(f"id_token verification failed: {exc}") from exc
    if nonce and claims.get("nonce") not in (None, nonce):
        raise SSOError("SSO nonce mismatch")
    return claims


def fetch_claims(code: str, state: str) -> dict:
    """Exchange the auth code and return the verified id_token claims."""
    nonce = _verify_state(state)
    disc = discovery()
    token_resp = _post_form(disc["token_endpoint"], {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
    })
    id_token = token_resp.get("id_token")
    if not id_token:
        raise SSOError("no id_token in token response")
    return _verify_id_token(id_token, disc, nonce)


def provision_and_issue(db, claims: dict) -> dict:
    """Map verified OIDC claims to a local user (creating one on first sight)
    and issue SilentGuard tokens."""
    email = (claims.get("email") or "").strip().lower()
    if not email:
        raise SSOError("no email in SSO claims")
    if claims.get("email_verified") is False:
        raise SSOError("email not verified by the identity provider")
    domain = settings.oidc_allowed_domain.strip().lower()
    if domain and not email.endswith("@" + domain):
        raise SSOError("email domain not permitted for SSO")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        user = auth_service.create_user(
            db, email, secrets.token_urlsafe(24), settings.oidc_default_role)
        user.email_verified = True
        db.commit()
        log.info("sso user provisioned", extra={"email": email})
    if not user.is_active:
        raise SSOError("account is disabled")
    return auth_service.issue_tokens(db, user)


def login(db, code: str, state: str) -> dict:
    if not is_available():
        raise SSOError("SSO is not configured")
    claims = fetch_claims(code, state)
    return provision_and_issue(db, claims)
