# SSO via OpenID Connect (v1.4)

Front SilentGuard with your enterprise IdP (Okta, Entra ID, Google Workspace,
Keycloak, …) using the OIDC authorization-code flow. The IdP owns authentication
— including its own MFA and conditional-access policies — and SilentGuard maps
the verified identity onto a local user, then issues its normal JWT session.

## Configuration

| Variable | Purpose |
|---|---|
| `SG_OIDC_ENABLED` | Master switch |
| `SG_OIDC_ISSUER` | IdP base URL (discovery at `/.well-known/openid-configuration`) |
| `SG_OIDC_CLIENT_ID` / `SG_OIDC_CLIENT_SECRET` | Registered client credentials |
| `SG_OIDC_REDIRECT_URI` | Your `…/api/auth/sso/callback` URL, registered at the IdP |
| `SG_OIDC_SCOPES` | Requested scopes (default `openid email profile`) |
| `SG_OIDC_DEFAULT_ROLE` | Role for a first-seen SSO user (default `read_only`) |
| `SG_OIDC_ALLOWED_DOMAIN` | Optional email-domain allowlist (e.g. `example.com`) |

SSO is available only when the switch and all four core values are set
(`settings.oidc_available`); otherwise the endpoints return `503`.

## Flow

1. **`GET /api/auth/sso/login`** → `{ "authorization_url": "https://idp/authorize?..." }`
   The URL carries a **signed state** — a short-lived HS256 token binding a nonce
   — so no server-side session store is needed and the callback state cannot be
   forged. Redirect the browser there.
2. The IdP authenticates the user and redirects back to
   **`GET /api/auth/sso/callback?code=…&state=…`**, which:
   - verifies the signed state (extracting the nonce),
   - exchanges the code at the token endpoint,
   - verifies the `id_token` signature against the IdP's **JWKS** (RS256/ES256)
     plus issuer, audience, and nonce,
   - provisions-or-matches a local user by email, and
   - returns a standard `TokenResponse` (access + refresh JWT).

## User mapping

- The verified `email` claim keys the local user. A first-seen email is
  auto-provisioned with `SG_OIDC_DEFAULT_ROLE` and marked email-verified; an
  existing user keeps its role (RBAC is managed in SilentGuard, not the IdP).
- An IdP-reported `email_verified: false` is rejected.
- With `SG_OIDC_ALLOWED_DOMAIN` set, only emails in that domain may log in.
- A disabled local account is refused even with a valid IdP assertion.

Errors map to `401` (login failed) or `503` (not configured); the `id_token`
signature/issuer/audience/nonce are all validated, so a forged or misdirected
token is rejected.

## Testing

`server/tests/test_sso.py` mocks the network and id_token verification to cover
signed-state round-trip and rejection, authorize-URL construction, user
provisioning (new/existing/missing-email/unverified/domain allowlist), and the
`login`/`callback` endpoints (URL, success, `SSOError`→401, unconfigured→503).
