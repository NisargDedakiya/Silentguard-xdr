# Authentication (Module M4)

M4 introduces real user accounts and JWT authentication, replacing the single
shared admin token as the identity model. **The legacy `X-Admin-Token` still
works** so existing dashboards and scripts keep functioning during migration.

## Model

- **Users** (`users` table): email, PBKDF2-hashed password, role, active flag,
  lockout bookkeeping.
- **Refresh sessions** (`refresh_tokens` table): one row per issued refresh
  token keyed by its JWT `jti`, so sessions can be revoked (logout, rotation).
- **Roles** (`app/core/roles.py`): the seven enterprise roles. M4 stores the
  role and does coarse admin-capable checks; fine-grained per-permission
  enforcement lands in M5.

## Tokens

- **Access token** — short-lived (default 15 min, `SG_ACCESS_TTL`), HS256,
  carries `sub` (user id), `role`, `email`. Sent as `Authorization: Bearer …`.
- **Refresh token** — long-lived (default 14 days, `SG_REFRESH_TTL`), carries a
  `jti` persisted server-side. Refreshing **rotates** the token and revokes the
  old one.

Signing key: `SG_JWT_SECRET`. If unset, a 256-bit key is derived from
`SG_ADMIN_TOKEN` so the demo works zero-config — **set an independent secret in
production.**

## Endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/auth/login` | `{email, password}` | `{access_token, refresh_token, token_type, expires_in}` |
| POST | `/api/auth/refresh` | `{refresh_token}` | new token pair (old refresh revoked) |
| POST | `/api/auth/logout` | `{refresh_token}` | `{status: "logged_out"}` (idempotent) |
| GET | `/api/auth/me` | — (Bearer) | current `UserOut` |

## Protections

- **Password policy** — min length (`SG_PASSWORD_MIN_LENGTH`, default 12) plus a
  mixed-case + non-letter requirement, enforced at user creation.
- **Account lockout** — after `SG_LOGIN_MAX_ATTEMPTS` (default 5) failures the
  account locks for `SG_LOGIN_LOCKOUT_SECONDS` (default 15 min); a correct
  password during lockout returns `423 Locked`.
- **Rate limiting** — a per-client-IP sliding window (`SG_LOGIN_RATE_LIMIT` per
  `SG_LOGIN_RATE_WINDOW`s) returns `429`. In-process for now; moves to Redis in
  M20 for multi-worker correctness.
- **No account enumeration** — unknown email and wrong password both return the
  same generic `401`.
- **Audit** — logins are recorded in the audit log with `actor=user:<id>`.

## Bootstrapping the first admin

Set both env vars; on first startup (no users yet) a super-admin is created:

```bash
SG_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
SG_BOOTSTRAP_ADMIN_PASSWORD='a-strong-password-here'
```

## Admin API authorization

`require_admin` now accepts **either** a JWT access token (identifying a real
user; audit actor `user:<id>`) **or** the legacy `X-Admin-Token` (audit actor =
token fingerprint). Endpoints needing a guaranteed user identity use
`get_current_user`, which has no legacy fallback.

## Password hashing

PBKDF2-HMAC-SHA256 (210k rounds) from the standard library — no build
dependency, FIPS-friendly. The `PasswordHasher` boundary in
`app/core/security.py` is intentionally small so argon2/bcrypt can be swapped in
later without touching call sites.
