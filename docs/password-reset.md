# Password Reset & Email Verification (Module M7)

Completes the M4 authentication surface with self-service password reset and
email verification. Tokens are single-use, time-limited, and **stored only as a
SHA-256 hash** — the raw token is emailed to the user.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/password-reset/request` | public | issue a reset token (emailed) |
| POST | `/api/auth/password-reset/confirm` | public | set a new password with the token |
| POST | `/api/auth/verify-email/request` | Bearer | issue an email-verification token |
| POST | `/api/auth/verify-email/confirm` | public | mark the email verified |

## Behavior

- **No account enumeration** — the reset-request endpoint always returns 200
  whether or not the email exists.
- **Single-use / expiring** — reset tokens live `SG_RESET_TTL` (default 1h),
  verification tokens `SG_VERIFY_TTL` (default 24h). Issuing a new token of the
  same purpose invalidates any outstanding one.
- **Session revocation** — a successful password reset revokes all of the
  user's refresh sessions and clears any account lockout.
- **Password policy** — the M4 policy is enforced on the new password.
- **Rate limiting** — reset requests share the login rate limiter (per IP).

## Email delivery

`app/services/email.py` sends via the existing `SG_SMTP_*` settings, fire-and-
forget; failures are logged and swallowed so the flow never breaks. When SMTP is
not configured the message is logged instead.

## Token exposure (dev convenience)

Outside production (`SG_ENV` ≠ production) or when `SG_EXPOSE_AUTH_TOKENS=1`, the
request endpoints echo the raw token in the JSON response so local development
and tests don't need a mailbox. In production the token is delivered by email
only.
