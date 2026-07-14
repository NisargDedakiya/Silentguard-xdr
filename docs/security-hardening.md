# Security Hardening (Module M21)

Concrete hardening across the platform. Several controls landed in earlier
modules; this documents the full posture and the M21 additions.

## Already in place (earlier modules)

- **Secure response headers + body-size limit** (M1 middleware).
- **SQL injection**: all DB access is via SQLAlchemy ORM / bound parameters — no
  string-built SQL.
- **XSS/CSRF**: the API is JSON-only and authenticated with bearer tokens /
  headers (no cookies, no server-rendered HTML), so classic XSS/CSRF vectors do
  not apply to the API surface. The dashboard (M19) will add its own CSP.
- **Authentication**: constant-time token comparison, argon2/PBKDF2 hashing,
  lockout, rate limiting, hashed reset tokens (M4/M7).
- **Command injection**: agent OS calls pass argument **lists** to `subprocess`
  (never `shell=True`), so shell metacharacters are not interpreted.

## Added in M21

### SSRF protection (`app/core/ssrf.py`)

Admin-configured integration/webhook destinations are validated before the
server ever requests them:

- scheme restricted to http/https;
- host must resolve, and **every** resolved address must be routable —
  loopback, link-local (incl. the `169.254.169.254` cloud-metadata endpoint),
  multicast, reserved, and unspecified addresses are always rejected;
- private RFC1918 ranges are permitted by default (internal SIEM is legitimate)
  and can be blocked with `SG_BLOCK_PRIVATE_INTEGRATIONS=1`.

Enforced at integration creation (`400` on an unsafe URL/host).

### Production secret checks

On startup in production (`SG_ENV=production`), the server logs prominent
warnings if it detects demo defaults: default admin/enroll tokens, an unset
`SG_JWT_SECRET`, or `SG_CORS_ORIGINS=*`.

### SBOM & dependency scanning

- `scripts/generate_sbom.py` emits a CycloneDX-style JSON SBOM from the
  installed packages (no third-party deps):
  `python scripts/generate_sbom.py > sbom.json`.
- Dependency vulnerability scanning: run `pip-audit` (or `safety`) in CI against
  `server/requirements.txt` and `agent/requirements.txt`.

## Roadmap (deferred)

Full secrets-manager integration (Vault/KMS), signed agent-update packages
(the M14 `remote_update` action currently acknowledges only), and automated
dependency-scan gating are tracked for later hardening passes.
