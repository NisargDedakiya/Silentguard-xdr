"""TLS certificate pinning for the agent (v1.4).

Pins the management server's certificate by its SHA-256 fingerprint so a
man-in-the-middle with a valid-but-rogue CA-issued cert (corporate proxy,
compromised CA) cannot impersonate the server. Enforcement is delegated to
urllib3's well-tested ``assert_fingerprint`` on the connection pool, mounted on
the agent's HTTP session; a mismatch raises an SSL error and the request fails
closed.

Configure ``SG_PIN_SHA256`` with the server leaf certificate's SHA-256
fingerprint (hex, colons optional, case-insensitive). Compute it with, e.g.::

    openssl s_client -connect host:443 </dev/null 2>/dev/null \\
      | openssl x509 -noout -fingerprint -sha256

Leave it unset to keep the default CA-based verification only.
"""
import logging

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("silentguard.pinning")


def normalize_pin(value: str) -> str:
    """Lower-case, strip colons/whitespace so ``AA:BB`` == ``aabb``."""
    return value.replace(":", "").strip().lower()


def parse_pins(raw: str) -> list[str]:
    return [normalize_pin(p) for p in (raw or "").split(",") if p.strip()]


class FingerprintAdapter(HTTPAdapter):
    """A requests adapter that asserts the peer cert's SHA-256 fingerprint."""

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        return super().init_poolmanager(*args, **kwargs)


def build_session(config) -> requests.Session:
    """A requests Session with certificate pinning applied when configured."""
    session = requests.Session()
    pins = parse_pins(getattr(config, "pin_sha256", "") or "")
    if not pins:
        return session
    if len(pins) > 1:
        # urllib3 asserts a single fingerprint per pool; use the first and warn
        # so a rotation window (dual pins) doesn't silently pin only one.
        log.warning("Multiple certificate pins set; enforcing the first "
                    "(configure one active pin at a time)")
    session.mount("https://", FingerprintAdapter(pins[0]))
    log.info("Certificate pinning enabled for the management server")
    return session
