"""SSRF protection for admin-supplied outbound URLs (M21).

Integration/webhook destinations are configured by admins and then fetched by
the server, which is a classic SSRF sink. This validates a URL before it is
ever requested:

* scheme must be http/https;
* the host must resolve, and **every** resolved address must be routable —
  loopback, link-local (incl. the 169.254.169.254 cloud-metadata endpoint),
  multicast, reserved, and unspecified addresses are always rejected;
* private ranges (RFC1918) are allowed by default (internal SIEM targets are
  legitimate) but can be blocked with ``block_private=True``.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


def _addr_ok(ip: str, block_private: bool) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast \
            or addr.is_reserved or addr.is_unspecified:
        return False
    if block_private and addr.is_private:
        return False
    return True


def is_safe_url(url: str, block_private: bool = False) -> bool:
    parsed = urlparse(url or "")
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 0,
                                   proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    return all(_addr_ok(info[4][0], block_private) for info in infos)


def is_safe_host(host: str, block_private: bool = False) -> bool:
    """Validate a bare host (e.g. a syslog target) the same way."""
    return is_safe_url(f"http://{host}", block_private=block_private)
