"""Host / domain matching helpers (subdomain-aware blocking).

Blocking a domain must cover **all of its subdomains** — blocking ``example.com``
blocks ``evil.example.com`` and ``a.b.example.com`` too, both for outbound
requests the endpoint would send and for anything referencing that domain. These
helpers give one dot-boundary-safe, URL-aware definition of "does this host fall
under a blocked domain" used everywhere the software makes that decision.

The dot boundary matters for security: ``notexample.com`` must NOT match
``example.com`` (only a true subdomain or the domain itself does), and
``example.com.evil.com`` must NOT match ``example.com`` either.
"""
from urllib.parse import urlsplit


def extract_host(value: str) -> str:
    """Reduce a domain or URL to its bare lowercase host.

    ``https://Sub.Example.COM:8443/p?x=1`` -> ``sub.example.com``;
    ``evil.example.com.`` -> ``evil.example.com``; ``user@host:22`` -> ``host``.
    """
    if not value:
        return ""
    v = str(value).strip().lower().rstrip(".")
    if not v:
        return ""
    if "://" not in v:
        v = "//" + v  # let urlsplit parse a bare host[:port]/path as a netloc
    return urlsplit(v).hostname or ""


def parent_domains(host: str) -> list[str]:
    """Every registrable suffix of ``host`` including itself, e.g.
    ``a.b.example.com`` -> ``[a.b.example.com, b.example.com, example.com, com]``.
    """
    host = extract_host(host)
    if not host:
        return []
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def host_matches_domain(host: str, blocked: str) -> bool:
    """True when ``host`` is ``blocked`` or a subdomain of it."""
    host = extract_host(host)
    blocked = extract_host(blocked)
    if not host or not blocked:
        return False
    return host == blocked or host.endswith("." + blocked)


def host_matches_any(host: str, blocked) -> str | None:
    """Return the blocked domain that ``host`` falls under, or None.

    ``blocked`` is any iterable of domains; matching is done via suffix set
    intersection so it stays cheap even for large block lists.
    """
    blocked_set = {extract_host(b) for b in blocked if b}
    blocked_set.discard("")
    for suffix in parent_domains(host):
        if suffix in blocked_set:
            return suffix
    return None
