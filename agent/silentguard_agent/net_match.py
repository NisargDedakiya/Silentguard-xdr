"""Host / domain matching helpers (agent-side, subdomain-aware).

Mirrors the server's ``app/core/netmatch`` so both sides agree on what "under a
blocked domain" means: a host matches a blocked domain if it equals it or is a
subdomain of it (``example.com`` covers ``evil.example.com``), with a dot
boundary so ``notexample.com`` never matches ``example.com``.
"""
from urllib.parse import urlsplit


def extract_host(value: str) -> str:
    """Reduce a domain or URL to its bare lowercase host."""
    if not value:
        return ""
    v = str(value).strip().lower().rstrip(".")
    if not v:
        return ""
    if "://" not in v:
        v = "//" + v
    return urlsplit(v).hostname or ""


def parent_domains(host: str) -> list[str]:
    host = extract_host(host)
    if not host:
        return []
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def host_matches_domain(host: str, blocked: str) -> bool:
    host = extract_host(host)
    blocked = extract_host(blocked)
    if not host or not blocked:
        return False
    return host == blocked or host.endswith("." + blocked)


def host_matches_any(host: str, blocked) -> str | None:
    """Return the blocked domain ``host`` falls under, or None."""
    blocked_set = {extract_host(b) for b in blocked if b}
    blocked_set.discard("")
    for suffix in parent_domains(host):
        if suffix in blocked_set:
            return suffix
    return None
