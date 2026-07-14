# Domain / URL Blocking — Subdomain-Aware

Blocking a domain covers **the domain and all of its subdomains**. Blocking
`example.com` also blocks `evil.example.com` and `a.b.example.com` — both what
the endpoint would *send* to and anything referencing that domain — while never
matching look-alikes like `notexample.com` or `example.com.evil.com` (a strict
dot boundary).

## What you configure

Add a blocklist entry of kind `domain`:

```
POST /api/admin/blocklist   { "kind": "domain", "value": "example.com" }
```

A full URL is accepted and reduced to its host, so
`https://evil.example.com/malware?x=1` is stored as `evil.example.com`. Matching
is case-insensitive and ignores scheme, port, path, and a trailing dot.

## Two enforcement layers

Blocking works at two layers that together cover subdomains:

### 1. Server-side detection & response (covers all subdomains)

The detection engine matches every observed domain/URL against the org blocklist
(and domain threat-intel IOCs) using subdomain-aware suffix matching. It mines
indicators from telemetry fields (`domain`, `url`, `ip`) **and from command
lines** (e.g. `curl https://cdn.example.com/x`). Any request to a blocked domain
or a subdomain of one raises a `blocklist_domain` detection (high, T1071) — which
flows through alerting, integrations, AI explanation, and can trigger a response
action (kill process / isolate). This layer fully covers arbitrary subdomains.

*Verified live:* with `example.com` blocked, telemetry to
`tracker.ads.example.com` and a command line hitting `cdn.example.com` both
produced `blocklist_domain` detections, while `notexample.com` produced none.

### 2. Agent DNS sinkhole (egress prevention)

The agent pins blocked hosts to `0.0.0.0` in the OS hosts file, so the endpoint
cannot resolve or connect to them. Each entry is normalized to a bare host first
(a blocked URL becomes a hostname). 

When an **apex** domain is blocked (e.g. `youtube.com`), the sinkhole also writes
its most common subdomains — `www.`, `m.`, `mobile.` — because browsers usually
load `www.youtube.com` when you type `youtube.com`. This covers the everyday "I
blocked the site but it still opens" case.

**Limitation:** the OS hosts file is exact-hostname and cannot wildcard, so it
covers the apex + the common subdomains above, not *arbitrary* subdomains at the
resolver. Broader subdomain coverage at the endpoint is provided by layer 1
(detect the subdomain request and respond), and by adding specific subdomains to
the blocklist. True wildcard egress blocking would require a local DNS proxy.

### Requirements for hosts-file blocking to actually take effect

If a blocked site still opens, check these — in order:

1. **The agent must run elevated** (Administrator on Windows / root on Linux) to
   edit the hosts file. Unelevated, it logs "must run elevated…" and does nothing.
2. **The agent must not be in dry-run** (`SG_DRY_RUN=1` only logs "would
   sinkhole" and never writes).
3. **Browser Secure DNS / DNS-over-HTTPS (DoH) can bypass the hosts file.** In
   Chrome/Edge: Settings → Privacy & security → Security → turn **off** "Use
   secure DNS". Otherwise the browser resolves via a DoH server and ignores the
   hosts file entirely.
4. **Flush caches after a change:** `ipconfig /flushdns` (Windows) and restart
   the browser (browsers keep their own DNS cache and warm connections).

Layer 1 (server detection) still records the attempt regardless of these.

## Matching definition (both layers)

`host_matches_domain(host, blocked)` is true iff `host == blocked` or
`host` ends with `"." + blocked`. Implemented identically in
`server/app/core/netmatch.py` and `agent/silentguard_agent/net_match.py`.

## Testing

- Server: `server/tests/test_netmatch.py` — host extraction, subdomain matches,
  boundary safety (no `notexample.com` / `example.com.evil.com` false positives),
  URL-normalized blocklist entries, and end-to-end `blocklist_domain` /
  subdomain-IOC detections including a URL mined from a command line.
- Agent: `agent/tests/test_net_match.py` — matcher parity and sinkhole
  host-normalization of URL entries.
