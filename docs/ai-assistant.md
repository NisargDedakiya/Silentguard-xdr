# AI Security Assistant (Stage 6)

A Claude-powered triage assistant that turns a raw behavioral detection into an
analyst-ready briefing: a plain-language **summary** of what likely happened, a
**MITRE ATT&CK explanation** of the technique and why it matters, and concrete,
prioritized **remediation** steps.

It is **fully optional and off by default** — the platform runs identically
without it. Nothing about detection, triage, response, or reporting depends on
it; it is a value-add on top of an existing detection.

## Enabling it

Set two environment variables on the server:

| Variable | Purpose | Default |
|---|---|---|
| `SG_AI_ENABLED` | Master switch for the assistant | `false` |
| `SG_ANTHROPIC_API_KEY` | Anthropic API key (falls back to the standard `ANTHROPIC_API_KEY`) | *(empty)* |
| `SG_AI_MODEL` | Pin a specific model; empty uses the built-in default | *(empty)* |
| `SG_AI_MAX_TOKENS` | Response token budget | `2048` |

The assistant is considered available only when `SG_AI_ENABLED` is set **and** a
key is present (`settings.ai_available`). Otherwise the endpoint returns
`503 Service Unavailable` with a clear message.

## Endpoint

```
POST /api/admin/detections/{id}/explain
```

- **Permission:** `READ_FLEET` — explaining a detection is read-only, so any
  analyst who can view detections can request a briefing. No state is changed
  on the detection itself.
- **Scoping:** org-scoped like every other detection route; a principal cannot
  explain a detection outside its tenant (404).
- **Audit:** each call writes a `detection_explain` audit entry recording the
  rule id and the model used.

### Response

```json
{
  "detection_id": 42,
  "summary": "A reverse-shell listener on port 4444 was opened and killed ...",
  "mitre_explanation": "T1059 (Command and Scripting Interpreter) covers ...",
  "remediation": ["Isolate the affected host", "Rotate exposed credentials", "..."],
  "confidence": "high",
  "model": "<model id>",
  "generated_at": "2026-07-12T10:00:00+00:00"
}
```

### Status codes

| Code | Meaning |
|---|---|
| `200` | Briefing generated |
| `404` | Detection not found (or outside the caller's tenant) |
| `502` | The model call failed (transport/auth/rate-limit) |
| `503` | Assistant not configured |

## How it works

`app/services/ai_assistant.py` builds a prompt from the detection facts (rule,
severity, risk score, ATT&CK technique, details) plus the originating telemetry
event when available, sends it to Claude with a system prompt that pins the
output to a strict JSON shape, and parses the reply defensively — a non-JSON
reply degrades gracefully into the `summary` field rather than failing.

- **Best-effort:** every SDK failure is caught, logged, and re-raised as a
  typed `AIAssistantError` (never a raw stack trace to the client).
- **Adaptive thinking** is enabled so the model can reason about multi-signal
  detections; thinking blocks are stripped before parsing.
- **Dependency-light:** the `anthropic` SDK is imported lazily, so it is only
  required at runtime when the assistant is actually enabled.

## Testing

`server/tests/test_ai_assistant.py` injects a fake client (no network) to cover
prompt construction, JSON and code-fence parsing, plain-text fallback,
thinking-block stripping, availability gating, and error normalization, plus
endpoint tests for the 200 / 404 / 502 / 503 paths and audit logging.
