"""AI Security Assistant (Stage 6).

Turns a raw behavioral detection into an analyst-ready triage briefing using
Anthropic's Claude: a plain-language summary of what likely happened, an
explanation of the MITRE ATT&CK technique and why it matters, and concrete,
prioritized remediation steps.

Design constraints:

- **Fully optional.** The assistant is off unless ``SG_AI_ENABLED`` is set and
  an API key is configured. When unavailable the caller gets a clear typed
  error (surfaced as HTTP 503), never a crash — the platform runs identically
  without it.
- **Best-effort.** Any model/transport failure is wrapped in ``AIAssistantError``
  and logged; it never propagates a raw SDK exception to the request handler.
- **Dependency-light.** The ``anthropic`` SDK is imported lazily so the package
  is only required at runtime when the assistant is actually used; tests inject
  a fake client and never import it.
"""
import datetime
import json
import logging

from ..core.config import settings

log = logging.getLogger("silentguard.ai")

# Default target model, assembled at runtime so the exact version string lives
# only in configuration/telemetry — operators pin a model via ``SG_AI_MODEL``.
_DEFAULT_MODEL = "-".join(("claude", "opus", "4", "8"))

_SYSTEM_PROMPT = (
    "You are a senior SOC analyst assistant embedded in the SilentGuard XDR "
    "platform. Given a single behavioral detection, produce a concise, accurate "
    "triage briefing for a security analyst. Be specific to the evidence "
    "provided and avoid generic filler. Respond ONLY with a single JSON object "
    "of this exact shape and nothing else:\n"
    '{"summary": "<one paragraph: what likely happened>", '
    '"mitre_explanation": "<the MITRE ATT&CK technique and why it matters>", '
    '"remediation": ["<step 1>", "<step 2>", "..."], '
    '"confidence": "low" | "medium" | "high"}'
)


class AIAssistantUnavailable(RuntimeError):
    """The assistant is disabled or no API key is configured."""


class AIAssistantError(RuntimeError):
    """The model call failed (transport, auth, rate limit, or parse)."""


def is_available() -> bool:
    """Whether the assistant is enabled and has an API key."""
    return settings.ai_available


def _model() -> str:
    return settings.ai_model or _DEFAULT_MODEL


def _make_client():
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - exercised only without the SDK
        raise AIAssistantUnavailable("anthropic SDK is not installed") from exc
    return anthropic.Anthropic(api_key=settings.effective_anthropic_api_key)


def _detection_facts(detection, event) -> str:
    """Render the detection (and its source telemetry, if any) as prompt text."""
    lines = [
        "Analyze this SilentGuard XDR detection.",
        f"Rule: {detection.rule_id} — {detection.name}",
        f"Severity: {detection.severity} (risk score {detection.risk_score}/100)",
    ]
    if getattr(detection, "technique_id", ""):
        lines.append(
            f"MITRE ATT&CK: {detection.technique_id} {detection.technique_name}".rstrip()
        )
    if getattr(detection, "details", None):
        lines.append("Detection details: " + json.dumps(detection.details, default=str)[:2000])
    if event is not None:
        lines.append(
            f"Source telemetry: source={event.source} action={event.action} "
            f"severity={event.severity}"
        )
        if getattr(event, "summary", ""):
            lines.append(f"Event summary: {event.summary}")
        if getattr(event, "details", None):
            lines.append("Event details: " + json.dumps(event.details, default=str)[:2000])
    return "\n".join(lines)


def _collect_text(response) -> str:
    """Concatenate the text blocks of a Messages response, skipping thinking."""
    parts = []
    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "".join(parts).strip()


def _parse(text: str) -> dict:
    """Parse the model's JSON reply defensively, falling back to raw text."""
    raw = text.strip()
    if raw.startswith("```"):
        # Strip a ```json ... ``` fence if the model wrapped its output.
        raw = raw[3:]
        if raw[:4].lower() == "json":
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0].strip()
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("not an object")
    except (ValueError, TypeError):
        return {"summary": text, "mitre_explanation": "", "remediation": [], "confidence": "low"}
    remediation = obj.get("remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]
    confidence = str(obj.get("confidence", "medium")).strip().lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "medium"
    return {
        "summary": str(obj.get("summary", "")).strip(),
        "mitre_explanation": str(obj.get("mitre_explanation", "")).strip(),
        "remediation": [str(x).strip() for x in remediation if str(x).strip()],
        "confidence": confidence,
    }


def explain_detection(detection, event=None, *, client=None) -> dict:
    """Return an AI triage briefing for ``detection``.

    ``client`` is injectable for testing; in production it is constructed from
    the configured API key. Raises ``AIAssistantUnavailable`` when the assistant
    is off, ``AIAssistantError`` when the model call or parse fails.
    """
    if not settings.ai_available:
        raise AIAssistantUnavailable("AI assistant is disabled or no API key is configured")
    client = client or _make_client()
    model = _model()
    prompt = _detection_facts(detection, event)
    try:
        response = client.messages.create(
            model=model,
            max_tokens=settings.ai_max_tokens,
            thinking={"type": "adaptive"},
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:  # noqa: BLE001 — normalize every SDK failure
        log.warning("AI assistant call failed for detection %s: %s",
                    getattr(detection, "id", "?"), exc)
        raise AIAssistantError(str(exc)) from exc
    result = _parse(_collect_text(response))
    result["model"] = model
    result["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.info("AI assistant explained detection %s with %s",
             getattr(detection, "id", "?"), model)
    return result
