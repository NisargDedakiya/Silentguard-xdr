"""Sigma rule support for the detection engine (v1.3).

Sigma is the open, vendor-neutral signature format SOC teams use to share
detections. `IntelRule` rows of ``kind="sigma"`` were previously stored and
distributed but never evaluated; this module compiles them into predicates over
an :class:`~app.detection.rules.EventContext` so an operator's own Sigma rules
actually fire detections against live telemetry.

A pragmatic, well-tested subset of the spec is supported — the part that maps
cleanly onto endpoint telemetry:

- ``detection`` blocks with named **selections**. A selection may be a mapping
  of ``Field|modifier: value(s)`` (AND across fields) or a bare list of
  **keywords** (OR against the whole event).
- Field modifiers: ``contains``, ``startswith``, ``endswith``, ``re`` (regex),
  ``all`` (require every listed value), and plain equality (the default).
  String matching is case-insensitive, per Sigma.
- ``condition`` expressions: ``and`` / ``or`` / ``not``, parentheses, and the
  ``N of them`` / ``all of them`` / ``1 of prefix*`` aggregate forms.
- ``level`` → severity, ``tags`` → the first ``attack.tXXXX`` ATT&CK technique.

Anything referencing fields the agent does not report simply never matches (it
cannot raise a false positive). Compilation is cached by content hash so YAML is
parsed once, not per event.
"""
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Callable

import yaml

from .rules import EventContext

log = logging.getLogger("silentguard.sigma")

_LEVEL_SEVERITY = {
    "informational": "low", "info": "low", "low": "low",
    "medium": "medium", "high": "high", "critical": "critical",
}

# Sigma field name (lower-cased) → how to read it from our telemetry. Fields not
# listed fall back to a case-insensitive lookup in event.details.
_COMMAND_FIELDS = {"commandline", "cmdline", "image", "process", "processpath",
                   "originalfilename", "targetobject", "targetfilename"}
_NAME_FIELDS = {"processname", "name", "imagename"}


class SigmaError(ValueError):
    """A Sigma document could not be parsed/compiled."""


@dataclass(frozen=True)
class CompiledSigma:
    rule_id: str          # the Sigma ``id`` if present, else the title
    name: str
    severity: str         # low|medium|high|critical
    technique_id: str
    technique_name: str
    matches: Callable[[EventContext], bool]


# -- field / value matching ----------------------------------------------
def _field_value(ctx: EventContext, field: str) -> str:
    key = field.lower()
    lowered = {str(k).lower(): v for k, v in ctx.details.items()}
    if key in lowered and lowered[key] is not None:
        return str(lowered[key])
    if key in _COMMAND_FIELDS:
        return ctx.command_line
    if key in _NAME_FIELDS:
        return str(lowered.get("name", ""))
    return ""


def _match_value(modifiers: list[str], field: str, value, ctx: EventContext) -> bool:
    raw = _field_value(ctx, field)
    if "re" in modifiers:
        try:
            return re.search(str(value), raw, re.IGNORECASE) is not None
        except re.error:
            return False
    fv = raw.lower()
    v = str(value).lower()
    if "contains" in modifiers:
        return v in fv
    if "startswith" in modifiers:
        return fv.startswith(v)
    if "endswith" in modifiers:
        return fv.endswith(v)
    return fv == v


def _compile_selection(spec) -> Callable[[EventContext], bool]:
    if isinstance(spec, dict):
        preds = []
        for key, values in spec.items():
            parts = str(key).split("|")
            field, modifiers = parts[0], parts[1:]
            vals = values if isinstance(values, list) else [values]
            combine = all if "all" in modifiers else any

            def make(field=field, modifiers=modifiers, vals=vals, combine=combine):
                return lambda ctx: combine(_match_value(modifiers, field, v, ctx) for v in vals)

            preds.append(make())
        return lambda ctx: all(p(ctx) for p in preds)
    if isinstance(spec, list):
        keywords = [str(x).lower() for x in spec]
        return lambda ctx: any(k in ctx.haystack for k in keywords)
    keyword = str(spec).lower()
    return lambda ctx: keyword in ctx.haystack


# -- condition expression -------------------------------------------------
def _tokenize(condition: str) -> list[str]:
    return condition.replace("(", " ( ").replace(")", " ) ").split()


def _compile_condition(condition, names: list[str]) -> Callable[[dict], bool]:
    if isinstance(condition, list):  # a list of conditions is an OR
        condition = " or ".join(f"( {c} )" for c in condition)
    tokens = _tokenize(str(condition or " and ".join(names)))
    pos = 0

    def peek(offset=0):
        idx = pos + offset
        return tokens[idx] if idx < len(tokens) else None

    def advance():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_expr():
        node = parse_term()
        while (peek() or "").lower() == "or":
            advance()
            rhs = parse_term()
            node = (lambda a, b: lambda r: a(r) or b(r))(node, rhs)
        return node

    def parse_term():
        node = parse_factor()
        while (peek() or "").lower() == "and":
            advance()
            rhs = parse_factor()
            node = (lambda a, b: lambda r: a(r) and b(r))(node, rhs)
        return node

    def parse_factor():
        tok = peek()
        if tok is None:
            return lambda r: False
        low = tok.lower()
        if low == "not":
            advance()
            operand = parse_factor()
            return lambda r: not operand(r)
        if tok == "(":
            advance()
            node = parse_expr()
            if peek() == ")":
                advance()
            return node
        if (low in ("all", "any", "1") or low.isdigit()) and (peek(1) or "").lower() == "of":
            count = advance()
            advance()  # 'of'
            group = advance()
            return _compile_of(count, group, names)
        name = advance()
        return lambda r, n=name: bool(r.get(n))

    return parse_expr()


def _compile_of(count: str, group: str, names: list[str]) -> Callable[[dict], bool]:
    g = group.lower()
    if g == "them":
        targets = list(names)
    elif g.endswith("*"):
        targets = [n for n in names if n.lower().startswith(g[:-1])]
    else:
        targets = [n for n in names if n.lower() == g]

    def fn(results):
        hits = sum(1 for n in targets if results.get(n))
        if count.lower() == "all":
            return bool(targets) and hits == len(targets)
        if count.lower() in ("any", "1"):
            return hits >= 1
        try:
            return hits >= int(count)
        except ValueError:
            return hits >= 1

    return fn


# -- top-level compile ----------------------------------------------------
def _technique_from_tags(tags) -> str:
    for tag in tags or []:
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            return tag.split(".", 1)[1].upper()
    return ""


def compile_sigma(text: str) -> CompiledSigma:
    """Compile a Sigma YAML document. Raises :class:`SigmaError` if invalid."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaError(f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise SigmaError("Sigma rule must be a mapping")
    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise SigmaError("Sigma rule needs a non-empty 'detection' block")
    condition = detection.get("condition")
    selections = {
        name: _compile_selection(spec)
        for name, spec in detection.items()
        if name != "condition"
    }
    if not selections:
        raise SigmaError("Sigma 'detection' block has no selections")
    cond_fn = _compile_condition(condition, list(selections.keys()))

    def matches(ctx: EventContext) -> bool:
        results = {name: sel(ctx) for name, sel in selections.items()}
        return cond_fn(results)

    title = str(doc.get("title") or "Sigma rule")
    return CompiledSigma(
        rule_id=str(doc.get("id") or title),
        name=title,
        severity=_LEVEL_SEVERITY.get(str(doc.get("level", "")).lower(), "medium"),
        technique_id=_technique_from_tags(doc.get("tags")),
        technique_name="",
        matches=matches,
    )


def validate_sigma(text: str) -> None:
    """Raise :class:`SigmaError` if ``text`` is not a compilable Sigma rule."""
    compile_sigma(text)


# -- compile cache --------------------------------------------------------
_CACHE: dict[str, CompiledSigma] = {}


def compile_cached(text: str) -> CompiledSigma:
    """Compile with a content-hash cache so YAML is parsed once per rule body."""
    digest = hashlib.sha256(text.encode()).hexdigest()
    compiled = _CACHE.get(digest)
    if compiled is None:
        compiled = compile_sigma(text)
        _CACHE[digest] = compiled
    return compiled
