"""Webhook response evaluation logic for conditional and static responses."""

from __future__ import annotations

import json
import re
from http import HTTPStatus

def parse_json_content(value: str, fallback_key: str) -> dict | list:
    """Parse JSON string, falling back to wrapping primitives."""
    try:
        parsed = json.loads(value)
        if isinstance(parsed, (dict, list)):
            return parsed
        return {fallback_key: parsed}
    except json.JSONDecodeError:
        return {fallback_key: value}


def normalize_webhook_response_body(response_body: object | None, raw_body: bytes | str) -> dict | list:
    """Normalize response body to dict/list format."""
    raw_value = raw_body.decode() if isinstance(raw_body, bytes) else str(raw_body)
    if response_body in (None, ""):
        return parse_json_content(raw_value, "payload")
    if isinstance(response_body, (dict, list)):
        return response_body
    if isinstance(response_body, str):
        return parse_json_content(response_body, "message")
    return {"message": str(response_body)}


def coerce_webhook_status_code(value: object | None) -> int:
    """Coerce value to valid HTTP status code."""
    try:
        status_code = int(value) if value is not None else int(HTTPStatus.ACCEPTED)
    except (TypeError, ValueError):
        return int(HTTPStatus.ACCEPTED)
    if status_code < 100 or status_code > 599:
        return int(HTTPStatus.ACCEPTED)
    return status_code


def get_by_dotted_path(payload: object, path: str) -> object | None:
    """Resolve JSONPath-like dot notation: $.a.b.c

    - Only supports objects/dicts and dot-separated keys.
    - Returns None if any segment is missing.
    """
    if not path:
        return None
    p = path.strip()
    if p.startswith("$"):
        p = p[1:]
    if p.startswith("."):
        p = p[1:]
    if not p:
        return payload
    current: object = payload
    for seg in p.split("."):
        if not seg:
            return None
        if isinstance(current, dict) and seg in current:
            current = current[seg]
        else:
            return None
    return current


def match_rule_condition(cond: dict, payload: object) -> bool:
    """Check if condition matches payload.

    Supported condition keys (one rule may include multiple, all must match):
      - path (required)
      - equals
      - not_equals
      - exists (bool)
      - in (list)
      - contains (string or list element)
      - regex
      - greater_than
      - greater_than_or_equal
      - less_than
      - less_than_or_equal
    """
    path = cond.get("path")
    if not isinstance(path, str) or not path.strip():
        return False

    value = get_by_dotted_path(payload, path)

    def to_number(v: object) -> float | None:
        try:
            return float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    # exists check
    if "exists" in cond:
        exists_expected = bool(cond.get("exists"))
        exists_actual = value is not None
        if exists_expected != exists_actual:
            return False

    # equals check
    if "equals" in cond:
        if value != cond.get("equals"):
            return False

    # not_equals check
    if "not_equals" in cond:
        if value == cond.get("not_equals"):
            return False

    # in check
    if "in" in cond:
        haystack = cond.get("in")
        if not isinstance(haystack, list):
            return False
        if value not in haystack:
            return False

    # contains check
    if "contains" in cond:
        needle = cond.get("contains")
        if isinstance(value, str) and isinstance(needle, str):
            if needle not in value:
                return False
        elif isinstance(value, list):
            if needle not in value:
                return False
        else:
            return False

    # regex check
    if "regex" in cond:
        pattern = cond.get("regex")
        if not isinstance(value, str) or not isinstance(pattern, str):
            return False
        try:
            if re.search(pattern, value) is None:
                return False
        except re.error:
            return False

    # numeric comparisons
    for op, cmp_fn in (
        ("greater_than", lambda a, b: a > b),
        ("greater_than_or_equal", lambda a, b: a >= b),
        ("less_than", lambda a, b: a < b),
        ("less_than_or_equal", lambda a, b: a <= b),
    ):
        if op in cond:
            a = to_number(value)
            b = to_number(cond.get(op))
            if a is None or b is None:
                return False
            if not cmp_fn(a, b):
                return False

    return True


def render_templates_in_string(s: str, payload: object) -> str:
    """Replace {{ $.path }} templates with resolved values.

    Minimal templating: replace occurrences of "{{ $.path }}" with resolved value.
    No loops/conditionals/functions; safe deterministic substitution.
    """
    out = s
    if "{{" not in out:
        return out

    i = 0
    while True:
        start = out.find("{{", i)
        if start == -1:
            break
        end = out.find("}}", start + 2)
        if end == -1:
            break
        expr = out[start + 2 : end].strip()
        replacement: str = ""
        if expr.startswith("$"):
            resolved = get_by_dotted_path(payload, expr)
            replacement = "" if resolved is None else str(resolved)
        out = out[:start] + replacement + out[end + 2 :]
        i = start + len(replacement)
    return out


def render_templates(obj: object, payload: object) -> object:
    """Recursively render templates in objects."""
    if isinstance(obj, str):
        return render_templates_in_string(obj, payload)
    if isinstance(obj, list):
        return [render_templates(item, payload) for item in obj]
    if isinstance(obj, dict):
        return {k: render_templates(v, payload) for k, v in obj.items()}
    return obj


def parse_json_maybe(raw: object) -> object:
    """Parse JSON if string, otherwise return as-is."""
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def evaluate_configurable_webhook_response(
    response_config: dict,
    raw_body: bytes | str,
) -> tuple[int, dict | list]:
    """Evaluate webhook response based on configuration.

    Priority:
      1) response_rules + default_response (conditional mode)
      2) legacy response_status_code/response_body (static mode)
      3) echo payload / accepted

    Args:
        response_config: Configuration dict with response_rules, default_response,
                        status_code, and response_body keys
        raw_body: Raw request body as bytes or string

    Returns:
        Tuple of (status_code, response_body)
    """
    raw_text = raw_body.decode() if isinstance(raw_body, bytes) else str(raw_body)
    payload_obj = parse_json_maybe(raw_text)

    # Prepare payload for matching
    match_payload: object
    if isinstance(payload_obj, (dict, list)):
        match_payload = payload_obj
    else:
        match_payload = {"payload": payload_obj}

    # Try conditional mode first
    rules_raw = parse_json_maybe(response_config.get("response_rules"))
    default_raw = parse_json_maybe(response_config.get("default_response"))

    if isinstance(rules_raw, list):
        # Evaluate rules
        for rule in rules_raw:
            if not isinstance(rule, dict):
                continue
            cond = rule.get("when")
            resp = rule.get("response")
            if not isinstance(cond, dict) or not isinstance(resp, dict):
                continue
            if match_rule_condition(cond, match_payload):
                status_code = coerce_webhook_status_code(resp.get("status_code"))
                body = resp.get("body")
                body_obj = parse_json_maybe(body)
                rendered = render_templates(body_obj, match_payload)
                if isinstance(rendered, (dict, list)):
                    return status_code, rendered
                return status_code, {"message": str(rendered)}

        # No rule matched, use default_response
        if isinstance(default_raw, dict):
            status_code = coerce_webhook_status_code(default_raw.get("status_code"))
            body_obj = parse_json_maybe(default_raw.get("body"))
            rendered = render_templates(body_obj, match_payload)
            if isinstance(rendered, (dict, list)):
                return status_code, rendered
            return status_code, {"message": str(rendered)}

    # Legacy static mode
    status_code = coerce_webhook_status_code(response_config.get("status_code"))
    body = normalize_webhook_response_body(response_config.get("response_body"), raw_body)
    return status_code, body
