"""Webhook response evaluator logic for conditional and static responses."""

from __future__ import annotations

import json
import re
from http import HTTPStatus

HTTP_STATUS_MIN = 100
HTTP_STATUS_MAX = 599


def parse_json_content(value: str, fallback_key: str) -> dict | list:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict | list):
            return parsed
    except json.JSONDecodeError:
        return {fallback_key: value}
    else:
        return {fallback_key: parsed}


def normalize_webhook_response_body(response_body: object | None, raw_body: bytes | str) -> dict | list:
    raw_value = raw_body.decode() if isinstance(raw_body, bytes) else str(raw_body)
    if response_body in (None, ""):
        return parse_json_content(raw_value, "payload")
    if isinstance(response_body, dict | list):
        return response_body
    if isinstance(response_body, str):
        return parse_json_content(response_body, "message")
    return {"message": str(response_body)}


def coerce_webhook_status_code(value: object | None) -> int:
    try:
        status_code = int(value) if value is not None else int(HTTPStatus.ACCEPTED)
    except (TypeError, ValueError):
        return int(HTTPStatus.ACCEPTED)

    if status_code < HTTP_STATUS_MIN or status_code > HTTP_STATUS_MAX:
        return int(HTTPStatus.ACCEPTED)
    return status_code


def get_by_dotted_path(payload: object, path: str) -> object | None:
    if not path:
        return None

    normalized_path = path.strip()
    normalized_path = normalized_path.removeprefix("$")
    normalized_path = normalized_path.removeprefix(".")

    if not normalized_path:
        return payload

    current: object = payload
    for segment in normalized_path.split("."):
        if not segment:
            return None
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return None

    return current


def match_rule_condition(condition: dict, payload: object) -> bool:
    path = condition.get("path")
    if not isinstance(path, str) or not path.strip():
        return False

    value = get_by_dotted_path(payload, path)

    def to_number(raw: object) -> float | None:
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    if "exists" in condition:
        expected_exists = bool(condition.get("exists"))
        if (value is not None) != expected_exists:
            return False

    if "equals" in condition and value != condition.get("equals"):
        return False

    if "not_equals" in condition and value == condition.get("not_equals"):
        return False

    if "in" in condition:
        haystack = condition.get("in")
        if not isinstance(haystack, list) or value not in haystack:
            return False

    if "contains" in condition:
        needle = condition.get("contains")
        if (isinstance(value, str) and isinstance(needle, str)) or isinstance(value, list):
            if needle not in value:
                return False
        else:
            return False

    if "regex" in condition:
        pattern = condition.get("regex")
        if not isinstance(value, str) or not isinstance(pattern, str):
            return False
        try:
            if re.search(pattern, value) is None:
                return False
        except re.error:
            return False

    for op, compare_fn in (
        ("greater_than", lambda lhs, rhs: lhs > rhs),
        ("greater_than_or_equal", lambda lhs, rhs: lhs >= rhs),
        ("less_than", lambda lhs, rhs: lhs < rhs),
        ("less_than_or_equal", lambda lhs, rhs: lhs <= rhs),
    ):
        if op in condition:
            lhs = to_number(value)
            rhs = to_number(condition.get(op))
            if lhs is None or rhs is None or not compare_fn(lhs, rhs):
                return False

    return True


def render_templates_in_string(text: str, payload: object) -> str:
    rendered = text
    if "{{" not in rendered:
        return rendered

    cursor = 0
    while True:
        start = rendered.find("{{", cursor)
        if start == -1:
            break
        end = rendered.find("}}", start + 2)
        if end == -1:
            break

        expression = rendered[start + 2 : end].strip()
        replacement = ""
        if expression.startswith("$"):
            resolved = get_by_dotted_path(payload, expression)
            replacement = "" if resolved is None else str(resolved)

        rendered = rendered[:start] + replacement + rendered[end + 2 :]
        cursor = start + len(replacement)

    return rendered


def render_templates(raw: object, payload: object) -> object:
    if isinstance(raw, str):
        return render_templates_in_string(raw, payload)
    if isinstance(raw, list):
        return [render_templates(item, payload) for item in raw]
    if isinstance(raw, dict):
        return {key: render_templates(value, payload) for key, value in raw.items()}
    return raw


def parse_json_maybe(raw: object) -> object:
    if raw is None:
        return None
    if isinstance(raw, dict | list):
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
    """Evaluate webhook response based on component configuration."""
    raw_text = raw_body.decode() if isinstance(raw_body, bytes) else str(raw_body)
    payload = parse_json_maybe(raw_text)
    match_payload: object = payload if isinstance(payload, dict | list) else {"payload": payload}

    rules = parse_json_maybe(response_config.get("response_rules"))
    default_response = parse_json_maybe(response_config.get("default_response"))

    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            condition = rule.get("when")
            response = rule.get("response")
            if not isinstance(condition, dict) or not isinstance(response, dict):
                continue
            if not match_rule_condition(condition, match_payload):
                continue

            status_code = coerce_webhook_status_code(response.get("status_code"))
            body = render_templates(parse_json_maybe(response.get("body")), match_payload)
            if isinstance(body, dict | list):
                return status_code, body
            return status_code, {"message": str(body)}

        if isinstance(default_response, dict):
            status_code = coerce_webhook_status_code(default_response.get("status_code"))
            body = render_templates(parse_json_maybe(default_response.get("body")), match_payload)
            if isinstance(body, dict | list):
                return status_code, body
            return status_code, {"message": str(body)}

    status_code = coerce_webhook_status_code(response_config.get("status_code"))
    body = normalize_webhook_response_body(response_config.get("response_body"), raw_body)
    return status_code, body
