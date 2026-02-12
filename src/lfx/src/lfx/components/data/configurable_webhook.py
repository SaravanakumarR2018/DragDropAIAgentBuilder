"""Configurable webhook component with conditional response support."""

import json

from lfx.custom.custom_component.component import Component
from lfx.io import BoolInput, IntInput, MultilineInput, Output
from lfx.schema.data import Data


def _get_default_rules() -> str:
    """Get default example rules."""
    return '''[
  {
    "when": { "path": "$.event", "equals": "order.created" },
    "response": {
      "status_code": 201,
      "body": { "status": "created", "order_id": "{{ $.id }}" }
    }
  },
  {
    "when": { "path": "$.customer_id", "exists": true },
    "response": {
      "status_code": 200,
      "body": { "status": "customer_present", "customer_id": "{{ $.customer_id }}" }
    }
  },
  {
    "when": { "path": "$.event", "in": ["order.updated", "order.cancelled"] },
    "response": {
      "status_code": 200,
      "body": { "status": "order_changed", "event": "{{ $.event }}" }
    }
  },
  {
    "when": { "path": "$.amount", "greater_than": 1000 },
    "response": {
      "status_code": 402,
      "body": { "status": "too_large", "amount": "{{ $.amount }}" }
    }
  }
]'''


def _get_rules_info() -> str:
    """Get info text for rules field."""
    return (
        "JSON array of conditional rules. First match wins.\n"
        'Condition supports: {"path":"$.a.b","equals":...,"not_equals":...,"exists":true,'
        '"in":[...],"contains":"...","regex":"...","greater_than":...,'
        '"greater_than_or_equal":...,"less_than":...,"less_than_or_equal":...}.\n'
        'Response: {"status_code": 200-599, "body": <json with {{ $.path }} templates>}.\n'
        "Leave empty to disable conditional mode."
    )


class ConfigurableWebhookComponent(Component):
    display_name = "Configurable Webhook"
    description = "Webhook input with configurable response options (including conditional responses)."
    documentation: str = "https://docs.langflow.org/components-data#webhook"
    name = "ConfigurableWebhook"
    icon = "webhook"

    inputs = [
        MultilineInput(
            name="data",
            display_name="Payload",
            info="Receives a payload from external systems via HTTP POST.",
            advanced=True,
        ),
        MultilineInput(
            name="curl",
            display_name="cURL",
            value="CURL_WEBHOOK",
            advanced=True,
            input_types=[],
        ),
        MultilineInput(
            name="endpoint",
            display_name="Endpoint",
            value="BACKEND_URL",
            advanced=False,
            copy_field=True,
            input_types=[],
        ),
        BoolInput(
            name="use_default_response",
            display_name="Use Default Response",
            value=True,
            info="Return the default 202 response when enabled.",
            advanced=True,
        ),
        # Conditional mode
        MultilineInput(
            name="response_rules",
            display_name="Response Rules (JSON)",
            value=_get_default_rules(),
            info=_get_rules_info(),
            advanced=True,
        ),
        MultilineInput(
            name="default_response",
            display_name="Default Response (JSON)",
            value='{\n  "status_code": 202,\n  "body": { "status": "accepted" }\n}',
            info="Fallback response when no rules match (conditional mode).",
            advanced=True,
        ),
        # Legacy static mode
        IntInput(
            name="response_status_code",
            display_name="Response Status Code (Legacy)",
            value=202,
            info="(Legacy) HTTP status code for static responses.",
            advanced=True,
        ),
        MultilineInput(
            name="response_body",
            display_name="Response Body (Legacy)",
            value='{"message": "Task started in the background", "status": "in progress"}',
            info="(Legacy) JSON or text to return. Leave blank to echo payload.",
            advanced=True,
        ),
        BoolInput(
            name="use_response_body_as_output",
            display_name="Use Response as Output",
            value=False,
            info="Use configured response body as component output instead of incoming payload.",
            advanced=True,
        ),
    ]

    outputs = [
        Output(display_name="Data", name="output_data", method="build_data"),
    ]

    def build_data(self) -> Data:
        """Build data output from webhook payload."""
        if not self.data:
            self.status = "No data provided."
            return Data(data={})

        # Parse payload
        payload_value = self.data.replace('"\n"', '"\\n"')
        try:
            payload_obj = json.loads(payload_value or "{}")
        except json.JSONDecodeError:
            payload_obj = {"payload": payload_value}

        # Import evaluation logic
        from langflow.services.webhook.response_evaluator import (
            evaluate_configurable_webhook_response,
        )

        # Get response configuration
        response_config = {
            "response_rules": self.response_rules,
            "default_response": self.default_response,
            "status_code": self.response_status_code,
            "response_body": self.response_body,
        }

        # Evaluate response
        try:
            status_code, selected_body = evaluate_configurable_webhook_response(
                response_config,
                json.dumps(payload_obj) if isinstance(payload_obj, (dict, list)) else str(payload_obj),
            )
        except Exception as exc:
            self.status = f"Error evaluating response: {exc}"
            return Data(data=payload_obj if isinstance(payload_obj, dict) else {"payload": payload_obj})

        # Return selected response or payload
        if self.use_response_body_as_output:
            if isinstance(selected_body, dict):
                out_data = selected_body
            elif isinstance(selected_body, list):
                out_data = {"payload": selected_body}
            else:
                out_data = {"message": str(selected_body)}
            self.status = f"Selected response as output.\nStatus Code: {status_code}"
            return Data(data=out_data)

        # Default: return payload
        if isinstance(payload_obj, dict):
            self.status = "Parsed payload."
            return Data(data=payload_obj)

        self.status = "Parsed payload."
        return Data(data={"payload": payload_obj})