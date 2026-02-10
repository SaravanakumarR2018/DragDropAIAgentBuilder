"""Configurable webhook component with conditional response support."""

from __future__ import annotations

import json

from lfx.custom.custom_component.component import Component
from lfx.io import BoolInput, IntInput, MultilineInput, Output
from lfx.schema.data import Data


def _get_default_rules() -> str:
    """Get default example rules."""
    return """[
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
  }
]"""


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
            value='{"status_code": 202, "body": {"status": "accepted"}}',
            info="Fallback response when no rules match (conditional mode).",
            advanced=True,
        ),
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

    outputs = [Output(display_name="Data", name="output_data", method="build_data")]

    def build_data(self) -> Data:
        """Build data output from webhook payload."""
        message: str | Data = ""
        if not self.data:
            self.status = "No data provided."
            return Data(data={})

        try:
            payload_value = self.data.replace('"\n"', '"\\n"')
            body = json.loads(payload_value or "{}")
        except json.JSONDecodeError:
            body = {"payload": self.data}
            message = f"Invalid JSON payload. Please check the format.\n\n{self.data}"

        data = Data(data=body)
        if not message:
            message = data
        self.status = message
        return data
