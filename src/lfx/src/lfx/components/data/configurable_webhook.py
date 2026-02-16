"""Configurable webhook component with conditional response support."""

import json

from lfx.custom.custom_component.component import Component
from lfx.io import BoolInput, MultilineInput, Output
from lfx.schema.data import Data


def _get_default_rules() -> str:
    """Get default example rules."""
    return '''#Examples of default Conditional Configuration 
[
  {
    "when": { "path": "$.event", "equals": "order.created"},
    "response": {
      "status_code": 201,
      "body": { "condition": "equals", "status": "created", "order_id": "{{ $.id }}" }
    }
  },
  {
    "when": { "path": "$.event", "in": ["order.updated", "order.cancelled"]},
    "response": {
      "status_code": 200,
      "body": { "condition": "in", "event": "{{ $.event }}" }
    }
  },
  {
    "when": { "path": "$.amount", "greater_than": 1000 },
    "response": {
      "status_code": 402,
      "body": { "condition": "greater_than", "error": "Amount too large", "amount": "{{ $.amount }}"
      }
    }
  },
  {
    "when": { "path": "$.amount", "greater_than_or_equal": 500 },
    "response": {
      "status_code": 200,
      "body": { "condition": "greater_than_or_equal", "tier": "medium", "amount": "{{ $.amount }}"
      }
    }
  },
  {
    "when": { "path": "$.amount", "less_than_or_equal": 10 },
    "response": {
      "status_code": 200,
      "body": { "condition": "less_than_or_equal", "tier": "tiny", "amount": "{{ $.amount }}" }
    }
  },
  {
    "when": { "path": "$.amount", "less_than": 100 },
    "response": {
      "status_code": 200,
      "body": { "condition": "less_than", "tier": "low", "amount": "{{ $.amount }}" }
    }
  },
  {
    "when": { "path": "$.message", "contains": "error" },
    "response": {
      "status_code": 400,
      "body": { "condition": "contains", "message": "{{ $.message }}" }
    }
  },
  {
    "when": { "path": "$.email", "regex": ".*@example.com$" },
    "response": {
      "status_code": 200,
      "body": { "condition": "regex", "email": "{{ $.email }}" }
    }
  },
  {
    "when": { "path": "$.user_id", "exists": true },
    "response": {
      "status_code": 200,
      "body": { "condition": "exists", "user_id": "{{ $.user_id }}" }
    }
  },
  {
    "when": { "path": "$.event", "exists": true, "not_equals": "order.created" },
    "response": {
      "status_code": 200,
      "body": { "condition": "not_equals", "event": "{{ $.event }}" }
    }
  }
]'''

class ConfigurableWebhookComponent(Component):
    display_name = "Webhook Configurable"
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
            info="Returns the default 202 response without applying any configured response rules.",
            advanced=True,
        ),
        # Conditional mode
        MultilineInput(
            name="response_rules",
            display_name="Configured Response Rules (JSON)",
            value=_get_default_rules(),
            info=(
                "Define response rules in JSON format. Refer to the value field for "
                "example configurations on how to set up response rules."
            ),
            advanced=True,
        ),
        MultilineInput(
            name="default_response",
            display_name="Configured Default Response (JSON)",
            value='{\n  "status_code": 202,\n  "body": { "status": "accepted" }\n}',
            info=(
                "Specifies the fallback response in JSON format when none of the "
                "configured response rules match. Refer to the value field for "
                "example configurations."
            ),
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

        # Default: return payload
        if isinstance(payload_obj, dict):
            self.status = "Parsed payload."
            return Data(data=payload_obj)

        self.status = "Parsed payload."
        return Data(data={"payload": payload_obj})