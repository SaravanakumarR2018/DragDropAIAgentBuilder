#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${1:-}"
ENV_FILE="${2:-}"
ENVIRONMENT="${3:-}"

if [[ -z "$CONFIG_FILE" || -z "$ENV_FILE" || -z "$ENVIRONMENT" ]]; then
  echo "Usage: $0 <config_file> <env_file> <environment>" >&2
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Stripe config not found: $CONFIG_FILE" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

stripe_key_template=$(awk -v env="$ENVIRONMENT" '
  $1 ~ env ":" { in_env=1; next }
  /^[a-zA-Z0-9_-]+:/ && $1 !~ env ":" { in_env=0 }
  in_env && $1 == "STRIPE_SECRET_KEY:" { print $2; exit }
' "$CONFIG_FILE")

if [[ -z "$stripe_key_template" ]]; then
  echo "No STRIPE_SECRET_KEY configured for environment: $ENVIRONMENT" >&2
  exit 1
fi

stripe_key=$(eval "echo \"$stripe_key_template\"")

if [[ -z "$stripe_key" ]]; then
  echo "Stripe token environment variable not set for $ENVIRONMENT" >&2
  exit 1
fi

if grep -q '^STRIPE_SECRET_KEY=' "$ENV_FILE"; then
  sed -i "s|^STRIPE_SECRET_KEY=.*|STRIPE_SECRET_KEY=${stripe_key}|" "$ENV_FILE"
else
  echo "STRIPE_SECRET_KEY=${stripe_key}" >> "$ENV_FILE"
fi

if grep -q '^LANGFLOW_ENVIRONMENT=' "$ENV_FILE"; then
  sed -i "s|^LANGFLOW_ENVIRONMENT=.*|LANGFLOW_ENVIRONMENT=${ENVIRONMENT}|" "$ENV_FILE"
else
  echo "LANGFLOW_ENVIRONMENT=${ENVIRONMENT}" >> "$ENV_FILE"
fi
