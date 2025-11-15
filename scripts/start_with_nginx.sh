#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
PUBLIC_PORT="${LANGFLOW_PORT:-7860}"
BACKEND_PORT="${LANGFLOW_BACKEND_PORT:-7861}"

export LANGFLOW_HOST="$BACKEND_HOST"
export LANGFLOW_BACKEND_PORT="$BACKEND_PORT"
export LANGFLOW_PUBLIC_PORT="$PUBLIC_PORT"
export LANGFLOW_PORT="$BACKEND_PORT"

CONFIG_TEMPLATE="/etc/nginx/conf.d/frontend2.conf.template"
CONFIG_PATH="/etc/nginx/conf.d/frontend2.conf"

if [ -f "$CONFIG_TEMPLATE" ]; then
  sed \
    -e "s/{{NGINX_PORT}}/${PUBLIC_PORT}/g" \
    -e "s/{{BACKEND_PORT}}/${BACKEND_PORT}/g" \
    "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
fi

SUPERVISORD_CONF="${SCRIPT_DIR}/langflow_supervisord.conf"

if [ ! -f "$SUPERVISORD_CONF" ]; then
  echo "Supervisor configuration not found at $SUPERVISORD_CONF" >&2
  exit 1
fi

if ! command -v supervisord >/dev/null 2>&1; then
  echo "supervisord is not installed or not available in PATH" >&2
  exit 1
fi

exec supervisord -c "$SUPERVISORD_CONF"
