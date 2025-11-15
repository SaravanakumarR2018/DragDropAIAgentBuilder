#!/bin/sh
set -e

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
PUBLIC_PORT="${LANGFLOW_PORT:-7860}"
BACKEND_PORT="${LANGFLOW_BACKEND_PORT:-7861}"

export LANGFLOW_HOST="$BACKEND_HOST"
export LANGFLOW_PORT="$PUBLIC_PORT"
export LANGFLOW_BACKEND_PORT="$BACKEND_PORT"

CONFIG_TEMPLATE="/etc/nginx/conf.d/frontend2.conf.template"
CONFIG_PATH="/etc/nginx/conf.d/frontend2.conf"

if [ -f "$CONFIG_TEMPLATE" ]; then
  sed \
    -e "s/{{NGINX_PORT}}/${PUBLIC_PORT}/g" \
    -e "s/{{BACKEND_PORT}}/${BACKEND_PORT}/g" \
    "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
fi

exec supervisord -c /etc/supervisor/conf.d/langflow.conf
