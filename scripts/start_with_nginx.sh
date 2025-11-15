#!/bin/sh
set -e

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
PUBLIC_PORT="${LANGFLOW_PORT:-7860}"
BACKEND_PORT="${LANGFLOW_BACKEND_PORT:-7861}"

CONFIG_TEMPLATE="/etc/nginx/conf.d/frontend2.conf.template"
CONFIG_PATH="/etc/nginx/conf.d/frontend2.conf"

if [ -f "$CONFIG_TEMPLATE" ]; then
  sed \
    -e "s/{{NGINX_PORT}}/${PUBLIC_PORT}/g" \
    -e "s/{{BACKEND_PORT}}/${BACKEND_PORT}/g" \
    "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
fi

LANGFLOW_PORT="$BACKEND_PORT" runuser -u user -- langflow run --host "$BACKEND_HOST" --port "$BACKEND_PORT" &
BACKEND_PID=$!

graceful_shutdown() {
  kill -TERM "$BACKEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
}

trap graceful_shutdown INT TERM EXIT

nginx -g 'daemon off;'
